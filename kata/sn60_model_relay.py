"""SN60 model-pinning inference relay.

Untrusted miner agents run inside an internet-blocked Docker network, so the only
way they can reach an LLM is through the inference endpoint Kata hands them via
``KATA_SN60_INFERENCE_API``. Point that variable at this relay and it forces every
inference request onto a single pinned model before forwarding to the real Bitsec
proxy. That protects the validator two ways at once:

* **Cost** — a miner cannot spend the validator's inference budget on a costlier
  model; the model is overwritten no matter what the agent's code asked for.
* **Fairness** — king and candidate are guaranteed to duel on the same model
  and cannot override sampling parameters through runtime request bodies.

Enforcement happens on the actual API call, not by scanning source, so runtime or
obfuscated model strings cannot bypass it: the internal network gives the agent no
other route to a provider. Only ``POST /inference`` is forwarded upstream; relay
health/cost endpoints are answered locally.

The module has no third-party dependencies (kata ships none) and is meant to run as
a small sidecar container on the agent network:

    docker run --rm --name kata_model_relay --network bitsec-net \\
        -e KATA_RELAY_UPSTREAM=http://bitsec_proxy:8000 \\
        -e KATA_RELAY_PINNED_MODEL=qwen/qwen3.6-35b-a3b \\
        kata-sn60-model-relay

Then start the validator with ``KATA_SN60_INFERENCE_API=http://kata_model_relay:8000``.
"""

from __future__ import annotations

import json
import os
import sys
import threading
from collections import OrderedDict
from hmac import compare_digest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

DEFAULT_UPSTREAM = "http://bitsec_proxy:8000"
DEFAULT_PINNED_MODEL = "qwen/qwen3.6-35b-a3b"
DEFAULT_AKASH_PINNED_MODEL = "Qwen/Qwen3.6-35B-A3B"
DEFAULT_AKASH_UPSTREAM = "https://api.akashml.com/v1/chat/completions"
DEFAULT_TIMEOUT_SECONDS = 900

# Default qwen/qwen3.6-35b-a3b prices (USD per 1M tokens); override via env.
DEFAULT_PRICE_INPUT_PER_M = 0.14
DEFAULT_PRICE_OUTPUT_PER_M = 1.00

# qwen3.6 is a reasoning model: on a real (large) codebase it emits thousands of
# reasoning tokens *before* the answer, so a small ``max_tokens`` truncates the
# completion mid-reasoning (finish_reason=length). The upstream proxy then rejects
# that as "response unusable" (HTTP 502), which the agent sees as an inference
# failure -> the candidate evaluation is marked invalid and every PR loses. But
# turning reasoning *off* makes detection too shallow (0 findings on real audits).
# The fix is to give the model enough room to both think and answer: the relay
# forces ``max_tokens`` up to this ceiling. It is a cap, not a target -- the model
# stops at finish_reason=stop long before it, so cost tracks actual usage.
DEFAULT_MAX_OUTPUT_TOKENS = 32000

# Per-agent inference budget. The validator funds every token, and candidates
# submit arbitrary agents, so each agent run gets a hard cap: once it exhausts
# its output-token OR call budget for the current problem it is refused further
# inference and must finalize with what it found. This bounds cost per agent and
# blocks a greedy/looping agent from draining the validator's funds. Runs are
# serial (one agent container at a time), so the budget window is keyed by the
# calling container's address and reset whenever a new container starts calling.
# 0 disables a limit. Override with KATA_RELAY_AGENT_TOKEN_BUDGET / _CALL_BUDGET.
# Per-agent budget, keyed per problem via the `/j/<token>/inference` path Kata
# sets (see AgentBudget). Each agent may make up to CALL_BUDGET successful model
# calls per problem, and at most TOKEN_BUDGET output tokens across them, whichever
# is reached first (further calls -> HTTP 429). Failed calls are not counted, so a
# transient failure can be retried. Individual calls are also clamped to
# KATA_RELAY_MAX_OUTPUT_TOKENS.
DEFAULT_AGENT_TOKEN_BUDGET = 24000
DEFAULT_AGENT_CALL_BUDGET = 3

# Only this path carries a model to overwrite; everything else is forwarded as-is.
INFERENCE_PATH = "/inference"
# Answered by the relay itself so operators can prove the process is up without
# depending on the upstream proxy.
HEALTH_PATH = "/healthz"
# Actively probes the upstream model provider with one tiny pinned request so a
# caller can tell whether inference genuinely works (e.g. the OpenRouter key is
# not exhausted) BEFORE spending a round's worth of tokens. Unlike /inference it
# does not force max_tokens up, so the probe is cheap and fast.
UPSTREAM_CHECK_PATH = "/healthz/upstream"
# Output-token ceiling for the upstream probe. Big enough that the reasoning model
# finishes a trivial reply (so a healthy provider returns 200), small enough to be
# cheap and fast (~2s).
HEALTHCHECK_MAX_TOKENS = 2000
# Relay-local cost accounting: read the running total, or zero it before a PR.
COST_PATH = "/costs"
COST_RESET_PATH = "/costs/reset"
ADMIN_TOKEN_ENV = "KATA_RELAY_ADMIN_TOKEN"
ADMIN_TOKEN_HEADER = "x-kata-relay-admin-token"
FORBIDDEN_SAMPLING_FIELDS = {
    "temperature",
    "top_p",
    "top_k",
    "min_p",
    "top_a",
    "frequency_penalty",
    "presence_penalty",
    "repetition_penalty",
    "seed",
    "logit_bias",
    "logprobs",
    "top_logprobs",
}

# Hop-by-hop headers must never be forwarded (RFC 7230 section 6.1); Host and
# Content-Length are recomputed by the outbound request instead of copied.
_SKIP_REQUEST_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
}
_SKIP_RESPONSE_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "content-length",
}

AKASH_KEY_PREFIXES = ("akml-", "akml_")


def is_akash_api_key(api_key: str | None) -> bool:
    """Return true when the inference key belongs to AkashML."""
    if not api_key:
        return False
    return api_key.strip().startswith(AKASH_KEY_PREFIXES)


def resolve_upstream() -> str:
    """Base URL of the real inference proxy the relay forwards to."""
    value = os.environ.get("KATA_RELAY_UPSTREAM")
    if value and value.strip():
        return value.strip().rstrip("/")
    return DEFAULT_UPSTREAM


def resolve_pinned_model(api_key: str | None = None) -> str:
    """The single model every inference request is forced onto."""
    value = os.environ.get("KATA_RELAY_PINNED_MODEL")
    if value and value.strip():
        pinned_model = value.strip()
        if is_akash_api_key(api_key) and pinned_model == DEFAULT_PINNED_MODEL:
            return DEFAULT_AKASH_PINNED_MODEL
        return pinned_model
    if is_akash_api_key(api_key):
        return DEFAULT_AKASH_PINNED_MODEL
    return DEFAULT_PINNED_MODEL


def resolve_akash_upstream() -> str:
    """OpenAI-compatible AkashML chat-completions endpoint."""
    value = os.environ.get("KATA_RELAY_AKASH_UPSTREAM")
    if value and value.strip():
        return value.strip()
    return DEFAULT_AKASH_UPSTREAM


def resolve_max_output_tokens() -> int:
    """Ceiling the relay forces ``max_tokens`` up to so the reasoning model has
    room to think *and* answer without the proxy rejecting a length-truncated
    response. 0 disables the override (leave the caller's max_tokens as-is)."""
    value = os.environ.get("KATA_RELAY_MAX_OUTPUT_TOKENS")
    if value is None or not value.strip():
        return DEFAULT_MAX_OUTPUT_TOKENS
    try:
        parsed = int(value.strip())
    except ValueError:
        return DEFAULT_MAX_OUTPUT_TOKENS
    return parsed if parsed >= 0 else DEFAULT_MAX_OUTPUT_TOKENS


def _resolve_budget(env_var: str, default: int) -> int:
    value = os.environ.get(env_var)
    if value is None or not value.strip():
        return default
    try:
        parsed = int(value.strip())
    except ValueError:
        return default
    return parsed if parsed >= 0 else default


def resolve_agent_token_budget() -> int:
    """Max output tokens one agent may generate per problem (0 = unlimited)."""
    return _resolve_budget("KATA_RELAY_AGENT_TOKEN_BUDGET", DEFAULT_AGENT_TOKEN_BUDGET)


def resolve_agent_call_budget() -> int:
    """Max inference calls one agent may make per problem (0 = unlimited)."""
    return _resolve_budget("KATA_RELAY_AGENT_CALL_BUDGET", DEFAULT_AGENT_CALL_BUDGET)


def resolve_timeout() -> float:
    """Upstream request timeout; kept high because agent inference can be slow."""
    value = os.environ.get("KATA_RELAY_TIMEOUT")
    if value and value.strip():
        try:
            parsed = float(value.strip())
        except ValueError:
            return float(DEFAULT_TIMEOUT_SECONDS)
        if parsed > 0:
            return parsed
    return float(DEFAULT_TIMEOUT_SECONDS)


def resolve_admin_token() -> str:
    """Shared secret for relay operator endpoints.

    The relay is reachable by untrusted agent containers, so endpoints that can
    spend upstream tokens or mutate accounting must require an operator token.
    When unset, those endpoints are disabled rather than left open.
    """
    return os.environ.get(ADMIN_TOKEN_ENV, "").strip()


def _resolve_price(env_var: str, default: float) -> float:
    value = os.environ.get(env_var)
    if value and value.strip():
        try:
            parsed = float(value.strip())
        except ValueError:
            return default
        if parsed >= 0:
            return parsed
    return default


def resolve_price_input() -> float:
    """USD per 1M input tokens (defaults to the qwen input price)."""
    return _resolve_price("KATA_RELAY_PRICE_INPUT_PER_M", DEFAULT_PRICE_INPUT_PER_M)


def resolve_price_output() -> float:
    """USD per 1M output tokens (defaults to the qwen output price)."""
    return _resolve_price("KATA_RELAY_PRICE_OUTPUT_PER_M", DEFAULT_PRICE_OUTPUT_PER_M)


def _as_int(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def extract_usage(body: bytes) -> tuple[int, int, int]:
    """Pull (input, output, cached) token counts from an inference response.

    Prefers the OpenAI-style ``usage`` block; falls back to the proxy's flattened
    ``input_tokens``/``output_tokens`` fields. Returns zeros for anything we cannot
    read, so a surprising response body never breaks accounting or forwarding.
    """
    try:
        payload = json.loads(body)
    except (ValueError, TypeError):
        return (0, 0, 0)
    if not isinstance(payload, dict):
        return (0, 0, 0)

    input_tokens = output_tokens = cached_tokens = 0
    usage = payload.get("usage")
    if isinstance(usage, dict):
        input_tokens = _as_int(usage.get("prompt_tokens"))
        output_tokens = _as_int(usage.get("completion_tokens"))
        details = usage.get("prompt_tokens_details")
        if isinstance(details, dict):
            cached_tokens = _as_int(details.get("cached_tokens"))
    if input_tokens == 0:
        input_tokens = _as_int(payload.get("input_tokens"))
    if output_tokens == 0:
        output_tokens = _as_int(payload.get("output_tokens"))
    if cached_tokens == 0:
        cached_tokens = _as_int(payload.get("cached_tokens"))
    return (input_tokens, output_tokens, cached_tokens)


class CostMeter:
    """Thread-safe running total of agent inference tokens and their USD cost."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._input = 0
        self._output = 0
        self._cached = 0
        self._requests = 0

    def add(self, input_tokens: int, output_tokens: int, cached_tokens: int) -> None:
        with self._lock:
            self._input += input_tokens
            self._output += output_tokens
            self._cached += cached_tokens
            self._requests += 1

    def reset(self) -> None:
        with self._lock:
            self._input = 0
            self._output = 0
            self._cached = 0
            self._requests = 0

    def snapshot(self, price_input_per_m: float, price_output_per_m: float) -> dict:
        with self._lock:
            input_tokens = self._input
            output_tokens = self._output
            cached_tokens = self._cached
            requests = self._requests
        usd_input = round(input_tokens / 1_000_000 * price_input_per_m, 6)
        usd_output = round(output_tokens / 1_000_000 * price_output_per_m, 6)
        return {
            "requests": requests,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cached_tokens": cached_tokens,
            "price_input_per_1m_usd": price_input_per_m,
            "price_output_per_1m_usd": price_output_per_m,
            "usd_input": usd_input,
            "usd_output": usd_output,
            "usd_total": round(usd_input + usd_output, 6),
            "model": resolve_pinned_model(),
        }


# Process-wide meter shared across handler threads. Covers only agent inference
# (qwen) — scoring runs on a separate proxy endpoint that never reaches the relay.
COST_METER = CostMeter()


class AgentBudget:
    """Per-agent inference budget, keyed by the per-problem token Kata embeds in
    the inference URL (``/j/<token>/inference``).

    Each key -- one agent working one problem -- accrues its own call count and
    output-token total independently, so problems scored *concurrently* (each with
    a distinct token) never disturb one another's budget. Keying on the token (not
    the network source) is what makes this correct even though every agent reaches
    the relay from the same gateway address.

    The budget is a *cap*, never a quota: the relay only ever counts and refuses the
    agent's own calls, it never issues one. An agent that calls the model once is
    charged for one call; the limits only bite once the agent itself tries to exceed
    them.
    """

    # Bound the number of tracked keys so a long-lived relay cannot leak memory
    # across many rounds. Tokens are unique per problem and never reused, so
    # evicting the oldest key is safe -- it will never be seen again.
    MAX_TRACKED_KEYS = 8192

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_key: OrderedDict[str, dict[str, int]] = OrderedDict()

    def _bucket(self, key: str) -> dict[str, int]:
        bucket = self._by_key.get(key)
        if bucket is None:
            bucket = {"tokens": 0, "calls": 0}
            self._by_key[key] = bucket
            while len(self._by_key) > self.MAX_TRACKED_KEYS:
                self._by_key.popitem(last=False)
        return bucket

    def allow(self, key: str) -> tuple[bool, str | None]:
        with self._lock:
            bucket = self._bucket(key)
            max_calls = resolve_agent_call_budget()
            max_tokens = resolve_agent_token_budget()
            if max_calls and bucket["calls"] >= max_calls:
                return False, f"inference call budget ({max_calls}) exhausted for this problem"
            if max_tokens and bucket["tokens"] >= max_tokens:
                return False, f"output-token budget ({max_tokens}) exhausted for this problem"
            return True, None

    def record(self, key: str, output_tokens: int) -> None:
        with self._lock:
            bucket = self._bucket(key)
            bucket["tokens"] += output_tokens
            bucket["calls"] += 1

    def reset(self) -> None:
        with self._lock:
            self._by_key.clear()


AGENT_BUDGET = AgentBudget()


def pin_model_in_body(body: bytes, model: str, max_output_tokens: int = 0) -> bytes:
    """Force the OpenAI-compatible request body onto ``model``.

    A body we cannot read as a JSON object is returned untouched: the upstream
    proxy is the authority on request validity. For JSON objects, remove
    miner-controlled sampling knobs so fairness is enforced at the real network
    boundary, not only by static source checks, and raise ``max_tokens`` up to
    ``max_output_tokens`` (when > 0) so the pinned reasoning model has room to
    both reason and emit its answer -- a small cap truncates it mid-reasoning and
    the proxy rejects the unusable, length-finished response.
    """
    try:
        payload = json.loads(body)
    except (ValueError, TypeError):
        return body
    if not isinstance(payload, dict):
        return body
    payload["model"] = model
    for field in FORBIDDEN_SAMPLING_FIELDS:
        payload.pop(field, None)
    if max_output_tokens > 0:
        # Force max_tokens to exactly the ceiling: raise a too-small request so the
        # reasoning model has room to think AND answer, and clamp a too-large one
        # so a single call can't run away (agents were observed requesting ~82k).
        payload["max_tokens"] = max_output_tokens
    return json.dumps(payload).encode("utf-8")


class ModelPinningRelayHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    # -- request entry points -------------------------------------------------
    def do_GET(self) -> None:
        path = self._path_without_query()
        if path == HEALTH_PATH:
            self._send_json(200, {"status": "ok", "pinned_model": resolve_pinned_model()})
            return
        if path == COST_PATH:
            self._send_json(200, COST_METER.snapshot(resolve_price_input(), resolve_price_output()))
            return
        self._forward("GET")

    def do_POST(self) -> None:
        path = self._path_without_query()
        if path == COST_RESET_PATH:
            self._read_body()  # drain any body so the connection stays consistent
            if not self._admin_authorized():
                self._send_json(403, {"status": "error", "detail": "admin token required"})
                return
            COST_METER.reset()
            self._send_json(200, {"status": "reset"})
            return
        if path == UPSTREAM_CHECK_PATH:
            if not self._admin_authorized():
                self._read_body()
                self._send_json(403, {"status": "error", "detail": "admin token required"})
                return
            self._handle_upstream_check()
            return
        self._forward("POST")

    def _handle_upstream_check(self) -> None:
        """Send one tiny pinned request upstream and report whether it succeeded.

        Returns 200 with ``{"ok": bool, "status": <upstream status>, "detail": ...}``
        so a caller can decide whether inference is usable without parsing HTTP
        errors. ``max_tokens`` is kept at 1 (not forced up) so this stays cheap.
        """
        self._read_body()  # drain any body the caller sent
        # The pinned model reasons before answering, so a 1-token probe truncates and
        # the proxy rejects it as unusable (a false failure). Give it enough room to
        # finish a trivial reply; a healthy provider returns 200 in ~2s, an exhausted
        # key still fails fast with 403.
        api_key = self._inference_api_key()
        pinned_model = resolve_pinned_model(api_key)
        probe_body = json.dumps(
            {
                "model": pinned_model,
                "messages": [{"role": "user", "content": "Reply with the single word OK."}],
                "max_tokens": HEALTHCHECK_MAX_TOKENS,
            }
        ).encode()
        request = self._build_upstream_request(
            api_key=api_key,
            body=probe_body,
            upstream_path=INFERENCE_PATH,
            method="POST",
        )
        try:
            with urlopen(request, timeout=min(resolve_timeout(), 60.0)) as response:
                self._send_json(
                    200, {"ok": 200 <= response.status < 300, "status": response.status}
                )
        except HTTPError as error:
            try:
                detail = (error.read()[:300] or b"").decode("utf-8", "replace")
            except Exception:  # noqa: BLE001 - detail is best-effort
                detail = ""
            self._send_json(200, {"ok": False, "status": error.code, "detail": detail})
        except URLError as error:
            self._send_json(
                200,
                {"ok": False, "status": 0, "detail": f"could not reach upstream: {error.reason}"},
            )

    # -- forwarding -----------------------------------------------------------
    def _forward(self, method: str) -> None:
        body = self._read_body()
        path = self._path_without_query()
        query = self.path[len(path):]
        # Agents call `<INFERENCE_API>/inference`, and Kata sets INFERENCE_API to
        # `.../j/<token>` so each problem carries its own budget key. Accept both
        # the tokenized path and a bare /inference (which shares a "default" key).
        budget_key = "default"
        upstream_path = self.path
        if method == "POST" and path.startswith("/j/") and path.endswith(INFERENCE_PATH):
            budget_key = path[len("/j/") : -len(INFERENCE_PATH)].strip("/") or "default"
            upstream_path = INFERENCE_PATH + query
            is_inference = True
        else:
            is_inference = method == "POST" and path == INFERENCE_PATH
        if not is_inference:
            self._send_json(
                404,
                {
                    "status": "error",
                    "reason": "Only POST /inference and relay-local endpoints are allowed.",
                },
            )
            return

        # Enforce the per-agent (per-problem) inference budget before spending
        # upstream tokens.
        allowed, reason = AGENT_BUDGET.allow(budget_key)
        if not allowed:
            self._send_json(429, {"status": "error", "detail": f"inference budget: {reason}"})
            return

        api_key = self._inference_api_key()
        pinned_model = resolve_pinned_model(api_key)
        body = pin_model_in_body(body, pinned_model, resolve_max_output_tokens())

        headers = {
            key: value
            for key, value in self.headers.items()
            if key.lower() not in _SKIP_REQUEST_HEADERS
        }
        request = self._build_upstream_request(
            api_key=api_key,
            body=body,
            upstream_path=upstream_path,
            method=method,
            proxy_headers=headers,
        )
        try:
            with urlopen(request, timeout=resolve_timeout()) as response:
                response_body = response.read()
                if is_inference and 200 <= response.status < 300:
                    _, output_tokens, _ = extract_usage(response_body)
                    self._meter(response_body)
                    AGENT_BUDGET.record(budget_key, output_tokens)
                self._relay_response(response.status, response.headers.items(), response_body)
        except HTTPError as error:
            # Upstream returned a real HTTP error (4xx/5xx); pass it through verbatim.
            self._relay_response(error.code, error.headers.items(), error.read())
        except URLError as error:
            self._send_json(502, {"detail": f"relay could not reach upstream: {error.reason}"})

    def _meter(self, response_body: bytes) -> None:
        input_tokens, output_tokens, cached_tokens = extract_usage(response_body)
        if input_tokens or output_tokens:
            COST_METER.add(input_tokens, output_tokens, cached_tokens)

    def _build_upstream_request(
        self,
        *,
        api_key: str,
        body: bytes,
        upstream_path: str,
        method: str,
        proxy_headers: dict[str, str] | None = None,
    ) -> Request:
        if is_akash_api_key(api_key):
            return Request(
                resolve_akash_upstream(),
                data=body if body else None,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {api_key}",
                },
                method=method,
            )

        headers = proxy_headers or {"Content-Type": "application/json"}
        if api_key:
            headers["x-inference-api-key"] = api_key
        return Request(
            resolve_upstream() + upstream_path,
            data=body if body else None,
            headers=headers,
            method=method,
        )

    def _relay_response(self, status: int, header_items, body: bytes) -> None:
        self.send_response(status)
        for key, value in header_items:
            if key.lower() in _SKIP_RESPONSE_HEADERS:
                continue
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    # -- helpers --------------------------------------------------------------
    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length > 0 else b""

    def _path_without_query(self) -> str:
        return self.path.split("?", 1)[0]

    def _inference_api_key(self) -> str:
        return self.headers.get("x-inference-api-key", "").strip()

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _admin_authorized(self) -> bool:
        expected = resolve_admin_token()
        if not expected:
            return False
        supplied = self.headers.get(ADMIN_TOKEN_HEADER, "")
        return compare_digest(supplied, expected)

    def log_message(self, *_args) -> None:
        # Silence per-request logging; inference bodies could be large/noisy.
        return


def build_server(host: str, port: int) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), ModelPinningRelayHandler)
    server.daemon_threads = True
    return server


def main() -> int:
    host = os.environ.get("KATA_RELAY_HOST", "0.0.0.0")
    port = int(os.environ.get("KATA_RELAY_PORT", "8000"))
    server = build_server(host, port)
    print(
        f"SN60 model-pinning relay listening on {host}:{port} -> {resolve_upstream()} "
        f"(model pinned to {resolve_pinned_model()}; cost at GET {COST_PATH}, "
        f"zero it with POST {COST_RESET_PATH})",
        file=sys.stderr,
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
