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
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

DEFAULT_UPSTREAM = "http://bitsec_proxy:8000"
DEFAULT_PINNED_MODEL = "qwen/qwen3.6-35b-a3b"
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
# sets (see AgentBudget). Each agent may make at most this many calls / output
# tokens per problem before the relay refuses further calls (HTTP 429).
DEFAULT_AGENT_TOKEN_BUDGET = 24000
DEFAULT_AGENT_CALL_BUDGET = 3

# Only this path carries a model to overwrite; everything else is forwarded as-is.
INFERENCE_PATH = "/inference"
# Answered by the relay itself so operators can prove the process is up without
# depending on the upstream proxy.
HEALTH_PATH = "/healthz"
# Relay-local cost accounting: read the running total, or zero it before a PR.
COST_PATH = "/costs"
COST_RESET_PATH = "/costs/reset"
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


def resolve_upstream() -> str:
    """Base URL of the real inference proxy the relay forwards to."""
    value = os.environ.get("KATA_RELAY_UPSTREAM")
    if value and value.strip():
        return value.strip().rstrip("/")
    return DEFAULT_UPSTREAM


def resolve_pinned_model() -> str:
    """The single model every inference request is forced onto."""
    value = os.environ.get("KATA_RELAY_PINNED_MODEL")
    if value and value.strip():
        return value.strip()
    return DEFAULT_PINNED_MODEL


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

    Scoring is serial (one agent container runs at a time) and each problem gets a
    distinct token, so a change of token marks a new agent/problem and resets the
    window. Keying on the token (not the network source) is what makes this correct
    even though every agent reaches the relay from the same gateway address.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._key: str | None = None
        self._tokens = 0
        self._calls = 0

    def allow(self, key: str) -> tuple[bool, str | None]:
        with self._lock:
            if key != self._key:
                self._key = key
                self._tokens = 0
                self._calls = 0
            max_calls = resolve_agent_call_budget()
            max_tokens = resolve_agent_token_budget()
            if max_calls and self._calls >= max_calls:
                return False, f"inference call budget ({max_calls}) exhausted for this problem"
            if max_tokens and self._tokens >= max_tokens:
                return False, f"output-token budget ({max_tokens}) exhausted for this problem"
            return True, None

    def record(self, key: str, output_tokens: int) -> None:
        with self._lock:
            if key == self._key:
                self._tokens += output_tokens
                self._calls += 1

    def reset(self) -> None:
        with self._lock:
            self._key = None
            self._tokens = 0
            self._calls = 0


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
        if self._path_without_query() == COST_RESET_PATH:
            self._read_body()  # drain any body so the connection stays consistent
            COST_METER.reset()
            self._send_json(200, {"status": "reset"})
            return
        self._forward("POST")

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

        body = pin_model_in_body(body, resolve_pinned_model(), resolve_max_output_tokens())

        headers = {
            key: value
            for key, value in self.headers.items()
            if key.lower() not in _SKIP_REQUEST_HEADERS
        }
        url = resolve_upstream() + upstream_path
        request = Request(
            url,
            data=body if body else None,
            headers=headers,
            method=method,
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

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

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
