"""SN60 model-pinning inference relay.

Untrusted miner agents run inside an internet-blocked Docker network, so the only
way they can reach an LLM is through the inference endpoint Kata hands them via
``KATA_SN60_INFERENCE_API``. Point that variable at this relay and it forces every
inference request onto a single pinned model before forwarding to the real Bitsec
proxy. That protects the validator two ways at once:

* **Cost** — a miner cannot spend the validator's inference budget on a costlier
  model; the model is overwritten no matter what the agent's code asked for.
* **Fairness** — king and candidate are guaranteed to duel on the same model.

Enforcement happens on the actual API call, not by scanning source, so runtime or
obfuscated model strings cannot bypass it: the internal network gives the agent no
other route to a provider. Every non-inference request (metrics, health) is passed
through untouched — the relay only ever rewrites the ``model`` field of a
``POST /inference`` body.

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

# Only this path carries a model to overwrite; everything else is forwarded as-is.
INFERENCE_PATH = "/inference"
# Answered by the relay itself so operators can prove the process is up without
# depending on the upstream proxy.
HEALTH_PATH = "/healthz"
# Relay-local cost accounting: read the running total, or zero it before a PR.
COST_PATH = "/costs"
COST_RESET_PATH = "/costs/reset"

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


def resolve_admin_token() -> str | None:
    """Operator-only credential for POST /costs/reset; unset disables the endpoint."""
    value = os.environ.get("KATA_RELAY_ADMIN_TOKEN")
    if value and value.strip():
        return value.strip()
    return None


def _read_bearer_token(authorization: str | None) -> str | None:
    if not authorization:
        return None
    prefix = "bearer "
    if authorization.lower().startswith(prefix):
        token = authorization[len(prefix) :].strip()
        return token or None
    return None


def authorize_cost_reset(authorization: str | None) -> tuple[bool, int, str]:
    """Return (allowed, http_status, detail) for POST /costs/reset."""
    expected = resolve_admin_token()
    if expected is None:
        return (False, 403, "cost reset is disabled without KATA_RELAY_ADMIN_TOKEN")
    provided = _read_bearer_token(authorization)
    if provided is None:
        return (False, 401, "missing bearer token")
    if provided != expected:
        return (False, 403, "invalid bearer token")
    return (True, 200, "reset")


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


def pin_model_in_body(body: bytes, model: str) -> bytes:
    """Force the OpenAI-compatible request body onto ``model``.

    A body we cannot read as a JSON object is returned untouched: the upstream
    proxy is the authority on request validity, so the relay's only job is to
    overwrite the model field when one could exist, never to reject traffic.
    """
    try:
        payload = json.loads(body)
    except (ValueError, TypeError):
        return body
    if not isinstance(payload, dict):
        return body
    payload["model"] = model
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
            allowed, status, detail = authorize_cost_reset(
                self.headers.get("Authorization")
            )
            if not allowed:
                self._send_json(status, {"detail": detail})
                return
            COST_METER.reset()
            self._send_json(200, {"status": "reset"})
            return
        self._forward("POST")

    # -- forwarding -----------------------------------------------------------
    def _forward(self, method: str) -> None:
        body = self._read_body()
        is_inference = method == "POST" and self._path_without_query() == INFERENCE_PATH
        if is_inference:
            body = pin_model_in_body(body, resolve_pinned_model())

        headers = {
            key: value
            for key, value in self.headers.items()
            if key.lower() not in _SKIP_REQUEST_HEADERS
        }
        url = resolve_upstream() + self.path
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
                    self._meter(response_body)
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
