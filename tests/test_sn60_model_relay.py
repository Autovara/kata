from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from kata.packages.sn60.validator_system.model_relay import (
    ADMIN_TOKEN_HEADER,
    AGENT_BUDGET,
    COST_METER,
    DEFAULT_DIRECT_PINNED_MODEL,
    DEFAULT_DIRECT_UPSTREAM,
    DEFAULT_PINNED_MODEL,
    DEFAULT_UPSTREAM,
    CostMeter,
    build_server,
    extract_usage,
    is_akash_api_key,
    is_proxy_api_key,
    pin_model_in_body,
    resolve_direct_provider,
    resolve_max_output_tokens,
    resolve_pinned_model,
    resolve_timeout,
    resolve_upstream,
)

# --- pin_model_in_body ------------------------------------------------------


def test_pin_model_overwrites_requested_model() -> None:
    body = json.dumps({"model": "anthropic/claude-opus", "messages": []}).encode()
    out = json.loads(pin_model_in_body(body, "qwen/pinned"))
    assert out["model"] == "qwen/pinned"
    assert out["messages"] == []


def test_pin_model_adds_model_when_absent() -> None:
    body = json.dumps({"messages": [{"role": "user", "content": "hi"}]}).encode()
    out = json.loads(pin_model_in_body(body, "qwen/pinned"))
    assert out["model"] == "qwen/pinned"


def test_pin_model_preserves_tools_and_removes_sampling_fields() -> None:
    body = json.dumps(
        {
            "model": "x",
            "messages": [],
            "tools": [{"t": 1}],
            "temperature": 0.9,
            "seed": 123,
        }
    ).encode()
    out = json.loads(pin_model_in_body(body, "qwen/pinned"))
    assert out["model"] == "qwen/pinned"
    assert out["tools"] == [{"t": 1}]
    assert "temperature" not in out
    assert "seed" not in out


def test_pin_model_raises_small_max_tokens_to_ceiling() -> None:
    body = json.dumps({"model": "x", "messages": [], "max_tokens": 4000}).encode()
    out = json.loads(pin_model_in_body(body, "qwen/pinned", max_output_tokens=32000))
    assert out["max_tokens"] == 32000


def test_pin_model_adds_max_tokens_when_absent() -> None:
    body = json.dumps({"model": "x", "messages": []}).encode()
    out = json.loads(pin_model_in_body(body, "qwen/pinned", max_output_tokens=32000))
    assert out["max_tokens"] == 32000


def test_pin_model_clamps_larger_requested_max_tokens() -> None:
    # A call asking for more than the ceiling is clamped down so it can't run away.
    body = json.dumps({"model": "x", "messages": [], "max_tokens": 82000}).encode()
    out = json.loads(pin_model_in_body(body, "qwen/pinned", max_output_tokens=32000))
    assert out["max_tokens"] == 32000


def test_pin_model_leaves_max_tokens_untouched_when_override_zero() -> None:
    body = json.dumps({"model": "x", "messages": [], "max_tokens": 4000}).encode()
    out = json.loads(pin_model_in_body(body, "qwen/pinned", max_output_tokens=0))
    assert out["max_tokens"] == 4000


def test_pin_model_leaves_non_json_untouched() -> None:
    body = b"not json at all"
    assert pin_model_in_body(body, "qwen/pinned") == body


def test_pin_model_leaves_json_non_object_untouched() -> None:
    body = json.dumps([1, 2, 3]).encode()
    assert pin_model_in_body(body, "qwen/pinned") == body


# --- env resolution ---------------------------------------------------------


def test_resolve_upstream_default(monkeypatch) -> None:
    monkeypatch.delenv("KATA_RELAY_UPSTREAM", raising=False)
    assert resolve_upstream() == DEFAULT_UPSTREAM


def test_resolve_upstream_strips_trailing_slash(monkeypatch) -> None:
    monkeypatch.setenv("KATA_RELAY_UPSTREAM", "http://proxy:8000/")
    assert resolve_upstream() == "http://proxy:8000"


def test_resolve_pinned_model_default(monkeypatch) -> None:
    monkeypatch.delenv("KATA_RELAY_PINNED_MODEL", raising=False)
    assert resolve_pinned_model() == DEFAULT_PINNED_MODEL


def test_resolve_pinned_model_uses_akash_default_for_akash_keys(monkeypatch) -> None:
    monkeypatch.delenv("KATA_RELAY_PINNED_MODEL", raising=False)
    assert resolve_pinned_model("akml-test") == DEFAULT_DIRECT_PINNED_MODEL
    assert resolve_pinned_model("akml_test") == DEFAULT_DIRECT_PINNED_MODEL


def test_resolve_pinned_model_treats_standard_default_as_provider_default(monkeypatch) -> None:
    monkeypatch.setenv("KATA_RELAY_PINNED_MODEL", DEFAULT_PINNED_MODEL)
    assert resolve_pinned_model("akml-test") == DEFAULT_DIRECT_PINNED_MODEL
    assert resolve_pinned_model("sk-or-test") == DEFAULT_PINNED_MODEL


def test_resolve_pinned_model_override(monkeypatch) -> None:
    monkeypatch.setenv("KATA_RELAY_PINNED_MODEL", "vendor/model")
    assert resolve_pinned_model() == "vendor/model"
    assert resolve_pinned_model("akml-test") == "vendor/model"


def test_is_akash_api_key_detects_known_prefixes() -> None:
    assert is_akash_api_key("akml-test")
    assert is_akash_api_key("akml_test")
    assert not is_akash_api_key("sk-or-test")
    assert not is_akash_api_key("cpk_test")
    assert not is_akash_api_key("")


def test_is_proxy_api_key_detects_existing_proxy_router_prefixes() -> None:
    assert is_proxy_api_key("sk-or-test")
    assert is_proxy_api_key("cpk_test")
    assert not is_proxy_api_key("akml-test")
    assert not is_proxy_api_key("other-key")


def test_resolve_direct_provider_uses_akash_defaults_and_overrides(monkeypatch) -> None:
    monkeypatch.delenv("KATA_RELAY_AKASH_UPSTREAM", raising=False)
    monkeypatch.delenv("KATA_RELAY_AKASH_MODEL", raising=False)
    provider = resolve_direct_provider("akml-test")
    assert provider is not None
    assert provider.upstream == DEFAULT_DIRECT_UPSTREAM
    assert provider.model == DEFAULT_DIRECT_PINNED_MODEL
    monkeypatch.setenv("KATA_RELAY_AKASH_UPSTREAM", "http://akash.local/v1/chat/completions")
    monkeypatch.setenv("KATA_RELAY_AKASH_MODEL", "Akash/Custom")
    provider = resolve_direct_provider("akml-test")
    assert provider is not None
    assert provider.upstream == "http://akash.local/v1/chat/completions"
    assert provider.model == "Akash/Custom"


def test_resolve_direct_provider_supports_configured_provider(monkeypatch) -> None:
    monkeypatch.setenv("KATA_RELAY_DIRECT_KEY_PREFIXES", "foo-,bar_")
    monkeypatch.setenv("KATA_RELAY_DIRECT_UPSTREAM", "https://provider.example/v1/chat/completions")
    monkeypatch.setenv("KATA_RELAY_DIRECT_MODEL", "Provider/Model")
    monkeypatch.setenv("KATA_RELAY_DIRECT_AUTH_HEADER", "X-API-Key")
    monkeypatch.setenv("KATA_RELAY_DIRECT_AUTH_VALUE_TEMPLATE", "Token {api_key}")

    provider = resolve_direct_provider("foo-secret")

    assert provider is not None
    assert provider.upstream == "https://provider.example/v1/chat/completions"
    assert provider.model == "Provider/Model"
    assert provider.auth_header == "X-API-Key"
    assert provider.auth_value_template == "Token {api_key}"
    assert resolve_direct_provider("sk-or-test") is None
    assert resolve_direct_provider("cpk_test") is None


def test_resolve_direct_provider_can_allow_unknown_keys(monkeypatch) -> None:
    monkeypatch.setenv("KATA_RELAY_DIRECT_ALLOW_UNKNOWN", "1")
    monkeypatch.setenv("KATA_RELAY_DIRECT_UPSTREAM", "https://provider.example/v1/chat/completions")
    monkeypatch.setenv("KATA_RELAY_DIRECT_MODEL", "Provider/Model")

    provider = resolve_direct_provider("unknown-secret")

    assert provider is not None
    assert provider.model == "Provider/Model"
    assert resolve_direct_provider("sk-or-test") is None


def test_resolve_max_output_tokens_default(monkeypatch) -> None:
    monkeypatch.delenv("KATA_RELAY_MAX_OUTPUT_TOKENS", raising=False)
    assert resolve_max_output_tokens() == 32000


def test_resolve_max_output_tokens_override(monkeypatch) -> None:
    monkeypatch.setenv("KATA_RELAY_MAX_OUTPUT_TOKENS", "16000")
    assert resolve_max_output_tokens() == 16000
    monkeypatch.setenv("KATA_RELAY_MAX_OUTPUT_TOKENS", "0")
    assert resolve_max_output_tokens() == 0
    monkeypatch.setenv("KATA_RELAY_MAX_OUTPUT_TOKENS", "garbage")
    assert resolve_max_output_tokens() == 32000


def test_resolve_timeout_invalid_falls_back(monkeypatch) -> None:
    monkeypatch.setenv("KATA_RELAY_TIMEOUT", "not-a-number")
    assert resolve_timeout() == 900.0


def test_resolve_timeout_reads_positive_override(monkeypatch) -> None:
    monkeypatch.setenv("KATA_RELAY_TIMEOUT", "12.5")
    assert resolve_timeout() == 12.5


# --- end-to-end over real sockets -------------------------------------------


class _RecordingUpstream(BaseHTTPRequestHandler):
    """Fake Bitsec proxy: records each request and returns a canned response."""

    def _handle(self, method: str) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        self.server.records.append(  # type: ignore[attr-defined]
            {
                "method": method,
                "path": self.path,
                "headers": {k.lower(): v for k, v in self.headers.items()},
                "body": body,
            }
        )
        force_status = getattr(self.server, "force_status", None)
        if force_status is not None:
            self._reply(
                force_status,
                {"error": {"message": "Key limit exceeded (total limit)", "code": force_status}},
            )
            return
        if self.headers.get("X-Upstream-Boom") == "yes":
            self._reply(502, {"detail": "upstream boom"})
            return
        self._reply(
            200,
            {
                "ok": True,
                "echo_path": self.path,
                "usage": {"prompt_tokens": 100, "completion_tokens": 20},
            },
            extra_header=("X-Upstream", "yes"),
        )

    def _reply(self, status: int, payload: dict, extra_header=None) -> None:
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        if extra_header is not None:
            self.send_header(*extra_header)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:
        self._handle("POST")

    def do_GET(self) -> None:
        self._handle("GET")

    def log_message(self, *_args) -> None:
        return


@pytest.fixture
def relay_and_upstream(monkeypatch):
    COST_METER.reset()  # process-wide meter; keep each test independent
    AGENT_BUDGET.reset()  # process-wide per-agent budget; isolate each test
    # Default the budget off so it doesn't interfere with non-budget tests; the
    # budget tests set their own limits explicitly.
    monkeypatch.setenv("KATA_RELAY_AGENT_CALL_BUDGET", "0")
    monkeypatch.setenv("KATA_RELAY_AGENT_INPUT_TOKEN_BUDGET", "0")
    monkeypatch.setenv("KATA_RELAY_AGENT_TOKEN_BUDGET", "0")
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), _RecordingUpstream)
    upstream.records = []  # type: ignore[attr-defined]
    upstream.daemon_threads = True
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    upstream_port = upstream.server_address[1]

    monkeypatch.setenv("KATA_RELAY_UPSTREAM", f"http://127.0.0.1:{upstream_port}")
    monkeypatch.setenv("KATA_RELAY_PINNED_MODEL", "qwen/pinned-test")
    monkeypatch.setenv("KATA_RELAY_PRICE_INPUT_PER_M", "2")
    monkeypatch.setenv("KATA_RELAY_PRICE_OUTPUT_PER_M", "5")
    monkeypatch.setenv("KATA_RELAY_ADMIN_TOKEN", "test-admin")

    relay = build_server("127.0.0.1", 0)
    threading.Thread(target=relay.serve_forever, daemon=True).start()
    relay_base = f"http://127.0.0.1:{relay.server_address[1]}"

    try:
        yield relay_base, upstream
    finally:
        relay.shutdown()
        upstream.shutdown()


@pytest.fixture
def akash_upstream(monkeypatch):
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), _RecordingUpstream)
    upstream.records = []  # type: ignore[attr-defined]
    upstream.daemon_threads = True
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    upstream_port = upstream.server_address[1]
    monkeypatch.setenv(
        "KATA_RELAY_AKASH_UPSTREAM",
        f"http://127.0.0.1:{upstream_port}/v1/chat/completions",
    )

    try:
        yield upstream
    finally:
        upstream.shutdown()


@pytest.fixture
def generic_direct_upstream(monkeypatch):
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), _RecordingUpstream)
    upstream.records = []  # type: ignore[attr-defined]
    upstream.daemon_threads = True
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    upstream_port = upstream.server_address[1]
    monkeypatch.setenv("KATA_RELAY_DIRECT_KEY_PREFIXES", "foo-")
    monkeypatch.setenv(
        "KATA_RELAY_DIRECT_UPSTREAM",
        f"http://127.0.0.1:{upstream_port}/v1/chat/completions",
    )
    monkeypatch.setenv("KATA_RELAY_DIRECT_MODEL", "Provider/Model")
    monkeypatch.setenv("KATA_RELAY_DIRECT_AUTH_HEADER", "X-API-Key")
    monkeypatch.setenv("KATA_RELAY_DIRECT_AUTH_VALUE_TEMPLATE", "Token {api_key}")

    try:
        yield upstream
    finally:
        upstream.shutdown()


def _post(url: str, body: bytes, headers: dict[str, str] | None = None):
    request = Request(url, data=body, method="POST", headers=headers or {})
    with urlopen(request, timeout=10) as response:
        return (
            response.status,
            response.read(),
            {k.lower(): v for k, v in response.headers.items()},
        )


def _admin_headers(extra: dict[str, str] | None = None) -> dict[str, str]:
    return {ADMIN_TOKEN_HEADER: "test-admin", **(extra or {})}


def test_inference_budget_refuses_agent_after_call_limit(relay_and_upstream, monkeypatch) -> None:
    base, upstream = relay_and_upstream
    AGENT_BUDGET.reset()
    monkeypatch.setenv("KATA_RELAY_AGENT_CALL_BUDGET", "2")
    monkeypatch.setenv("KATA_RELAY_AGENT_INPUT_TOKEN_BUDGET", "0")
    monkeypatch.setenv("KATA_RELAY_AGENT_TOKEN_BUDGET", "0")  # isolate the call-count cap
    body = json.dumps({"messages": [{"role": "user", "content": "x"}]}).encode()

    for _ in range(2):
        status, _, _ = _post(base + "/inference", body)
        assert status == 200

    seen = len(upstream.records)
    with pytest.raises(HTTPError) as excinfo:
        _post(base + "/inference", body)
    assert excinfo.value.code == 429
    # The refused call never reached upstream, so it cost nothing.
    assert len(upstream.records) == seen
    AGENT_BUDGET.reset()


def test_inference_budget_refuses_agent_after_input_token_limit(
    relay_and_upstream, monkeypatch
) -> None:
    base, upstream = relay_and_upstream
    AGENT_BUDGET.reset()
    monkeypatch.setenv("KATA_RELAY_AGENT_CALL_BUDGET", "0")
    monkeypatch.setenv("KATA_RELAY_AGENT_INPUT_TOKEN_BUDGET", "200")
    monkeypatch.setenv("KATA_RELAY_AGENT_TOKEN_BUDGET", "0")
    body = json.dumps({"messages": [{"role": "user", "content": "x"}]}).encode()

    for _ in range(2):
        status, _, _ = _post(base + "/j/AAA/inference", body)
        assert status == 200

    seen = len(upstream.records)
    with pytest.raises(HTTPError) as excinfo:
        _post(base + "/j/AAA/inference", body)
    assert excinfo.value.code == 429
    assert "input-token budget" in excinfo.value.read().decode()
    assert len(upstream.records) == seen
    AGENT_BUDGET.reset()


def test_inference_budget_is_per_problem_token_not_global(relay_and_upstream, monkeypatch) -> None:
    # The bug this guards against: a shared source address made the budget cap the
    # whole round. Keying on the per-problem token, each problem gets its own budget.
    base, upstream = relay_and_upstream
    AGENT_BUDGET.reset()
    monkeypatch.setenv("KATA_RELAY_AGENT_CALL_BUDGET", "2")
    monkeypatch.setenv("KATA_RELAY_AGENT_INPUT_TOKEN_BUDGET", "0")
    monkeypatch.setenv("KATA_RELAY_AGENT_TOKEN_BUDGET", "0")
    body = json.dumps({"messages": [{"role": "user", "content": "x"}]}).encode()

    # Problem token AAA: 2 calls served, 3rd refused.
    for _ in range(2):
        status, _, _ = _post(base + "/j/AAA/inference", body)
        assert status == 200
    with pytest.raises(HTTPError) as excinfo:
        _post(base + "/j/AAA/inference", body)
    assert excinfo.value.code == 429

    # A DIFFERENT problem token (BBB) gets its own fresh budget — first call served.
    status, _, _ = _post(base + "/j/BBB/inference", body)
    assert status == 200

    # Upstream sees /inference (token stripped), never /j/<token>/inference.
    assert upstream.records and all(r["path"] == "/inference" for r in upstream.records)
    AGENT_BUDGET.reset()


def test_inference_budget_survives_interleaved_problem_tokens(
    relay_and_upstream, monkeypatch
) -> None:
    # Problems are scored concurrently, so their tokens arrive interleaved. Each
    # token must keep its own running count -- a different token in between must not
    # reset it. (The old single-key budget reset on every token change, which would
    # have let interleaving bypass the cap.)
    base, upstream = relay_and_upstream
    AGENT_BUDGET.reset()
    monkeypatch.setenv("KATA_RELAY_AGENT_CALL_BUDGET", "2")
    monkeypatch.setenv("KATA_RELAY_AGENT_INPUT_TOKEN_BUDGET", "0")
    monkeypatch.setenv("KATA_RELAY_AGENT_TOKEN_BUDGET", "0")
    body = json.dumps({"messages": [{"role": "user", "content": "x"}]}).encode()

    # Interleave AAA and BBB so each ends up with exactly 2 served calls.
    for token in ("AAA", "BBB", "AAA", "BBB"):
        status, _, _ = _post(base + f"/j/{token}/inference", body)
        assert status == 200

    # Both are now at their 2-call cap; the next call for each is refused.
    for token in ("AAA", "BBB"):
        with pytest.raises(HTTPError) as excinfo:
            _post(base + f"/j/{token}/inference", body)
        assert excinfo.value.code == 429
    AGENT_BUDGET.reset()


def test_upstream_check_reports_ok_when_reachable(relay_and_upstream) -> None:
    base, upstream = relay_and_upstream
    status, body, _ = _post(
        base + "/healthz/upstream",
        b"",
        _admin_headers({"x-inference-api-key": "k"}),
    )
    assert status == 200
    payload = json.loads(body)
    assert payload["ok"] is True
    assert payload["status"] == 200
    # The probe hits upstream /inference with a bounded max_tokens (not forced up to
    # the 32k inference ceiling), so it stays cheap while giving the reasoning model
    # room to return a usable reply.
    last = upstream.records[-1]
    assert last["path"] == "/inference"
    assert json.loads(last["body"])["max_tokens"] == 2000


def test_upstream_check_reports_failure_status(relay_and_upstream) -> None:
    base, upstream = relay_and_upstream
    upstream.force_status = 403  # simulate OpenRouter "Key limit exceeded"
    try:
        status, body, _ = _post(
            base + "/healthz/upstream",
            b"",
            _admin_headers({"x-inference-api-key": "k"}),
        )
    finally:
        upstream.force_status = None
    assert status == 200
    payload = json.loads(body)
    assert payload["ok"] is False
    assert payload["status"] == 403
    assert "limit" in str(payload.get("detail", "")).lower()


def test_upstream_check_requires_admin_token(relay_and_upstream) -> None:
    base, upstream = relay_and_upstream
    with pytest.raises(HTTPError) as excinfo:
        _post(base + "/healthz/upstream", b"", {"x-inference-api-key": "k"})
    assert excinfo.value.code == 403
    assert upstream.records == []


def test_upstream_check_with_akash_key_probes_akash_directly(
    relay_and_upstream, akash_upstream, monkeypatch
) -> None:
    base, bitsec_upstream = relay_and_upstream
    monkeypatch.delenv("KATA_RELAY_PINNED_MODEL", raising=False)

    status, body, _ = _post(
        base + "/healthz/upstream",
        b"",
        _admin_headers({"x-inference-api-key": "akml-test"}),
    )

    assert status == 200
    payload = json.loads(body)
    assert payload["ok"] is True
    assert payload["status"] == 200
    assert bitsec_upstream.records == []
    assert len(akash_upstream.records) == 1
    record = akash_upstream.records[0]
    assert record["path"] == "/v1/chat/completions"
    assert record["headers"].get("authorization") == "Bearer akml-test"
    assert "x-inference-api-key" not in record["headers"]
    outbound = json.loads(record["body"])
    assert outbound["model"] == DEFAULT_DIRECT_PINNED_MODEL
    assert outbound["max_tokens"] == 2000


def test_inference_model_is_pinned_before_reaching_upstream(relay_and_upstream) -> None:
    base, upstream = relay_and_upstream
    body = json.dumps(
        {
            "model": "anthropic/claude-opus",
            "messages": [],
            "temperature": 0.9,
            "seed": 123,
        }
    ).encode()

    status, _, resp_headers = _post(
        base + "/inference",
        body,
        {"Content-Type": "application/json", "x-inference-api-key": "sk-or-abc"},
    )

    assert status == 200
    assert resp_headers.get("x-upstream") == "yes"  # upstream response passed through
    assert len(upstream.records) == 1
    record = upstream.records[0]
    assert record["path"] == "/inference"
    outbound = json.loads(record["body"])
    assert outbound["model"] == "qwen/pinned-test"
    assert "temperature" not in outbound
    assert "seed" not in outbound
    # The agent's inference key rides through untouched to the real proxy.
    assert record["headers"].get("x-inference-api-key") == "sk-or-abc"


def test_akash_inference_uses_direct_endpoint_not_bitsec_proxy(
    relay_and_upstream, akash_upstream, monkeypatch
) -> None:
    base, bitsec_upstream = relay_and_upstream
    monkeypatch.delenv("KATA_RELAY_PINNED_MODEL", raising=False)
    body = json.dumps(
        {
            "model": "openrouter/other",
            "messages": [{"role": "user", "content": "hi"}],
            "temperature": 0.9,
            "max_tokens": 100,
        }
    ).encode()

    status, _, _ = _post(
        base + "/inference",
        body,
        {"Content-Type": "application/json", "x-inference-api-key": "akml-test"},
    )

    assert status == 200
    assert bitsec_upstream.records == []
    assert len(akash_upstream.records) == 1
    record = akash_upstream.records[0]
    assert record["path"] == "/v1/chat/completions"
    assert record["headers"].get("authorization") == "Bearer akml-test"
    assert "x-inference-api-key" not in record["headers"]
    outbound = json.loads(record["body"])
    assert outbound["model"] == DEFAULT_DIRECT_PINNED_MODEL
    assert outbound["max_tokens"] == 32000
    assert "temperature" not in outbound
    costs = _get_json(base + "/costs")
    assert costs["requests"] == 1
    assert costs["input_tokens"] == 100
    assert costs["output_tokens"] == 20


def test_configured_direct_provider_uses_generic_direct_path(
    relay_and_upstream, generic_direct_upstream, monkeypatch
) -> None:
    base, bitsec_upstream = relay_and_upstream
    monkeypatch.delenv("KATA_RELAY_PINNED_MODEL", raising=False)
    body = json.dumps(
        {
            "model": "ignored/model",
            "messages": [{"role": "user", "content": "hi"}],
            "temperature": 0.9,
            "max_tokens": 100,
        }
    ).encode()

    status, _, _ = _post(
        base + "/inference",
        body,
        {"Content-Type": "application/json", "x-inference-api-key": "foo-secret"},
    )

    assert status == 200
    assert bitsec_upstream.records == []
    assert len(generic_direct_upstream.records) == 1
    record = generic_direct_upstream.records[0]
    assert record["path"] == "/v1/chat/completions"
    assert record["headers"].get("x-api-key") == "Token foo-secret"
    assert "authorization" not in record["headers"]
    assert "x-inference-api-key" not in record["headers"]
    outbound = json.loads(record["body"])
    assert outbound["model"] == "Provider/Model"
    assert outbound["max_tokens"] == 32000
    assert "temperature" not in outbound


def test_inference_query_string_is_still_pinned(relay_and_upstream) -> None:
    base, upstream = relay_and_upstream
    body = json.dumps({"model": "expensive/model", "messages": []}).encode()

    _post(base + "/inference?trace=1", body, {"Content-Type": "application/json"})

    record = upstream.records[0]
    assert record["path"] == "/inference?trace=1"
    assert json.loads(record["body"])["model"] == "qwen/pinned-test"


def test_non_inference_upstream_paths_are_blocked(relay_and_upstream) -> None:
    base, upstream = relay_and_upstream
    body = json.dumps({"model": "anthropic/claude-opus"}).encode()

    with pytest.raises(HTTPError) as excinfo:
        _post(
            base + "/metrics/job-runs/x/summary/reset",
            body,
            {"Content-Type": "application/json"},
        )

    assert excinfo.value.code == 404
    assert upstream.records == []


def test_health_is_answered_locally_without_touching_upstream(relay_and_upstream) -> None:
    base, upstream = relay_and_upstream
    with urlopen(base + "/healthz", timeout=10) as response:
        payload = json.loads(response.read())

    assert payload["status"] == "ok"
    assert payload["pinned_model"] == "qwen/pinned-test"
    assert upstream.records == []


def test_upstream_http_error_is_passed_through(relay_and_upstream) -> None:
    base, _ = relay_and_upstream
    body = json.dumps({"messages": []}).encode()

    with pytest.raises(HTTPError) as excinfo:
        _post(
            base + "/inference",
            body,
            {"Content-Type": "application/json", "X-Upstream-Boom": "yes"},
        )

    assert excinfo.value.code == 502


def test_unreachable_upstream_returns_502(monkeypatch) -> None:
    monkeypatch.setenv("KATA_RELAY_UPSTREAM", "http://127.0.0.1:9")  # nothing listening
    monkeypatch.setenv("KATA_RELAY_PINNED_MODEL", "qwen/pinned-test")
    relay = build_server("127.0.0.1", 0)
    threading.Thread(target=relay.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{relay.server_address[1]}"
    try:
        body = json.dumps({"model": "x", "messages": []}).encode()
        with pytest.raises(HTTPError) as excinfo:
            _post(base + "/inference", body, {"Content-Type": "application/json"})
        assert excinfo.value.code == 502
    finally:
        relay.shutdown()


# --- cost accounting --------------------------------------------------------


def test_extract_usage_reads_openai_usage_block() -> None:
    body = json.dumps(
        {
            "usage": {
                "prompt_tokens": 1200,
                "completion_tokens": 340,
                "prompt_tokens_details": {"cached_tokens": 200},
            }
        }
    ).encode()
    assert extract_usage(body) == (1200, 340, 200)


def test_extract_usage_falls_back_to_flattened_fields() -> None:
    body = json.dumps({"input_tokens": 50, "output_tokens": 9, "cached_tokens": 3}).encode()
    assert extract_usage(body) == (50, 9, 3)


def test_extract_usage_returns_zeros_for_unreadable_body() -> None:
    assert extract_usage(b"not json") == (0, 0, 0)
    assert extract_usage(json.dumps([1, 2]).encode()) == (0, 0, 0)


def test_cost_meter_accumulates_and_prices() -> None:
    meter = CostMeter()
    meter.add(1_000_000, 500_000, 0)
    meter.add(1_000_000, 500_000, 0)
    snap = meter.snapshot(0.14, 1.00)
    assert snap["requests"] == 2
    assert snap["input_tokens"] == 2_000_000
    assert snap["output_tokens"] == 1_000_000
    assert snap["usd_input"] == 0.28  # 2M * $0.14/M
    assert snap["usd_output"] == 1.00  # 1M * $1.00/M
    assert snap["usd_total"] == 1.28


def test_cost_meter_reset_zeroes_totals() -> None:
    meter = CostMeter()
    meter.add(10, 10, 0)
    meter.reset()
    snap = meter.snapshot(1.0, 1.0)
    assert snap["requests"] == 0
    assert snap["input_tokens"] == 0
    assert snap["usd_total"] == 0.0


def _get_json(url: str) -> dict:
    with urlopen(url, timeout=10) as response:
        return json.loads(response.read())


def test_costs_endpoint_reports_measured_inference_spend(relay_and_upstream) -> None:
    base, upstream = relay_and_upstream

    # Two inference calls; upstream reports 100 in / 20 out tokens each.
    for _ in range(2):
        _post(base + "/inference", json.dumps({"messages": []}).encode(),
              {"Content-Type": "application/json"})

    costs = _get_json(base + "/costs")
    assert costs["requests"] == 2
    assert costs["input_tokens"] == 200
    assert costs["output_tokens"] == 40
    assert costs["model"] == "qwen/pinned-test"
    # Fixture prices: $2/1M in, $5/1M out.
    assert costs["usd_input"] == round(200 / 1_000_000 * 2, 6)
    assert costs["usd_output"] == round(40 / 1_000_000 * 5, 6)
    assert costs["usd_total"] == round(costs["usd_input"] + costs["usd_output"], 6)
    # /costs is answered locally, never forwarded upstream.
    assert all(r["path"] != "/costs" for r in upstream.records)


def test_costs_reset_zeroes_the_running_total(relay_and_upstream) -> None:
    base, _ = relay_and_upstream
    _post(base + "/inference", json.dumps({"messages": []}).encode(),
          {"Content-Type": "application/json"})
    assert _get_json(base + "/costs")["input_tokens"] == 100

    _post(base + "/costs/reset", b"", _admin_headers({"Content-Type": "application/json"}))

    after = _get_json(base + "/costs")
    assert after["requests"] == 0
    assert after["input_tokens"] == 0
    assert after["usd_total"] == 0.0


def test_costs_reset_requires_admin_token(relay_and_upstream) -> None:
    base, _ = relay_and_upstream
    _post(base + "/inference", json.dumps({"messages": []}).encode(),
          {"Content-Type": "application/json"})
    assert _get_json(base + "/costs")["requests"] == 1

    with pytest.raises(HTTPError) as excinfo:
        _post(base + "/costs/reset", b"", {"Content-Type": "application/json"})

    assert excinfo.value.code == 403
    assert _get_json(base + "/costs")["requests"] == 1


def test_scoring_style_traffic_is_not_metered(relay_and_upstream) -> None:
    base, _ = relay_and_upstream
    # Non-/inference calls are blocked and must not count toward inference cost.
    with pytest.raises(HTTPError) as excinfo:
        _post(
            base + "/metrics/job-runs/x/summary/reset",
            b"{}",
            {"Content-Type": "application/json"},
        )
    assert excinfo.value.code == 404
    assert _get_json(base + "/costs")["requests"] == 0
