"""Phase 1 tests: the SubnetPlugin contract and registry.

Nothing in the core uses these yet; these tests just pin the plugin interface and the
registry semantics that Phases 2+ build on.
"""

from __future__ import annotations

from typing import Any

import pytest

from kata.packages import (
    EnvSpec,
    ProgressUpdate,
    RunContext,
    ScoreCard,
    ScoringProfile,
    SubnetPlugin,
    all_plugins,
    clear_registry,
    get_plugin,
    get_plugin_or_none,
    register_plugin,
)


class _StubPlugin(SubnetPlugin):
    evaluator_id = "stub_subnet"
    pack = "stub__pack"
    mode = "miner"
    scoring_profile = ScoringProfile.DETERMINISTIC
    validator_identity = "stub-validator-v1"

    def environment_spec(self) -> EnvSpec:
        return EnvSpec(network="relay_only")

    def sample_problems(self, *, seed: str, config: dict[str, Any]):
        return [f"problem-{seed}"]

    def benchmark_identity(self, problems) -> str:
        return "bench-1"

    def run_candidate(self, *, agent_path: str, problems, context: RunContext):
        return {"agent": agent_path, "problems": problems}

    def score(self, raw, problems) -> ScoreCard:
        return ScoreCard(comparable=1.0, passed=True, metrics={"x": 1})

    def compare(self, a: ScoreCard, b: ScoreCard) -> int:
        return (a.comparable > b.comparable) - (a.comparable < b.comparable)

    def beats_king(self, candidate: ScoreCard, king: ScoreCard | None) -> bool:
        return king is None or candidate.comparable > king.comparable


@pytest.fixture(autouse=True)
def _isolate_registry():
    clear_registry()
    yield
    clear_registry()


def test_register_and_get_plugin() -> None:
    plugin = _StubPlugin()
    register_plugin(plugin)
    assert get_plugin("stub_subnet") is plugin
    assert get_plugin_or_none("stub_subnet") is plugin
    assert all_plugins() == (plugin,)


def test_register_is_idempotent_for_same_instance() -> None:
    plugin = _StubPlugin()
    register_plugin(plugin)
    register_plugin(plugin)  # no error
    assert all_plugins() == (plugin,)


def test_register_rejects_conflicting_id() -> None:
    register_plugin(_StubPlugin())
    with pytest.raises(ValueError, match="already registered"):
        register_plugin(_StubPlugin())  # different instance, same evaluator_id


def test_register_rejects_missing_attribute() -> None:
    class _Broken(_StubPlugin):
        evaluator_id = ""  # missing/blank required attribute

    with pytest.raises(ValueError, match="missing required attribute 'evaluator_id'"):
        register_plugin(_Broken())


def test_get_missing_plugin_raises() -> None:
    with pytest.raises(KeyError, match="No subnet plugin registered"):
        get_plugin("does_not_exist")
    assert get_plugin_or_none("does_not_exist") is None


def test_incomplete_plugin_cannot_be_instantiated() -> None:
    class _Partial(SubnetPlugin):
        evaluator_id = "partial"
        pack = "p"
        mode = "miner"
        scoring_profile = ScoringProfile.DETERMINISTIC
        validator_identity = "v"
        # abstract methods intentionally not implemented

    with pytest.raises(TypeError):
        _Partial()  # ABC refuses instantiation with unimplemented abstract methods


def test_value_object_defaults() -> None:
    env = EnvSpec()
    assert env.network == "relay_only"
    assert env.allowed_hosts == () and env.required_secrets == ()
    assert env.pinned_model is None and env.resources == {}

    card = ScoreCard(comparable=0.5, passed=True)
    assert card.beats_threshold == 0.0 and card.metrics == {}

    update = ProgressUpdate(variant="king", done=1, total=7, state="scoring")
    assert update.metrics == {}

    assert ScoringProfile.DETERMINISTIC.value == "deterministic"
    assert ScoringProfile.NOISY.value == "noisy"


def test_default_static_screen_is_noop() -> None:
    assert _StubPlugin().static_screen("/some/path") is None
