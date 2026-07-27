"""Contestant execution order is the plugin's to choose, and can never change who wins.

Contestants run one after another on a shared host, so whichever goes first meets a different
machine than whichever goes second. With a fixed king-then-challenger order that difference lands on
the same side every round, and any signal touching wall clock inherits a bias no averaging removes.

Two properties matter, and they pull against each other, so both are tested here:

* the plugin's order is actually USED — otherwise the hook is decorative;
* the RESULT is independent of it — otherwise permuting execution would decide crowns, which is
  strictly worse than the bias it was meant to remove.
"""

from __future__ import annotations

from pathlib import Path

from kata.plugins.contract import EnvSpec, ScoreCard, ScoringProfile, SubnetPlugin


class _OrderRecordingPlugin(SubnetPlugin):
    """Scores by directory name, and records the order in which it was actually run."""

    evaluator_id = "order-test"
    pack = "order__test"
    mode = "miner"
    scoring_profile = ScoringProfile.DETERMINISTIC
    validator_identity = "order-test-v1"

    def __init__(self, order=None):
        self.executed: list[str] = []
        self._order = order

    def environment_spec(self) -> EnvSpec:
        return EnvSpec()

    def sample_problems(self, *, seed: str, config: dict) -> dict:
        return {"seed": seed}

    def benchmark_identity(self, problems: dict) -> str:
        return "order-benchmark"

    def execution_order(self, *, problems, variants):
        return self._order(variants) if self._order is not None else tuple(variants)

    def run_candidate(self, *, agent_path: str, problems: dict, context) -> float:
        self.executed.append(context.label)
        return float(Path(agent_path).name)

    def score(self, raw: float, problems: dict) -> ScoreCard:
        return ScoreCard(comparable=raw, passed=True, beats_threshold=0.0)

    def compare(self, a: ScoreCard, b: ScoreCard) -> int:
        return (a.comparable > b.comparable) - (a.comparable < b.comparable)

    def beats_king(self, candidate: ScoreCard, king: ScoreCard | None) -> bool:
        return king is None or candidate.comparable > king.comparable

    def hash_bundle(self, path: Path) -> str:
        return f"hash:{path.name}"


def _dirs(tmp_path: Path, *names: str) -> list[Path]:
    made = []
    for name in names:
        path = tmp_path / name
        path.mkdir(parents=True)
        made.append(path)
    return made


def _run(plugin, tmp_path, king="0.4", candidates=(("pr-9", "0.8"),)):
    king_dir, *candidate_dirs = _dirs(tmp_path, king, *[value for _label, value in candidates])
    return plugin.run_challenge(
        king_agent_path=str(king_dir),
        candidates=[(label, str(path)) for (label, _v), path in zip(candidates, candidate_dirs)],
        config={},
        output_root=str(tmp_path / "runs"),
        run_id="order-run",
    )


def test_the_default_order_is_king_first(tmp_path: Path) -> None:
    """A plugin that does not override the hook is completely unaffected."""
    plugin = _OrderRecordingPlugin()
    _run(plugin, tmp_path)
    assert plugin.executed == ["king", "pr-9"]


def test_a_plugin_can_put_the_challenger_first(tmp_path: Path) -> None:
    plugin = _OrderRecordingPlugin(order=lambda variants: tuple(reversed(variants)))
    _run(plugin, tmp_path)
    assert plugin.executed == ["pr-9", "king"]


def test_the_order_does_not_change_the_result(tmp_path: Path) -> None:
    """The whole point: permuting execution inconveniences a contestant, it does not rank one."""
    forward = _OrderRecordingPlugin()
    reversed_ = _OrderRecordingPlugin(order=lambda variants: tuple(reversed(variants)))
    first = _run(forward, tmp_path / "a")
    second = _run(reversed_, tmp_path / "b")

    assert forward.executed != reversed_.executed          # they really ran differently...
    assert first.outcome.winner.label == second.outcome.winner.label
    assert first.outcome.king.card.comparable == second.outcome.king.card.comparable
    assert ([v.label for v in first.outcome.ranked]
            == [v.label for v in second.outcome.ranked])


def test_ranked_order_follows_the_comparator_not_the_execution_order(tmp_path: Path) -> None:
    plugin = _OrderRecordingPlugin(order=lambda variants: tuple(sorted(variants)))
    result = _run(plugin, tmp_path, candidates=(("pr-1", "0.9"), ("pr-2", "0.5")))
    # Executed alphabetically...
    assert plugin.executed == ["king", "pr-1", "pr-2"]
    # ...but ranked best-first by score, and 0.9 beats 0.5.
    assert [variant.label for variant in result.outcome.ranked] == ["pr-1", "pr-2"]


def test_a_dropped_label_falls_back_instead_of_skipping_a_contestant(tmp_path: Path) -> None:
    """A plugin that omits a label must not cause a contestant to go unrun and still be ranked."""
    plugin = _OrderRecordingPlugin(order=lambda variants: (variants[0],))
    result = _run(plugin, tmp_path)
    assert sorted(plugin.executed) == ["king", "pr-9"]
    assert result.outcome.winner is not None


def test_a_duplicated_label_falls_back_instead_of_running_twice(tmp_path: Path) -> None:
    """Executing a submission twice would bill it twice — on a metered lane, real money."""
    plugin = _OrderRecordingPlugin(order=lambda variants: (variants[0], variants[0]))
    _run(plugin, tmp_path)
    assert plugin.executed == ["king", "pr-9"]


def test_an_invented_label_falls_back(tmp_path: Path) -> None:
    plugin = _OrderRecordingPlugin(order=lambda variants: ("king", "not-a-contestant"))
    _run(plugin, tmp_path)
    assert plugin.executed == ["king", "pr-9"]


def test_a_raising_hook_never_fails_the_challenge(tmp_path: Path) -> None:
    """An ordering PREFERENCE must not be able to take a lane down."""
    def _boom(_variants):
        raise RuntimeError("ordering backend exploded")

    plugin = _OrderRecordingPlugin(order=_boom)
    result = _run(plugin, tmp_path)
    assert plugin.executed == ["king", "pr-9"]
    assert result.outcome.winner is not None


def test_a_lazy_king_challenge_orders_only_the_candidates(tmp_path: Path) -> None:
    """With no king scored there is nothing to alternate against, and that must not crash.

    Driven through ``run_plugin_challenge`` because the lazy-king optimization is a core-level
    argument, not part of the plugin's own ``run_challenge`` surface.
    """
    from kata.core.challenge import run_plugin_challenge

    plugin = _OrderRecordingPlugin(order=lambda variants: tuple(reversed(variants)))
    king_dir, one, two = _dirs(tmp_path, "0.4", "0.8", "0.6")
    run_plugin_challenge(
        plugin,
        king_agent_path=str(king_dir),
        candidates=[("pr-1", str(one)), ("pr-2", str(two))],
        config={},
        output_root=str(tmp_path / "runs"),
        seed="lazy-seed",
        score_king=False,
    )
    assert plugin.executed == ["pr-2", "pr-1"]
    assert "king" not in plugin.executed
