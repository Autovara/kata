"""Phase 3a tests: the subnet-agnostic round orchestrator.

Two layers:
- A trivial numeric stub plugin exercises the control flow (ranking, king logic,
  candidate-only) fast and in isolation.
- The real SN60 plugin proves the generic orchestrator produces the *same* winner and
  ranking as the existing ``run_sn60_round`` (parity), so Phase 3b's swap is safe.
"""

from __future__ import annotations

import json
from pathlib import Path

from kata.core.round import run_plugin_round
from kata.packages.plugin import EnvSpec, ScoreCard, ScoringProfile, SubnetPlugin
from kata.packages.sn60 import Sn60BitsecPlugin
from kata.validator_system import run_sn60_round


class _NumPlugin(SubnetPlugin):
    """Stub: the agent_path is a string float that is its own score."""

    evaluator_id = "num"
    pack = "num__p"
    mode = "miner"
    scoring_profile = ScoringProfile.DETERMINISTIC
    validator_identity = "num-v"

    def environment_spec(self) -> EnvSpec:
        return EnvSpec()

    def sample_problems(self, *, seed, config):
        return {"seed": seed}

    def benchmark_identity(self, problems) -> str:
        return "bench-num"

    def run_candidate(self, *, agent_path, problems, context):
        return {"score": float(agent_path)}

    def score(self, raw, problems) -> ScoreCard:
        return ScoreCard(comparable=raw["score"], passed=True, payload=raw["score"])

    def compare(self, a: ScoreCard, b: ScoreCard) -> int:
        return (a.comparable > b.comparable) - (a.comparable < b.comparable)

    def beats_king(self, candidate: ScoreCard, king: ScoreCard | None) -> bool:
        return king is None or candidate.comparable > king.comparable


def test_orchestrator_ranks_and_picks_winner_over_king() -> None:
    outcome = run_plugin_round(
        _NumPlugin(),
        king_agent_path="0.25",
        candidates=[("a", "0.0"), ("b", "0.5"), ("c", "0.75")],
        config={},
        output_root="/unused",
        seed="round-1",
    )
    assert [v.label for v in outcome.ranked] == ["c", "b", "a"]
    assert outcome.king is not None and outcome.king.card.comparable == 0.25
    assert outcome.winner is not None and outcome.winner.label == "c"
    assert outcome.benchmark_identity == "bench-num"
    assert outcome.scoring_profile is ScoringProfile.DETERMINISTIC


def test_orchestrator_no_winner_when_king_unbeaten() -> None:
    outcome = run_plugin_round(
        _NumPlugin(),
        king_agent_path="0.9",
        candidates=[("a", "0.1"), ("b", "0.5")],
        config={},
        output_root="/unused",
        seed="round-1",
    )
    assert outcome.winner is None
    assert [v.label for v in outcome.ranked] == ["b", "a"]


def test_plugin_run_round_default_delegates_to_orchestrator() -> None:
    # The interface's default run_round drives the generic orchestrator.
    outcome = _NumPlugin().run_round(
        king_agent_path="0.25",
        candidates=[("a", "0.1"), ("b", "0.9")],
        config={},
        output_root="/unused",
        run_id="r",
    )
    assert outcome.king is not None and outcome.king.card.comparable == 0.25
    assert outcome.winner is not None and outcome.winner.label == "b"


def test_orchestrator_candidate_only_skips_king() -> None:
    outcome = run_plugin_round(
        _NumPlugin(),
        king_agent_path="0.9",  # ignored because score_king=False
        candidates=[("a", "0.1"), ("b", "0.5")],
        config={},
        output_root="/unused",
        seed="round-1",
        score_king=False,
    )
    assert outcome.king is None
    # With no king, beats_king is True for all -> winner is the top-ranked candidate.
    assert outcome.winner is not None and outcome.winner.label == "b"


# --- SN60 parity -----------------------------------------------------------------


def _write_detection_bundle(root: Path, detection: float) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "agent.py").write_text(
        f"# detection={detection}\n"
        "def agent_main(project_dir=None, inference_api=None):\n"
        "    return {'vulnerabilities': []}\n",
        encoding="utf-8",
    )


def _write_benchmark(root: Path) -> Path:
    benchmark_path = root / "validator" / "curated-highs-only-2025-08-08.json"
    benchmark_path.parent.mkdir(parents=True, exist_ok=True)
    benchmark_path.write_text(
        json.dumps([{"project_id": "project-alpha", "vulnerabilities": [{"title": "expected"}]}])
        + "\n",
        encoding="utf-8",
    )
    return benchmark_path


def _detection_hooks():
    def execute(context) -> dict[str, object]:
        source = (Path(context.bundle_root) / "agent.py").read_text(encoding="utf-8")
        detection = 0.0
        for line in source.splitlines():
            if "# detection=" in line:
                detection = float(line.split("# detection=")[1].strip())
        return {
            "success": True,
            "report": {
                "project": context.project_key,
                "vulnerabilities": [{"title": "v"}],
                "detection": detection,
            },
        }

    def evaluate(_context, report_payload: dict[str, object]) -> dict[str, object]:
        detection = report_payload["report"]["detection"]
        return {
            "status": "success",
            "result": {
                "result": "PASS" if detection >= 1.0 else "FAIL",
                "detection_rate": detection,
                "true_positives": int(round(detection * 4)),
                "total_expected": 4,
                "total_found": 4,
                "precision": 1.0,
                "f1_score": detection,
            },
        }

    return execute, evaluate


def test_sn60_orchestrator_matches_run_sn60_round(tmp_path: Path) -> None:
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = _write_benchmark(sandbox_root)
    king_root = tmp_path / "king"
    _write_detection_bundle(king_root, 0.25)
    candidate_specs = [("cand-a", 0.0), ("cand-b", 0.5), ("cand-c", 0.75)]
    candidate_paths = {}
    for name, detection in candidate_specs:
        path = tmp_path / name
        _write_detection_bundle(path, detection)
        candidate_paths[name] = str(path)

    execute, evaluate = _detection_hooks()

    # Legacy path.
    legacy = run_sn60_round(
        king_artifact_path=str(king_root),
        candidates=[(name, candidate_paths[name]) for name, _ in candidate_specs],
        project_keys=["project-alpha"],
        output_root=str(tmp_path / "legacy-runs"),
        replicas_per_project=1,
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit="commit-parity",
        king_scoreboard_path=str(tmp_path / "king_scoreboard.json"),
        execution_hook=execute,
        evaluation_hook=evaluate,
    )

    # Generic orchestrator path, same inputs.
    plugin = Sn60BitsecPlugin(execution_hook=execute, evaluation_hook=evaluate)
    outcome = run_plugin_round(
        plugin,
        king_agent_path=str(king_root),
        candidates=[(name, candidate_paths[name]) for name, _ in candidate_specs],
        config={
            "sandbox_root": str(sandbox_root),
            "benchmark_file": str(benchmark_path),
            "sandbox_commit": "commit-parity",
            "project_keys": ["project-alpha"],
            "replicas_per_project": 1,
        },
        output_root=str(tmp_path / "generic-runs"),
        seed="round-parity",
    )

    # Same winner.
    assert outcome.winner is not None
    assert outcome.winner.label == legacy.winner_submission_id == "cand-c"
    # Same ranking order.
    assert [v.label for v in outcome.ranked] == [e.submission_id for e in legacy.entries]
    # Same per-candidate true positives (the signal that decides the ranking here).
    legacy_tp = {e.submission_id: e.candidate.true_positives for e in legacy.entries}
    generic_tp = {v.label: v.card.metrics["true_positives"] for v in outcome.ranked}
    assert generic_tp == legacy_tp
    # Same king score.
    assert outcome.king is not None
    assert outcome.king.card.metrics["true_positives"] == legacy.king.true_positives
    # beats_king parity: exactly cand-c and cand-b beat the king.
    beats = {v.label: plugin.beats_king(v.card, outcome.king.card) for v in outcome.ranked}
    assert beats == {"cand-c": True, "cand-b": True, "cand-a": False}
