from __future__ import annotations

from pathlib import Path

from promptforge.challenge import ChallengePoolSummary, evaluate_promotion
from promptforge.scoring import score_variant_run


def write_file(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    if path.name == "checks.sh":
        path.chmod(0o755)


def create_eval_pack(root: Path) -> None:
    write_file(root / "task.md", "# Eval Task\n")
    write_file(root / "repo_ref.txt", "https://github.com/example/repo.git@main\n")
    write_file(root / "checks.sh", "#!/usr/bin/env bash\nset -euo pipefail\nexit 0\n")
    write_file(root / "rubric.md", "# Rubric\n")
    write_file(root / "allowed_paths.txt", "src/\n")
    write_file(root / "forbidden_paths.txt", "eval/\n")


def test_score_variant_run_uses_partial_score_file(tmp_path: Path) -> None:
    repo_snapshot = tmp_path / "repo"
    eval_pack = tmp_path / "eval"
    workspace = tmp_path / "workspace"
    repo_snapshot.mkdir()
    eval_pack.mkdir()
    workspace.mkdir()
    create_eval_pack(eval_pack)
    (workspace / "src").mkdir()
    write_file(workspace / "src" / "answer.txt", "ok\n")
    score_file = tmp_path / "score.txt"
    write_file(score_file, "0.75\n")

    result = score_variant_run(
        repo_snapshot=repo_snapshot,
        eval_pack_root=eval_pack,
        workspace=workspace,
        agent_exit_code=0,
        checks_exit_code=1,
        score_file=score_file,
    )

    assert result.verifier_score == 0.75
    assert result.quality_score == 0.75
    assert result.validity_passed
    assert result.score_source == "score-file"


def test_score_variant_run_zeroes_quality_on_path_violation(tmp_path: Path) -> None:
    repo_snapshot = tmp_path / "repo"
    eval_pack = tmp_path / "eval"
    workspace = tmp_path / "workspace"
    repo_snapshot.mkdir()
    eval_pack.mkdir()
    workspace.mkdir()
    create_eval_pack(eval_pack)
    write_file(workspace / "forbidden.txt", "bad\n")
    score_file = tmp_path / "score.txt"
    write_file(score_file, "1.0\n")

    result = score_variant_run(
        repo_snapshot=repo_snapshot,
        eval_pack_root=eval_pack,
        workspace=workspace,
        agent_exit_code=0,
        checks_exit_code=0,
        score_file=score_file,
    )

    assert result.verifier_score == 1.0
    assert result.quality_score == 0.0
    assert not result.validity_passed
    assert result.path_policy_violations == ["forbidden.txt"]


def test_evaluate_promotion_requires_margin() -> None:
    primary = ChallengePoolSummary(
        task_ids=["task-a"],
        eval_run_summary="run_summary.json",
        total_task_weight=1.0,
        variant_successes={"frontier": 1, "candidate": 1, "baseline": 0},
        variant_invalid_tasks={"frontier": 0, "candidate": 0, "baseline": 0},
        variant_scores={"frontier": 80.0, "candidate": 82.5, "baseline": 0.0},
        candidate_beats_frontier=True,
        candidate_score_delta=2.5,
    )

    promotion_ready, reason = evaluate_promotion(
        primary,
        None,
        promotion_margin_points=3.0,
    )

    assert not promotion_ready
    assert reason == "candidate improved the primary score but did not clear the promotion margin"


def test_evaluate_promotion_uses_configured_margin() -> None:
    primary = ChallengePoolSummary(
        task_ids=["task-a"],
        eval_run_summary="run_summary.json",
        total_task_weight=1.0,
        variant_successes={"frontier": 1, "candidate": 1, "baseline": 0},
        variant_invalid_tasks={"frontier": 0, "candidate": 0, "baseline": 0},
        variant_scores={"frontier": 80.0, "candidate": 82.5, "baseline": 0.0},
        candidate_beats_frontier=True,
        candidate_score_delta=2.5,
    )

    promotion_ready, reason = evaluate_promotion(
        primary,
        None,
        promotion_margin_points=2.0,
    )

    assert promotion_ready
    assert reason == "candidate cleared the primary score margin"
