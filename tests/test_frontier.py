from __future__ import annotations

import json
from pathlib import Path

from promptforge.challenge import ChallengePoolSummary, promotion_reason
from promptforge.frontier import (
    FrontierManifest,
    FrontierModeConfig,
    render_frontier_json,
    render_frontier_manifest,
)


def test_render_frontier_manifest_includes_primary_and_holdout_tasks(tmp_path: Path) -> None:
    manifest = FrontierManifest(
        schema_version=1,
        repo_ref="https://github.com/example/repo.git",
        eval_pack=str(tmp_path),
        updated_at="2026-06-28T00:00:00+00:00",
        modes={
            "contributor": FrontierModeConfig(
                baseline_prompt="/tmp/baseline.md",
                frontier_prompt="/tmp/frontier.md",
                primary_tasks=["task-a", "task-b"],
                holdout_tasks=["task-c"],
                promotion_margin_points=4.5,
                evaluator_version="2026-06-29.v1",
                baseline_prompt_hash="a" * 64,
                frontier_prompt_hash="b" * 64,
                primary_pool_fingerprint="c" * 64,
                holdout_pool_fingerprint="d" * 64,
                frontier_updated_at="2026-06-28T01:00:00+00:00",
                frontier_source="run-123",
            )
        },
    )

    rendered = render_frontier_manifest(manifest, "contributor")

    assert "Primary tasks: task-a, task-b" in rendered
    assert "Holdout tasks: task-c" in rendered
    assert "Frontier source: run-123" in rendered
    assert "Evaluator version: 2026-06-29.v1" in rendered
    assert "Promotion margin: 4.5 points" in rendered
    assert "Baseline prompt hash: aaaaaaaaaaaa" in rendered
    assert "Primary pool fingerprint: cccccccccccc" in rendered


def test_promotion_reason_explains_holdout_failure() -> None:
    primary = ChallengePoolSummary(
        task_ids=["task-a"],
        eval_run_summary="run_summary.json",
        total_task_weight=1.0,
        variant_successes={"frontier": 0, "candidate": 1, "baseline": 0},
        variant_invalid_tasks={"frontier": 0, "candidate": 0, "baseline": 0},
        variant_scores={"frontier": 40.0, "candidate": 45.0, "baseline": 0.0},
        candidate_beats_frontier=True,
        candidate_score_delta=5.0,
    )
    holdout = ChallengePoolSummary(
        task_ids=["task-b"],
        eval_run_summary="run_summary.json",
        total_task_weight=1.0,
        variant_successes={"frontier": 1, "candidate": 1, "baseline": 0},
        variant_invalid_tasks={"frontier": 0, "candidate": 0, "baseline": 0},
        variant_scores={"frontier": 70.0, "candidate": 68.0, "baseline": 0.0},
        candidate_beats_frontier=False,
        candidate_score_delta=-2.0,
    )

    assert (
        promotion_reason(primary, holdout)
        == "candidate cleared the primary score margin but regressed on holdout"
    )


def test_render_frontier_json_includes_mode_configuration(tmp_path: Path) -> None:
    manifest = FrontierManifest(
        schema_version=1,
        repo_ref="https://github.com/example/repo.git",
        eval_pack=str(tmp_path),
        updated_at="2026-06-28T00:00:00+00:00",
        modes={
            "contributor": FrontierModeConfig(
                baseline_prompt="/tmp/baseline.md",
                frontier_prompt="/tmp/frontier.md",
                primary_tasks=["task-a"],
                holdout_tasks=[],
                promotion_margin_points=3.0,
            )
        },
    )

    payload = json.loads(render_frontier_json(manifest))

    assert payload["repo_ref"] == "https://github.com/example/repo.git"
    assert payload["modes"]["contributor"]["promotion_margin_points"] == 3.0
