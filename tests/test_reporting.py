from __future__ import annotations

from pathlib import Path

from kata.reporting import compare_variants, diff_paths, summarize_task_outcome


def test_diff_paths_reports_deleted_file_path(tmp_path: Path) -> None:
    source = tmp_path / "source"
    target = tmp_path / "target"
    source.mkdir()
    target.mkdir()
    (source / "forbidden.txt").write_text("x\n", encoding="utf-8")

    assert diff_paths(source, target) == ["forbidden.txt"]


def test_diff_paths_reports_added_file_path(tmp_path: Path) -> None:
    source = tmp_path / "source"
    target = tmp_path / "target"
    source.mkdir()
    target.mkdir()
    (target / "allowed.txt").write_text("x\n", encoding="utf-8")

    assert diff_paths(source, target) == ["allowed.txt"]


def test_compare_variants_rejects_path_policy_violating_win() -> None:
    baseline = {
        "agent_ok": True,
        "task_solved": False,
        "path_policy_passed": True,
        "success_score": 0,
    }
    generated = {
        "agent_ok": True,
        "task_solved": True,
        "path_policy_passed": False,
        "success_score": 0,
    }

    assert compare_variants(baseline, generated) == "Tie"


def test_compare_variants_prefers_valid_task_completion() -> None:
    baseline = {
        "agent_ok": True,
        "task_solved": False,
        "path_policy_passed": True,
        "success_score": 0,
    }
    generated = {
        "agent_ok": True,
        "task_solved": True,
        "path_policy_passed": True,
        "success_score": 1,
    }

    assert compare_variants(baseline, generated) == "Kata win"


def test_compare_variants_marks_double_invalid_runs_correctly() -> None:
    baseline = {
        "agent_ok": True,
        "validity_passed": False,
        "quality_score": 0.0,
    }
    generated = {
        "agent_ok": True,
        "validity_passed": False,
        "quality_score": 0.0,
    }

    assert compare_variants(baseline, generated) == "Invalid run"


def test_summarize_task_outcome_handles_multi_variant_runs() -> None:
    variants = {
        "baseline": {"quality_score": 0.0},
        "frontier": {"quality_score": 0.5},
        "candidate": {"quality_score": 1.0},
    }

    assert (
        summarize_task_outcome(variants, ["baseline", "frontier", "candidate"])
        == "best variant: candidate"
    )
