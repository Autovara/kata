from __future__ import annotations

import json
from pathlib import Path

from kata.frontier import (
    FRONTIER_SCHEMA_VERSION,
    FrontierManifest,
    FrontierModeConfig,
    write_frontier_manifest,
)
from kata.provenance import sha256_text
from kata.submissions import (
    PR_ACTION_CLOSE_INVALID,
    PR_ACTION_CLOSE_LOSING,
    PR_ACTION_EVALUATE,
    PR_ACTION_MERGE,
    PR_ACTION_RERUN_STALE,
    decide_submission_action,
    init_submission,
    inspect_pull_request,
    validate_submission,
    verify_submission_result,
)

VALID_AGENT = (
    "def solve(repo_path, issue, model, api_base, api_key):\n"
    "    return {\"success\": True, \"diff\": \"\"}\n"
)


def write_registry(
    root: Path,
    *,
    active_repo_packs: list[str] | None = None,
    default_repo_pack: str | None = None,
) -> None:
    root.mkdir(parents=True, exist_ok=True)
    payload: dict[str, object] = {
        "schema_version": 1,
        "registry_name": "test-registry",
        "benchmarks_dir": "benchmarks",
    }
    if active_repo_packs is not None:
        payload["active_repo_packs"] = active_repo_packs
    if default_repo_pack is not None:
        payload["default_repo_pack"] = default_repo_pack
    (root / "kata-benchmark-registry.json").write_text(
        json.dumps(payload) + "\n",
        encoding="utf-8",
    )
    (root / "benchmarks").mkdir(parents=True, exist_ok=True)


def write_frontier_pack(registry_root: Path, repo_pack: str, repo_ref: str) -> Path:
    pack_root = registry_root / "benchmarks" / repo_pack
    prompt_root = pack_root / "prompts" / "contributor"
    prompt_root.mkdir(parents=True, exist_ok=True)
    baseline_text = "# baseline\n"
    frontier_text = "# frontier\n"
    (prompt_root / "baseline.md").write_text(baseline_text, encoding="utf-8")
    (prompt_root / "frontier.md").write_text(frontier_text, encoding="utf-8")
    manifest = FrontierManifest(
        schema_version=FRONTIER_SCHEMA_VERSION,
        repo_ref=repo_ref,
        eval_pack=str(pack_root),
        updated_at="2026-06-29T00:00:00+00:00",
        modes={
            "contributor": FrontierModeConfig(
                baseline_prompt=str((prompt_root / "baseline.md").resolve()),
                frontier_prompt=str((prompt_root / "frontier.md").resolve()),
                primary_tasks=["task-a"],
                holdout_tasks=[],
                evaluator_version="2026-06-29.v1",
                baseline_prompt_hash=sha256_text(baseline_text),
                frontier_prompt_hash=sha256_text(frontier_text),
                primary_pool_fingerprint="a" * 64,
                holdout_pool_fingerprint=None,
                frontier_updated_at="2026-06-29T00:00:00+00:00",
                frontier_source="seed",
            )
        },
    )
    write_frontier_manifest(str(pack_root), manifest)
    return pack_root


def challenge_summary_payload(
    *,
    pack_root: Path,
    submission_root: Path,
    frontier_prompt_hash: str,
    candidate_prompt_hash: str,
) -> dict[str, object]:
    baseline_prompt = pack_root / "prompts" / "contributor" / "baseline.md"
    frontier_prompt = pack_root / "prompts" / "contributor" / "frontier.md"
    candidate_prompt = submission_root / "agent.py"
    return {
        "schema_version": 2,
        "run_id": "challenge-1",
        "manifest_path": str((pack_root / "frontier.json").resolve()),
        "mode": "contributor",
        "evaluator_version": "2026-06-29.v1",
        "baseline_prompt": str(baseline_prompt.resolve()),
        "frontier_prompt": str(frontier_prompt.resolve()),
        "candidate_prompt": str(candidate_prompt.resolve()),
        "baseline_prompt_hash": sha256_text("# baseline\n"),
        "frontier_prompt_hash": frontier_prompt_hash,
        "candidate_prompt_hash": candidate_prompt_hash,
        "primary_pool_fingerprint": "a" * 64,
        "holdout_pool_fingerprint": None,
        "promotion_margin_points": 3.0,
        "created_at": "2026-06-29T00:00:00+00:00",
        "primary": {
            "task_ids": ["task-a"],
            "eval_run_summary": "run_summary.json",
            "total_task_weight": 1.0,
            "variant_successes": {"baseline": 0, "frontier": 0, "candidate": 1},
            "variant_invalid_tasks": {"baseline": 0, "frontier": 0, "candidate": 0},
            "variant_scores": {"baseline": 0.0, "frontier": 0.0, "candidate": 100.0},
            "candidate_beats_frontier": True,
            "candidate_score_delta": 100.0,
        },
        "holdout": None,
        "promotion_ready": True,
        "promotion_reason": "candidate cleared the primary score margin",
    }


def test_validate_submission_accepts_scoped_submission_pr(
    tmp_path: Path,
    monkeypatch,
) -> None:
    registry_root = tmp_path / "registry"
    write_registry(registry_root)
    write_frontier_pack(registry_root, "example__repo", "/tmp/repo")
    monkeypatch.setenv("KATA_BENCHMARKS_ROOT", str(registry_root))
    repo_root = tmp_path / "Kata"
    submission_root = init_submission(
        repo_pack="example__repo",
        mode="contributor",
        submission_id="miner-1",
        output_root=str(repo_root / "submissions"),
    )
    (submission_root / "agent.py").write_text(VALID_AGENT, encoding="utf-8")

    result = validate_submission(
        str(submission_root),
        changed_paths=[
            "submissions/example__repo/contributor/miner-1/agent.py",
            "submissions/example__repo/contributor/miner-1/submission.json",
        ],
        repo_root=str(repo_root),
    )

    assert result.is_valid
    assert result.reasons == []
    assert result.off_scope_paths == []


def test_validate_submission_rejects_off_scope_pr_changes(
    tmp_path: Path,
    monkeypatch,
) -> None:
    registry_root = tmp_path / "registry"
    write_registry(registry_root)
    write_frontier_pack(registry_root, "example__repo", "/tmp/repo")
    monkeypatch.setenv("KATA_BENCHMARKS_ROOT", str(registry_root))
    repo_root = tmp_path / "Kata"
    submission_root = init_submission(
        repo_pack="example__repo",
        mode="contributor",
        submission_id="miner-2",
        output_root=str(repo_root / "submissions"),
    )
    (submission_root / "agent.py").write_text(VALID_AGENT, encoding="utf-8")

    result = validate_submission(
        str(submission_root),
        changed_paths=[
            "submissions/example__repo/contributor/miner-2/agent.py",
            "README.md",
        ],
        repo_root=str(repo_root),
    )

    assert not result.is_valid
    assert "Submission PR touches paths outside the allowed submission scope." in result.reasons
    assert result.off_scope_paths == ["README.md"]


def test_validate_submission_rejects_scaffold_agent(
    tmp_path: Path,
    monkeypatch,
) -> None:
    registry_root = tmp_path / "registry"
    write_registry(registry_root)
    write_frontier_pack(registry_root, "example__repo", "/tmp/repo")
    monkeypatch.setenv("KATA_BENCHMARKS_ROOT", str(registry_root))
    repo_root = tmp_path / "Kata"
    submission_root = init_submission(
        repo_pack="example__repo",
        mode="contributor",
        submission_id="miner-2b",
        output_root=str(repo_root / "submissions"),
    )

    result = validate_submission(str(submission_root))

    assert not result.is_valid
    assert "Submission agent still contains scaffold placeholder text." in result.reasons


def test_validate_submission_rejects_missing_solve(
    tmp_path: Path,
    monkeypatch,
) -> None:
    registry_root = tmp_path / "registry"
    write_registry(registry_root)
    write_frontier_pack(registry_root, "example__repo", "/tmp/repo")
    monkeypatch.setenv("KATA_BENCHMARKS_ROOT", str(registry_root))
    repo_root = tmp_path / "Kata"
    submission_root = init_submission(
        repo_pack="example__repo",
        mode="contributor",
        submission_id="miner-nosolve",
        output_root=str(repo_root / "submissions"),
    )
    (submission_root / "agent.py").write_text("print('hello')\n", encoding="utf-8")

    result = validate_submission(str(submission_root))

    assert not result.is_valid
    assert "Submission agent must define solve(...)." in result.reasons


def test_validate_submission_rejects_inactive_repo_pack(
    tmp_path: Path,
    monkeypatch,
) -> None:
    registry_root = tmp_path / "registry"
    write_registry(
        registry_root,
        active_repo_packs=["e35ventura__taopedia-articles"],
        default_repo_pack="e35ventura__taopedia-articles",
    )
    write_frontier_pack(registry_root, "example__repo", "/tmp/repo")
    monkeypatch.setenv("KATA_BENCHMARKS_ROOT", str(registry_root))
    repo_root = tmp_path / "Kata"
    submission_root = repo_root / "submissions" / "example__repo" / "contributor" / "miner-inactive"
    submission_root.mkdir(parents=True, exist_ok=True)
    (submission_root / "agent.py").write_text(VALID_AGENT, encoding="utf-8")
    (submission_root / "submission.json").write_text(
        json.dumps(
            {
                "schema_version": 2,
                "repo_pack": "example__repo",
                "mode": "contributor",
                "submission_id": "miner-inactive",
                "created_at": "2026-06-29T00:00:00+00:00",
                "author": "miner",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    result = validate_submission(str(submission_root))

    assert not result.is_valid
    assert any("Repo pack is not active" in reason for reason in result.reasons)


def test_init_submission_rejects_inactive_repo_pack(
    tmp_path: Path,
    monkeypatch,
) -> None:
    registry_root = tmp_path / "registry"
    write_registry(
        registry_root,
        active_repo_packs=["e35ventura__taopedia-articles"],
        default_repo_pack="e35ventura__taopedia-articles",
    )
    monkeypatch.setenv("KATA_BENCHMARKS_ROOT", str(registry_root))

    try:
        init_submission(
            repo_pack="example__repo",
            mode="contributor",
            submission_id="miner-inactive-init",
            output_root=str(tmp_path / "Kata" / "submissions"),
        )
    except ValueError as exc:
        assert "Repo pack is not active" in str(exc)
    else:
        raise AssertionError("Expected init_submission to reject inactive repo pack.")


def test_inspect_pull_request_rejects_non_submission_pr(tmp_path: Path) -> None:
    repo_root = tmp_path / "Kata"
    repo_root.mkdir()

    result = inspect_pull_request(
        repo_root=str(repo_root),
        changed_paths=["README.md"],
    )

    assert result.action == PR_ACTION_CLOSE_INVALID
    assert result.submission_path is None


def test_inspect_pull_request_accepts_single_submission_scope(
    tmp_path: Path,
    monkeypatch,
) -> None:
    registry_root = tmp_path / "registry"
    write_registry(registry_root)
    write_frontier_pack(registry_root, "example__repo", "/tmp/repo")
    monkeypatch.setenv("KATA_BENCHMARKS_ROOT", str(registry_root))
    repo_root = tmp_path / "Kata"
    repo_root.mkdir()
    submission_root = repo_root / "submissions" / "example__repo" / "contributor" / "miner-9"

    result = inspect_pull_request(
        repo_root=str(repo_root),
        changed_paths=[
            "submissions/example__repo/contributor/miner-9/agent.py",
            "submissions/example__repo/contributor/miner-9/submission.json",
        ],
    )

    assert result.action == PR_ACTION_EVALUATE
    assert result.submission_path == str(submission_root.resolve())


def test_inspect_pull_request_rejects_inactive_repo_pack(
    tmp_path: Path,
    monkeypatch,
) -> None:
    registry_root = tmp_path / "registry"
    write_registry(
        registry_root,
        active_repo_packs=["e35ventura__taopedia-articles"],
        default_repo_pack="e35ventura__taopedia-articles",
    )
    write_frontier_pack(registry_root, "example__repo", "/tmp/repo")
    monkeypatch.setenv("KATA_BENCHMARKS_ROOT", str(registry_root))
    repo_root = tmp_path / "Kata"
    repo_root.mkdir()

    result = inspect_pull_request(
        repo_root=str(repo_root),
        changed_paths=[
            "submissions/example__repo/contributor/miner-9/agent.py",
            "submissions/example__repo/contributor/miner-9/submission.json",
        ],
    )

    assert result.action == PR_ACTION_CLOSE_INVALID
    assert any("Repo pack is not active" in reason for reason in result.reasons)


def test_verify_submission_result_accepts_current_promotion_ready_result(
    tmp_path: Path,
    monkeypatch,
) -> None:
    registry_root = tmp_path / "registry"
    write_registry(registry_root)
    pack_root = write_frontier_pack(registry_root, "example__repo", "/tmp/repo")
    monkeypatch.setenv("KATA_BENCHMARKS_ROOT", str(registry_root))
    repo_root = tmp_path / "Kata"
    submission_root = init_submission(
        repo_pack="example__repo",
        mode="contributor",
        submission_id="miner-3",
        output_root=str(repo_root / "submissions"),
    )
    candidate_text = (
        "def solve(repo_path, issue, model, api_base, api_key):\n"
        "    return {\"success\": True, \"diff\": \"winner\"}\n"
    )
    (submission_root / "agent.py").write_text(candidate_text, encoding="utf-8")
    candidate_hash = sha256_text(candidate_text)
    summary_path = tmp_path / "challenge_summary.json"
    summary_path.write_text(
        json.dumps(
            challenge_summary_payload(
                pack_root=pack_root,
                submission_root=submission_root,
                frontier_prompt_hash=sha256_text("# frontier\n"),
                candidate_prompt_hash=candidate_hash,
            )
        )
        + "\n",
        encoding="utf-8",
    )

    result = verify_submission_result(str(submission_root), str(summary_path))

    assert result.submission_matches_challenge
    assert result.frontier_is_current
    assert result.benchmark_is_current
    assert result.auto_merge_ready
    assert result.reasons == []


def test_verify_submission_result_detects_stale_frontier(
    tmp_path: Path,
    monkeypatch,
) -> None:
    registry_root = tmp_path / "registry"
    write_registry(registry_root)
    pack_root = write_frontier_pack(registry_root, "example__repo", "/tmp/repo")
    monkeypatch.setenv("KATA_BENCHMARKS_ROOT", str(registry_root))
    repo_root = tmp_path / "Kata"
    submission_root = init_submission(
        repo_pack="example__repo",
        mode="contributor",
        submission_id="miner-4",
        output_root=str(repo_root / "submissions"),
    )
    candidate_text = (
        "def solve(repo_path, issue, model, api_base, api_key):\n"
        "    return {\"success\": True, \"diff\": \"winner\"}\n"
    )
    (submission_root / "agent.py").write_text(candidate_text, encoding="utf-8")
    summary_path = tmp_path / "challenge_summary.json"
    summary_path.write_text(
        json.dumps(
            challenge_summary_payload(
                pack_root=pack_root,
                submission_root=submission_root,
                frontier_prompt_hash=sha256_text("# older-frontier\n"),
                candidate_prompt_hash=sha256_text(candidate_text),
            )
        )
        + "\n",
        encoding="utf-8",
    )

    result = verify_submission_result(str(submission_root), str(summary_path))

    assert not result.frontier_is_current
    assert not result.auto_merge_ready
    assert "Challenge result is stale because the frontier prompt has changed." in result.reasons


def test_decide_submission_action_returns_merge_for_verified_winner(
    tmp_path: Path,
    monkeypatch,
) -> None:
    registry_root = tmp_path / "registry"
    write_registry(registry_root)
    pack_root = write_frontier_pack(registry_root, "example__repo", "/tmp/repo")
    monkeypatch.setenv("KATA_BENCHMARKS_ROOT", str(registry_root))
    repo_root = tmp_path / "Kata"
    submission_root = init_submission(
        repo_pack="example__repo",
        mode="contributor",
        submission_id="miner-merge",
        output_root=str(repo_root / "submissions"),
    )
    candidate_text = (
        "def solve(repo_path, issue, model, api_base, api_key):\n"
        "    return {\"success\": True, \"diff\": \"winner\"}\n"
    )
    (submission_root / "agent.py").write_text(candidate_text, encoding="utf-8")
    summary_path = tmp_path / "challenge_summary.json"
    summary_path.write_text(
        json.dumps(
            challenge_summary_payload(
                pack_root=pack_root,
                submission_root=submission_root,
                frontier_prompt_hash=sha256_text("# frontier\n"),
                candidate_prompt_hash=sha256_text(candidate_text),
            )
        )
        + "\n",
        encoding="utf-8",
    )

    result = decide_submission_action(str(submission_root), str(summary_path))

    assert result.action == PR_ACTION_MERGE
    assert result.auto_merge_ready


def test_decide_submission_action_returns_rerun_for_stale_result(
    tmp_path: Path,
    monkeypatch,
) -> None:
    registry_root = tmp_path / "registry"
    write_registry(registry_root)
    pack_root = write_frontier_pack(registry_root, "example__repo", "/tmp/repo")
    monkeypatch.setenv("KATA_BENCHMARKS_ROOT", str(registry_root))
    repo_root = tmp_path / "Kata"
    submission_root = init_submission(
        repo_pack="example__repo",
        mode="contributor",
        submission_id="miner-rerun",
        output_root=str(repo_root / "submissions"),
    )
    candidate_text = (
        "def solve(repo_path, issue, model, api_base, api_key):\n"
        "    return {\"success\": True, \"diff\": \"winner\"}\n"
    )
    (submission_root / "agent.py").write_text(candidate_text, encoding="utf-8")
    summary_path = tmp_path / "challenge_summary.json"
    summary_path.write_text(
        json.dumps(
            challenge_summary_payload(
                pack_root=pack_root,
                submission_root=submission_root,
                frontier_prompt_hash=sha256_text("# stale-frontier\n"),
                candidate_prompt_hash=sha256_text(candidate_text),
            )
        )
        + "\n",
        encoding="utf-8",
    )

    result = decide_submission_action(str(submission_root), str(summary_path))

    assert result.action == PR_ACTION_RERUN_STALE


def test_decide_submission_action_returns_close_for_loser(
    tmp_path: Path,
    monkeypatch,
) -> None:
    registry_root = tmp_path / "registry"
    write_registry(registry_root)
    pack_root = write_frontier_pack(registry_root, "example__repo", "/tmp/repo")
    monkeypatch.setenv("KATA_BENCHMARKS_ROOT", str(registry_root))
    repo_root = tmp_path / "Kata"
    submission_root = init_submission(
        repo_pack="example__repo",
        mode="contributor",
        submission_id="miner-lose",
        output_root=str(repo_root / "submissions"),
    )
    candidate_text = (
        "def solve(repo_path, issue, model, api_base, api_key):\n"
        "    return {\"success\": False, \"diff\": \"loser\"}\n"
    )
    (submission_root / "agent.py").write_text(candidate_text, encoding="utf-8")
    summary_path = tmp_path / "challenge_summary.json"
    payload = challenge_summary_payload(
        pack_root=pack_root,
        submission_root=submission_root,
        frontier_prompt_hash=sha256_text("# frontier\n"),
        candidate_prompt_hash=sha256_text(candidate_text),
    )
    payload["promotion_ready"] = False
    payload["promotion_reason"] = "candidate did not beat the current frontier on the primary score"
    summary_path.write_text(json.dumps(payload) + "\n", encoding="utf-8")

    result = decide_submission_action(str(submission_root), str(summary_path))

    assert result.action == PR_ACTION_CLOSE_LOSING
