from __future__ import annotations

import json
from pathlib import Path

from kata.agent_bundle import AGENT_ENTRY_FILENAME, AGENT_MANIFEST_FILENAME, write_agent_manifest
from kata.frontier import (
    FRONTIER_SCHEMA_VERSION,
    FrontierManifest,
    FrontierModeConfig,
    write_frontier_manifest,
)
from kata.provenance import sha256_directory, sha256_text
from kata.submissions import (
    PR_ACTION_CLOSE_INVALID,
    PR_ACTION_CLOSE_LOSING,
    PR_ACTION_EVALUATE,
    PR_ACTION_MERGE,
    PR_ACTION_RERUN_STALE,
    decide_submission_action,
    hash_submission_bundle,
    init_submission,
    inspect_pull_request,
    validate_submission,
    verify_submission_result,
)

VALID_AGENT = (
    "def solve(repo_path, issue, model, api_base, api_key):\n"
    "    return {\"success\": True, \"diff\": \"\"}\n"
)
SEED_AGENT = (
    "def solve(repo_path, issue, model, api_base, api_key):\n"
    "    return {\"diff\": \"\"}\n"
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
    artifact_root = pack_root / "agents" / "contributor"
    baseline_root = artifact_root / "baseline"
    frontier_root = artifact_root / "frontier"
    baseline_root.mkdir(parents=True, exist_ok=True)
    frontier_root.mkdir(parents=True, exist_ok=True)
    baseline_text = SEED_AGENT
    frontier_text = SEED_AGENT
    write_agent_manifest(baseline_root / AGENT_MANIFEST_FILENAME)
    write_agent_manifest(frontier_root / AGENT_MANIFEST_FILENAME)
    (baseline_root / AGENT_ENTRY_FILENAME).write_text(baseline_text, encoding="utf-8")
    (frontier_root / AGENT_ENTRY_FILENAME).write_text(frontier_text, encoding="utf-8")
    manifest = FrontierManifest(
        schema_version=FRONTIER_SCHEMA_VERSION,
        repo_ref=repo_ref,
        eval_pack=str(pack_root),
        updated_at="2026-06-29T00:00:00+00:00",
        modes={
            "contributor": FrontierModeConfig(
                baseline_artifact=str(baseline_root.resolve()),
                frontier_artifact=str(frontier_root.resolve()),
                primary_tasks=["task-a"],
                holdout_tasks=[],
                evaluator_version="2026-06-29.v1",
                baseline_artifact_hash=sha256_directory(
                    baseline_root,
                    include=[AGENT_ENTRY_FILENAME, AGENT_MANIFEST_FILENAME],
                ),
                frontier_artifact_hash=sha256_directory(
                    frontier_root,
                    include=[AGENT_ENTRY_FILENAME, AGENT_MANIFEST_FILENAME],
                ),
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
    frontier_artifact_hash: str,
    candidate_artifact_hash: str,
    validator_model: str = "Qwen3-32B",
) -> dict[str, object]:
    baseline_artifact = pack_root / "agents" / "contributor" / "baseline"
    frontier_artifact = pack_root / "agents" / "contributor" / "frontier"
    candidate_artifact = submission_root
    return {
        "schema_version": 4,
        "run_id": "challenge-1",
        "manifest_path": str((pack_root / "frontier.json").resolve()),
        "mode": "contributor",
        "evaluator_version": "2026-06-29.v1",
        "validator_model": validator_model,
        "baseline_artifact": str(baseline_artifact.resolve()),
        "frontier_artifact": str(frontier_artifact.resolve()),
        "candidate_artifact": str(candidate_artifact.resolve()),
        "baseline_artifact_hash": sha256_directory(
            baseline_artifact,
            include=[AGENT_ENTRY_FILENAME, AGENT_MANIFEST_FILENAME],
        ),
        "frontier_artifact_hash": frontier_artifact_hash,
        "candidate_artifact_hash": candidate_artifact_hash,
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


def test_init_submission_creates_agent_manifest(
    tmp_path: Path,
    monkeypatch,
) -> None:
    registry_root = tmp_path / "registry"
    write_registry(registry_root)
    write_frontier_pack(registry_root, "example__repo", "/tmp/repo")
    monkeypatch.setenv("KATA_BENCHMARKS_ROOT", str(registry_root))

    submission_root = init_submission(
        repo_pack="example__repo",
        mode="contributor",
        submission_id="miner-manifest",
        output_root=str(tmp_path / "Kata" / "submissions"),
    )

    assert (submission_root / AGENT_MANIFEST_FILENAME).exists()


def test_validate_submission_accepts_helper_only_change(
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
        submission_id="miner-helper",
        output_root=str(repo_root / "submissions"),
    )
    helpers_root = submission_root / "helpers"
    helpers_root.mkdir()
    (helpers_root / "planner.py").write_text("def plan():\n    return 'ok'\n", encoding="utf-8")
    (submission_root / "agent.py").write_text(VALID_AGENT, encoding="utf-8")

    result = validate_submission(
        str(submission_root),
        changed_paths=[
            "submissions/example__repo/contributor/miner-helper/helpers/planner.py",
        ],
        repo_root=str(repo_root),
    )

    assert result.is_valid


def test_validate_submission_rejects_unexpected_bundle_file(
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
        submission_id="miner-badfile",
        output_root=str(repo_root / "submissions"),
    )
    (submission_root / "agent.py").write_text(VALID_AGENT, encoding="utf-8")
    (submission_root / "notes.txt").write_text("bad\n", encoding="utf-8")

    result = validate_submission(str(submission_root))

    assert not result.is_valid
    assert "Submission bundle contains unsupported files: notes.txt" in result.reasons


def test_validate_submission_rejects_frontier_copycat_agent(
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
        submission_id="miner-copycat",
        output_root=str(repo_root / "submissions"),
    )
    helpers_root = submission_root / "helpers"
    helpers_root.mkdir()
    (helpers_root / "extra.py").write_text("VALUE = 1\n", encoding="utf-8")
    (submission_root / "agent.py").write_text(SEED_AGENT, encoding="utf-8")

    result = validate_submission(str(submission_root))

    assert not result.is_valid
    assert (
        "Submission agent duplicates the current frontier agent implementation."
        in result.reasons
    )


def test_validate_submission_rejects_validator_env_reference(
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
        submission_id="miner-env",
        output_root=str(repo_root / "submissions"),
    )
    (submission_root / "agent.py").write_text(
        "import os\n\n"
        "def solve(repo_path, issue, model, api_base, api_key):\n"
        "    key = os.environ.get('OPENAI_API_KEY', '')\n"
        "    return {\"success\": bool(key), \"diff\": \"\"}\n",
        encoding="utf-8",
    )

    result = validate_submission(str(submission_root))

    assert not result.is_valid
    assert any("OPENAI_API_KEY" in reason for reason in result.reasons)


def test_validate_submission_rejects_hardcoded_secret_like_token(
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
        submission_id="miner-secret",
        output_root=str(repo_root / "submissions"),
    )
    (submission_root / "agent.py").write_text(
        "def solve(repo_path, issue, model, api_base, api_key):\n"
        "    token = 'sk-1234567890abcdef'\n"
        "    return {\"success\": bool(token), \"diff\": \"\"}\n",
        encoding="utf-8",
    )

    result = validate_submission(str(submission_root))

    assert not result.is_valid
    assert any("hardcoded secret token" in reason for reason in result.reasons)


def test_validate_submission_rejects_invalid_helper_python_syntax(
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
        submission_id="miner-badhelper",
        output_root=str(repo_root / "submissions"),
    )
    helpers_root = submission_root / "helpers"
    helpers_root.mkdir()
    (helpers_root / "planner.py").write_text("def plan(:\n    return 'bad'\n", encoding="utf-8")
    (submission_root / "agent.py").write_text(VALID_AGENT, encoding="utf-8")

    result = validate_submission(str(submission_root))

    assert not result.is_valid
    assert any(
        "Submission bundle contains invalid Python syntax in helpers/planner.py" in reason
        for reason in result.reasons
    )


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
    candidate_hash = hash_submission_bundle(submission_root)
    summary_path = tmp_path / "challenge_summary.json"
    summary_path.write_text(
        json.dumps(
            challenge_summary_payload(
                pack_root=pack_root,
                submission_root=submission_root,
                frontier_artifact_hash=sha256_directory(
                    pack_root / "agents" / "contributor" / "frontier",
                    include=[AGENT_ENTRY_FILENAME, AGENT_MANIFEST_FILENAME],
                ),
                candidate_artifact_hash=candidate_hash,
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
                frontier_artifact_hash=sha256_text("# older-frontier\n"),
                candidate_artifact_hash=hash_submission_bundle(submission_root),
            )
        )
        + "\n",
        encoding="utf-8",
    )

    result = verify_submission_result(str(submission_root), str(summary_path))

    assert not result.frontier_is_current
    assert not result.auto_merge_ready
    assert "Challenge result is stale because the frontier artifact has changed." in result.reasons


def test_verify_submission_result_detects_validator_model_change(
    tmp_path: Path,
    monkeypatch,
) -> None:
    registry_root = tmp_path / "registry"
    write_registry(registry_root)
    pack_root = write_frontier_pack(registry_root, "example__repo", "/tmp/repo")
    monkeypatch.setenv("KATA_BENCHMARKS_ROOT", str(registry_root))
    monkeypatch.setenv("KATA_VALIDATOR_MODEL", "Qwen3-32B")
    repo_root = tmp_path / "Kata"
    submission_root = init_submission(
        repo_pack="example__repo",
        mode="contributor",
        submission_id="miner-model",
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
                frontier_artifact_hash=sha256_directory(
                    pack_root / "agents" / "contributor" / "frontier",
                    include=[AGENT_ENTRY_FILENAME, AGENT_MANIFEST_FILENAME],
                ),
                candidate_artifact_hash=hash_submission_bundle(submission_root),
                validator_model="OldModel-32B",
            )
        )
        + "\n",
        encoding="utf-8",
    )

    result = verify_submission_result(str(submission_root), str(summary_path))

    assert not result.benchmark_is_current
    assert not result.auto_merge_ready
    assert "Challenge result is stale because the validator model has changed." in result.reasons


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
                frontier_artifact_hash=sha256_directory(
                    pack_root / "agents" / "contributor" / "frontier",
                    include=[AGENT_ENTRY_FILENAME, AGENT_MANIFEST_FILENAME],
                ),
                candidate_artifact_hash=hash_submission_bundle(submission_root),
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
                frontier_artifact_hash=sha256_text("# stale-frontier\n"),
                candidate_artifact_hash=hash_submission_bundle(submission_root),
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
        frontier_artifact_hash=sha256_directory(
            pack_root / "agents" / "contributor" / "frontier",
            include=[AGENT_ENTRY_FILENAME, AGENT_MANIFEST_FILENAME],
        ),
        candidate_artifact_hash=hash_submission_bundle(submission_root),
    )
    payload["promotion_ready"] = False
    payload["promotion_reason"] = "candidate did not beat the current frontier on the primary score"
    summary_path.write_text(json.dumps(payload) + "\n", encoding="utf-8")

    result = decide_submission_action(str(submission_root), str(summary_path))

    assert result.action == PR_ACTION_CLOSE_LOSING
