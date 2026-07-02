from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from kata.agent_bundle import AGENT_MANIFEST_FILENAME, write_agent_manifest
from kata.challenge import run_sn60_challenge
from kata.lane_state import (
    KING_STATE_SCHEMA_VERSION,
    LANE_METADATA_SCHEMA_VERSION,
    EvaluatorLaneMetadata,
    LaneKingState,
    load_benchmark_snapshot,
    load_challenge_state,
    load_lane_king_state,
    write_benchmark_snapshot,
    write_challenge_state,
    write_lane_king_state,
    write_lane_metadata,
)
from kata.submissions import (
    PR_ACTION_CLOSE_INVALID,
    PR_ACTION_EVALUATE,
    PR_ACTION_MERGE,
    PR_ACTION_RERUN_STALE,
    decide_submission_action,
    evaluate_submission,
    hash_submission_bundle,
    init_submission,
    inspect_pull_request,
    promote_submission_result,
    validate_submission,
    verify_submission_result,
)

VALID_MINER_AGENT = (
    "def agent_main(project_dir=None, inference_api=None):\n"
    "    return {\"vulnerabilities\": []}\n"
)
SEED_MINER_AGENT = (
    "def agent_main(project_dir=None, inference_api=None):\n"
    "    return {\n"
    "        \"vulnerabilities\": [{\"title\": \"seed finding\"}],\n"
    "    }\n"
)


def make_miner_submission(
    tmp_path: Path,
    monkeypatch,
    *,
    agent_source: str | None = VALID_MINER_AGENT,
    submission_id: str = "alice-20260702-01",
):
    public_root = tmp_path / "kata-root"
    if not (public_root / "lanes").exists():
        write_evaluator_lane(public_root)
    monkeypatch.setenv("KATA_ROOT", str(public_root))
    repo_root = tmp_path / "Kata"
    submission_root = init_submission(
        repo_pack="sn60__bitsec",
        mode="miner",
        submission_id=submission_id,
        output_root=str(repo_root / "submissions"),
    )
    if agent_source is not None:
        (submission_root / "agent.py").write_text(agent_source, encoding="utf-8")
    return public_root, repo_root, submission_root


def validation_reasons(tmp_path, monkeypatch, agent_source):
    _, repo_root, submission_root = make_miner_submission(
        tmp_path, monkeypatch, agent_source=agent_source
    )
    return validate_submission(str(submission_root), repo_root=str(repo_root)).reasons


def test_validate_submission_accepts_scoped_pr_changes(tmp_path, monkeypatch) -> None:
    _, repo_root, submission_root = make_miner_submission(tmp_path, monkeypatch)
    rel = submission_root.relative_to(repo_root).as_posix()

    result = validate_submission(
        str(submission_root),
        changed_paths=[f"{rel}/agent.py"],
        repo_root=str(repo_root),
    )

    assert result.is_valid
    assert result.off_scope_paths == []


def test_validate_submission_rejects_off_scope_pr_changes(tmp_path, monkeypatch) -> None:
    _, repo_root, submission_root = make_miner_submission(tmp_path, monkeypatch)
    rel = submission_root.relative_to(repo_root).as_posix()

    result = validate_submission(
        str(submission_root),
        changed_paths=[f"{rel}/agent.py", "kata/cli.py"],
        repo_root=str(repo_root),
    )

    assert "kata/cli.py" in result.off_scope_paths
    assert not result.is_valid


def test_validate_submission_rejects_symlink_bundles(tmp_path, monkeypatch) -> None:
    _, repo_root, submission_root = make_miner_submission(tmp_path, monkeypatch)
    (submission_root / "link.py").symlink_to(submission_root / "agent.py")

    result = validate_submission(str(submission_root), repo_root=str(repo_root))

    assert any("must not contain symlinks" in reason for reason in result.reasons)


def test_validate_submission_rejects_scaffold_agent(tmp_path, monkeypatch) -> None:
    reasons = validation_reasons(tmp_path, monkeypatch, agent_source=None)
    assert any("scaffold placeholder" in reason for reason in reasons)


def test_validate_submission_rejects_missing_agent_main(tmp_path, monkeypatch) -> None:
    reasons = validation_reasons(
        tmp_path, monkeypatch, agent_source="def other():\n    return {}\n"
    )
    assert any("must define agent_main" in reason for reason in reasons)


def test_validate_submission_rejects_commented_agent_main(tmp_path, monkeypatch) -> None:
    reasons = validation_reasons(
        tmp_path,
        monkeypatch,
        agent_source="# def agent_main():\ndef other():\n    return {}\n",
    )
    assert any("must define agent_main" in reason for reason in reasons)


def test_validate_submission_rejects_required_agent_main_args(tmp_path, monkeypatch) -> None:
    reasons = validation_reasons(
        tmp_path,
        monkeypatch,
        agent_source="def agent_main(project_dir):\n    return {\"vulnerabilities\": []}\n",
    )
    assert any("no-argument invocation" in reason for reason in reasons)


def test_validate_submission_rejects_helper_files(tmp_path, monkeypatch) -> None:
    _, repo_root, submission_root = make_miner_submission(tmp_path, monkeypatch)
    helpers = submission_root / "helpers"
    helpers.mkdir()
    (helpers / "util.py").write_text("X = 1\n", encoding="utf-8")

    result = validate_submission(str(submission_root), repo_root=str(repo_root))

    assert any("do not support helper files in V1" in reason for reason in result.reasons)


def test_validate_submission_rejects_non_bitsec_report_contract(tmp_path, monkeypatch) -> None:
    reasons = validation_reasons(
        tmp_path,
        monkeypatch,
        agent_source=(
            "def agent_main(project_dir=None, inference_api=None):\n"
            "    return {\"findings\": []}\n"
        ),
    )
    assert any("top-level `vulnerabilities`" in reason for reason in reasons)


def test_validate_submission_rejects_unexpected_bundle_file(tmp_path, monkeypatch) -> None:
    _, repo_root, submission_root = make_miner_submission(tmp_path, monkeypatch)
    (submission_root / "extra.txt").write_text("hello\n", encoding="utf-8")

    result = validate_submission(str(submission_root), repo_root=str(repo_root))

    assert any("unsupported files" in reason for reason in result.reasons)


def test_validate_submission_ignores_python_cache_artifacts(tmp_path, monkeypatch) -> None:
    _, repo_root, submission_root = make_miner_submission(tmp_path, monkeypatch)
    cache = submission_root / "__pycache__"
    cache.mkdir()
    (cache / "agent.cpython-313.pyc").write_bytes(b"\x00")

    result = validate_submission(str(submission_root), repo_root=str(repo_root))

    assert result.is_valid


def test_validate_submission_rejects_validator_env_reference(tmp_path, monkeypatch) -> None:
    reasons = validation_reasons(
        tmp_path,
        monkeypatch,
        agent_source=(
            "import os\n"
            "def agent_main(project_dir=None, inference_api=None):\n"
            "    os.environ.get(\"OPENAI_API_KEY\")\n"
            "    return {\"vulnerabilities\": []}\n"
        ),
    )
    assert any("secret env vars" in reason for reason in reasons)


def test_validate_submission_rejects_hardcoded_secret(tmp_path, monkeypatch) -> None:
    reasons = validation_reasons(
        tmp_path,
        monkeypatch,
        agent_source=(
            "KEY = \"sk-abcdefghijklmnop\"\n"
            "def agent_main(project_dir=None, inference_api=None):\n"
            "    return {\"vulnerabilities\": []}\n"
        ),
    )
    assert any("hardcoded secret" in reason for reason in reasons)


def test_validate_submission_rejects_sampling_override(tmp_path, monkeypatch) -> None:
    reasons = validation_reasons(
        tmp_path,
        monkeypatch,
        agent_source=(
            "def agent_main(project_dir=None, inference_api=None):\n"
            "    call(temperature=0.2)\n"
            "    return {\"vulnerabilities\": []}\n"
        ),
    )
    assert any("sampling parameters" in reason for reason in reasons)


def test_validate_submission_rejects_provider_endpoint(tmp_path, monkeypatch) -> None:
    reasons = validation_reasons(
        tmp_path,
        monkeypatch,
        agent_source=(
            "URL = \"https://api.openai.com/v1\"\n"
            "def agent_main(project_dir=None, inference_api=None):\n"
            "    return {\"vulnerabilities\": []}\n"
        ),
    )
    assert any("provider endpoints" in reason for reason in reasons)


def test_validate_submission_reports_malformed_metadata(tmp_path, monkeypatch) -> None:
    _, repo_root, submission_root = make_miner_submission(tmp_path, monkeypatch)
    (submission_root / "submission.json").write_text("{not json", encoding="utf-8")

    result = validate_submission(str(submission_root), repo_root=str(repo_root))

    assert not result.is_valid
    assert result.reasons


def test_inspect_pull_request_rejects_non_submission_pr(tmp_path: Path) -> None:
    result = inspect_pull_request(
        repo_root=str(tmp_path),
        changed_paths=["README.md"],
    )
    assert result.action == PR_ACTION_CLOSE_INVALID


def test_inspect_pull_request_accepts_single_submission_scope(
    tmp_path: Path,
    monkeypatch,
) -> None:
    public_root = tmp_path / "kata-root"
    write_evaluator_lane(public_root)
    monkeypatch.setenv("KATA_ROOT", str(public_root))

    result = inspect_pull_request(
        repo_root=str(tmp_path),
        changed_paths=[
            "submissions/sn60__bitsec/miner/alice-20260702-01/agent.py",
            "submissions/sn60__bitsec/miner/alice-20260702-01/submission.json",
        ],
    )
    assert result.action == PR_ACTION_EVALUATE
    assert result.submission_id == "alice-20260702-01"


def test_decide_submission_action_merges_registry_winner(tmp_path, monkeypatch) -> None:
    _, submission_root, _, summary_path = run_registry_lane_sn60_duel(
        tmp_path, monkeypatch
    )

    decision = decide_submission_action(str(submission_root), str(summary_path))

    assert decision.action == PR_ACTION_MERGE
    assert decision.auto_merge_ready


def test_decide_submission_action_reruns_stale_benchmark(tmp_path, monkeypatch) -> None:
    public_root, submission_root, _, summary_path = run_registry_lane_sn60_duel(
        tmp_path, monkeypatch
    )
    snapshot = load_benchmark_snapshot("sn60__bitsec", public_root=str(public_root))
    write_benchmark_snapshot(
        "sn60__bitsec",
        replace(snapshot, sandbox_commit_hash="commit-b"),
        public_root=str(public_root),
    )

    decision = decide_submission_action(str(submission_root), str(summary_path))

    assert decision.action == PR_ACTION_RERUN_STALE


def write_evaluator_lane(public_root: Path, *, active: bool = True) -> None:
    write_lane_metadata(
        EvaluatorLaneMetadata(
            schema_version=LANE_METADATA_SCHEMA_VERSION,
            lane_id="sn60__bitsec",
            repo_pack="sn60__bitsec",
            mode="miner",
            evaluator_id="sn60_bitsec",
            evaluator_policy_version="v1",
            active=active,
            created_at="2026-07-01T00:00:00+00:00",
            updated_at="2026-07-01T00:00:00+00:00",
        ),
        public_root=str(public_root),
    )


def seed_lane_king(public_root: Path, repo_pack: str) -> Path:
    king_root = public_root / "kings" / repo_pack / "miner"
    king_root.mkdir(parents=True)
    (king_root / "agent.py").write_text(SEED_MINER_AGENT, encoding="utf-8")
    write_agent_manifest(king_root / AGENT_MANIFEST_FILENAME)
    return king_root


def run_registry_lane_sn60_duel(tmp_path: Path, monkeypatch):
    public_root = tmp_path / "kata-root"
    write_evaluator_lane(public_root)
    monkeypatch.setenv("KATA_ROOT", str(public_root))
    king_root = seed_lane_king(public_root, "sn60__bitsec")

    sandbox_root = tmp_path / "sandbox"
    benchmark_path = sandbox_root / "validator" / "curated-highs-only-2025-08-08.json"
    benchmark_path.parent.mkdir(parents=True)
    benchmark_path.write_text(
        json.dumps([{"project_id": "project-alpha", "vulnerabilities": []}]) + "\n",
        encoding="utf-8",
    )

    repo_root = tmp_path / "Kata"
    submission_root = init_submission(
        repo_pack="sn60__bitsec",
        mode="miner",
        submission_id="alice-20260702-10",
        output_root=str(repo_root / "submissions"),
    )
    (submission_root / "agent.py").write_text(VALID_MINER_AGENT, encoding="utf-8")

    def execute(context):
        return {"success": True, "report": {"vulnerabilities": []}}

    def evaluate(context, report_payload):
        rate = 1.0 if context.variant_name == "candidate" else 0.0
        return {
            "status": "success",
            "result": {
                "detection_rate": rate,
                "true_positives": int(rate * 2),
                "total_expected": 2,
                "total_found": 1,
                "result": "PASS" if rate == 1.0 else "FAIL",
            },
        }

    summary = run_sn60_challenge(
        frontier_artifact_path=str(king_root),
        candidate_artifact_path=str(submission_root),
        project_keys=["project-alpha"],
        candidate_submission_id="alice-20260702-10",
        output_root=str(tmp_path / "runs"),
        replicas_per_project=2,
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit="commit-a",
        public_root=str(public_root),
        screening_hook=lambda ctx: {"success": True, "report": {"vulnerabilities": []}},
        execution_hook=execute,
        evaluation_hook=evaluate,
    )
    summary_path = Path(summary.manifest_path).with_name("challenge_summary.json")
    return public_root, submission_root, summary, summary_path


def test_validate_submission_accepts_miner_submission_for_registry_lane(
    tmp_path: Path,
    monkeypatch,
) -> None:
    public_root = tmp_path / "kata-root"
    write_evaluator_lane(public_root)
    monkeypatch.setenv("KATA_ROOT", str(public_root))

    repo_root = tmp_path / "Kata"
    submission_root = init_submission(
        repo_pack="sn60__bitsec",
        mode="miner",
        submission_id="alice-20260702-01",
        output_root=str(repo_root / "submissions"),
        author="alice",
    )
    (submission_root / "agent.py").write_text(VALID_MINER_AGENT, encoding="utf-8")

    result = validate_submission(str(submission_root), repo_root=str(repo_root))

    assert result.reasons == []
    assert result.is_valid
    assert result.evaluator_id == "sn60_bitsec"


def test_init_submission_rejects_inactive_registry_lane(
    tmp_path: Path,
    monkeypatch,
) -> None:
    public_root = tmp_path / "kata-root"
    write_evaluator_lane(public_root, active=False)
    monkeypatch.setenv("KATA_ROOT", str(public_root))

    with pytest.raises(ValueError, match="not active in the pack registry"):
        init_submission(
            repo_pack="sn60__bitsec",
            mode="miner",
            submission_id="alice-20260702-01",
            output_root=str(tmp_path / "Kata" / "submissions"),
        )


def test_validate_submission_rejects_copy_of_lane_king(
    tmp_path: Path,
    monkeypatch,
) -> None:
    public_root = tmp_path / "kata-root"
    write_evaluator_lane(public_root)
    monkeypatch.setenv("KATA_ROOT", str(public_root))

    repo_root = tmp_path / "Kata"
    submission_root = init_submission(
        repo_pack="sn60__bitsec",
        mode="miner",
        submission_id="alice-20260702-01",
        output_root=str(repo_root / "submissions"),
    )
    (submission_root / "agent.py").write_text(VALID_MINER_AGENT, encoding="utf-8")

    write_lane_king_state(
        "sn60__bitsec",
        LaneKingState(
            schema_version=KING_STATE_SCHEMA_VERSION,
            current_king_submission_id="king-1",
            current_king_artifact_hash=hash_submission_bundle(submission_root),
            promotion_source_pr=None,
            promotion_timestamp=None,
            updated_at="2026-07-01T00:00:00+00:00",
        ),
        public_root=str(public_root),
    )

    result = validate_submission(str(submission_root), repo_root=str(repo_root))

    assert any("exact copy of the current lane king" in reason for reason in result.reasons)
    assert not result.is_valid


def test_evaluate_submission_uses_seeded_lane_king_for_registry_lane(
    tmp_path: Path,
    monkeypatch,
) -> None:
    public_root = tmp_path / "kata-root"
    write_evaluator_lane(public_root)
    monkeypatch.setenv("KATA_ROOT", str(public_root))
    king_root = seed_lane_king(public_root, "sn60__bitsec")

    repo_root = tmp_path / "Kata"
    submission_root = init_submission(
        repo_pack="sn60__bitsec",
        mode="miner",
        submission_id="alice-20260702-02",
        output_root=str(repo_root / "submissions"),
    )
    (submission_root / "agent.py").write_text(VALID_MINER_AGENT, encoding="utf-8")

    sentinel = object()
    calls: dict[str, object] = {}

    def fake_run_sn60_challenge(**kwargs):
        calls.update(kwargs)
        return sentinel

    monkeypatch.setattr("kata.submissions.run_sn60_challenge", fake_run_sn60_challenge)

    summary = evaluate_submission(
        str(submission_root),
        sn60_project_keys=["project-a"],
    )

    assert summary is sentinel
    assert calls["frontier_artifact_path"] == str(king_root.resolve())
    assert calls["lane_id"] == "sn60__bitsec"


def test_evaluate_submission_requires_seeded_king_for_registry_lane(
    tmp_path: Path,
    monkeypatch,
) -> None:
    public_root = tmp_path / "kata-root"
    write_evaluator_lane(public_root)
    monkeypatch.setenv("KATA_ROOT", str(public_root))

    repo_root = tmp_path / "Kata"
    submission_root = init_submission(
        repo_pack="sn60__bitsec",
        mode="miner",
        submission_id="alice-20260702-03",
        output_root=str(repo_root / "submissions"),
    )
    (submission_root / "agent.py").write_text(VALID_MINER_AGENT, encoding="utf-8")

    with pytest.raises(ValueError, match="king artifact is not seeded"):
        evaluate_submission(
            str(submission_root),
                sn60_project_keys=["project-a"],
        )


def test_evaluate_submission_selects_sn60_adapter_by_registry_evaluator_id(
    tmp_path: Path,
    monkeypatch,
) -> None:
    public_root = tmp_path / "kata-root"
    write_lane_metadata(
        EvaluatorLaneMetadata(
            schema_version=LANE_METADATA_SCHEMA_VERSION,
            lane_id="sn99__custom",
            repo_pack="sn99__custom",
            mode="miner",
            evaluator_id="sn60_bitsec",
            evaluator_policy_version="v1",
            active=True,
            created_at="2026-07-01T00:00:00+00:00",
            updated_at="2026-07-01T00:00:00+00:00",
        ),
        public_root=str(public_root),
    )
    monkeypatch.setenv("KATA_ROOT", str(public_root))
    king_root = seed_lane_king(public_root, "sn99__custom")

    repo_root = tmp_path / "Kata"
    submission_root = init_submission(
        repo_pack="sn99__custom",
        mode="miner",
        submission_id="alice-20260702-04",
        output_root=str(repo_root / "submissions"),
    )
    (submission_root / "agent.py").write_text(VALID_MINER_AGENT, encoding="utf-8")

    sentinel = object()
    calls: dict[str, object] = {}

    def fake_run_sn60_challenge(**kwargs):
        calls.update(kwargs)
        return sentinel

    monkeypatch.setattr("kata.submissions.run_sn60_challenge", fake_run_sn60_challenge)

    summary = evaluate_submission(
        str(submission_root),
        sn60_project_keys=["project-a"],
    )

    assert summary is sentinel
    assert calls["lane_id"] == "sn99__custom"
    assert calls["frontier_artifact_path"] == str(king_root.resolve())


def test_verify_and_promote_sn60_registry_lane_end_to_end(
    tmp_path: Path,
    monkeypatch,
) -> None:
    public_root, submission_root, summary, summary_path = run_registry_lane_sn60_duel(
        tmp_path, monkeypatch
    )

    verification = verify_submission_result(str(submission_root), str(summary_path))
    assert verification.submission_matches_challenge
    assert verification.frontier_is_current
    assert verification.benchmark_is_current
    assert verification.promotion_ready
    assert verification.auto_merge_ready

    result = promote_submission_result(
        str(submission_root),
        str(summary_path),
        public_root=str(public_root),
    )
    assert result.lane_id == "sn60__bitsec"
    king_state = load_lane_king_state("sn60__bitsec", public_root=str(public_root))
    assert king_state.current_king_submission_id == "alice-20260702-10"
    assert king_state.current_king_artifact_hash == summary.candidate_artifact_hash
    promoted_agent = public_root / "kings" / "sn60__bitsec" / "miner" / "agent.py"
    assert promoted_agent.read_text(encoding="utf-8").strip() == VALID_MINER_AGENT.strip()

    # After promotion the candidate IS the king, so re-verifying the same
    # submission must fail validation as a copy of the current lane king.
    with pytest.raises(ValueError, match="exact copy of the current lane king"):
        verify_submission_result(str(submission_root), str(summary_path))


def test_verify_sn60_registry_lane_detects_stale_benchmark_snapshot(
    tmp_path: Path,
    monkeypatch,
) -> None:
    public_root, submission_root, summary, summary_path = run_registry_lane_sn60_duel(
        tmp_path, monkeypatch
    )

    snapshot = load_benchmark_snapshot("sn60__bitsec", public_root=str(public_root))
    write_benchmark_snapshot(
        "sn60__bitsec",
        replace(snapshot, sandbox_commit_hash="commit-b"),
        public_root=str(public_root),
    )

    verification = verify_submission_result(str(submission_root), str(summary_path))
    assert verification.submission_matches_challenge
    assert verification.frontier_is_current
    assert not verification.benchmark_is_current
    assert not verification.auto_merge_ready
    assert any("SN60 benchmark lane has changed" in reason for reason in verification.reasons)


def test_verify_sn60_registry_lane_detects_superseded_challenge_fingerprint(
    tmp_path: Path,
    monkeypatch,
) -> None:
    public_root, submission_root, summary, summary_path = run_registry_lane_sn60_duel(
        tmp_path, monkeypatch
    )

    state = load_challenge_state("sn60__bitsec", public_root=str(public_root))
    write_challenge_state(
        "sn60__bitsec",
        replace(state, freshness_fingerprint="0" * 64),
        public_root=str(public_root),
    )

    verification = verify_submission_result(str(submission_root), str(summary_path))
    assert not verification.benchmark_is_current
    assert not verification.auto_merge_ready
