from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from kata.packages.sn60.evaluate import evaluate_submission
from kata.screening_system.rules import hash_submission_bundle
from kata.state_system.lane import (
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
from kata.submission_system import (
    PR_ACTION_CLOSE_INVALID,
    PR_ACTION_EVALUATE,
    PR_ACTION_MERGE,
    PR_ACTION_RERUN_STALE,
    decide_submission_action,
    init_submission,
    inspect_pull_request,
    promote_submission_result,
    validate_submission,
    verify_submission_result,
)
from kata.submission_system.bundle import AGENT_MANIFEST_FILENAME, write_agent_manifest
from kata.validator_system import run_sn60_challenge, sample_sn60_project_keys

SCREENING_DESCRIPTION = (
    "A privileged state-changing function can be called by any account, "
    "allowing unauthorized changes to protected protocol settings."
)
VALID_MINER_AGENT = (
    "def agent_main(project_dir=None, inference_api=None):\n"
    "    source_hint = str(project_dir or '')\n"
    "    finding = {\n"
    "        \"title\": \"Missing access control on privileged update\",\n"
    "        \"description\": (\n"
    "            \"A privileged state-changing function can be called by any \"\n"
    "            \"account, allowing unauthorized changes to protected protocol settings.\"\n"
    "        ) + source_hint[:0],\n"
    "        \"severity\": \"high\",\n"
    "        \"file\": \"contracts/Admin.sol\",\n"
    "    }\n"
    "    return {\n"
    "        \"vulnerabilities\": [finding],\n"
    "    }\n"
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


def write_replay_benchmark(root: Path) -> Path:
    benchmark_path = root / "curated-highs-only-2025-08-08.json"
    benchmark_path.write_text(
        json.dumps(
            [
                {
                    "project_id": "sample_project",
                    "name": "Sample Project",
                    "codebases": [],
                    "vulnerabilities": [
                        {
                            "finding_id": "2026-01-sample_H-01",
                            "severity": "high",
                            "title": "Exact Replay Title For Validation",
                            "description": (
                                "ValidationReplayContract knownFunctionName "
                                "knownStorageSlot copied benchmark answer text "
                                "should be rejected when strict concrete replay "
                                "screening is enabled for production intake."
                            ),
                        }
                    ],
                }
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return benchmark_path


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


def test_validate_submission_accepts_subnet_pack_metadata_field(tmp_path, monkeypatch) -> None:
    _, repo_root, submission_root = make_miner_submission(tmp_path, monkeypatch)
    metadata_path = submission_root / "submission.json"
    payload = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert payload["subnet_pack"] == "sn60__bitsec"
    assert "repo_pack" not in payload

    result = validate_submission(str(submission_root), repo_root=str(repo_root))

    assert result.is_valid
    assert result.metadata is not None
    assert result.metadata.repo_pack == "sn60__bitsec"


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


def test_validate_submission_allows_helper_files(tmp_path, monkeypatch) -> None:
    _, repo_root, submission_root = make_miner_submission(tmp_path, monkeypatch)
    helpers = submission_root / "helpers"
    helpers.mkdir()
    (helpers / "util.py").write_text("X = 1\n", encoding="utf-8")

    result = validate_submission(str(submission_root), repo_root=str(repo_root))

    assert result.is_valid
    assert not any("do not support helper files in V1" in reason for reason in result.reasons)


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


def test_validate_submission_allows_sampling_override_source(
    tmp_path, monkeypatch
) -> None:
    reasons = validation_reasons(
        tmp_path,
        monkeypatch,
        agent_source=(
            "def agent_main(project_dir=None, inference_api=None):\n"
            "    call(temperature=0.2)\n"
            "    return {\"vulnerabilities\": []}\n"
        ),
    )
    assert not any("sampling parameters" in reason for reason in reasons)


def test_validate_submission_allows_dict_unpack_sampling_override_source(
    tmp_path, monkeypatch
) -> None:
    reasons = validation_reasons(
        tmp_path,
        monkeypatch,
        agent_source=(
            "def agent_main(project_dir=None, inference_api=None):\n"
            "    call(**{'temperature': 0.2})\n"
            "    return {\"vulnerabilities\": []}\n"
        ),
    )
    assert not any("temperature" in reason for reason in reasons)


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


def test_validate_submission_reports_invalid_metadata_schema_type(
    tmp_path, monkeypatch
) -> None:
    _, repo_root, submission_root = make_miner_submission(tmp_path, monkeypatch)
    metadata_path = submission_root / "submission.json"
    payload = json.loads(metadata_path.read_text(encoding="utf-8"))
    payload["schema_version"] = None
    metadata_path.write_text(json.dumps(payload), encoding="utf-8")

    result = validate_submission(str(submission_root), repo_root=str(repo_root))

    assert not result.is_valid
    assert any("invalid field" in reason for reason in result.reasons)


def test_validate_submission_reports_invalid_manifest_schema_type(
    tmp_path, monkeypatch
) -> None:
    _, repo_root, submission_root = make_miner_submission(tmp_path, monkeypatch)
    manifest_path = submission_root / AGENT_MANIFEST_FILENAME
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    payload["schema_version"] = None
    manifest_path.write_text(json.dumps(payload), encoding="utf-8")

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


def run_registry_lane_sn60_duel(tmp_path: Path, monkeypatch, *, agent_source=VALID_MINER_AGENT):
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
    (submission_root / "agent.py").write_text(agent_source, encoding="utf-8")

    def execute(context):
        return {
            "success": True,
            "report": {
                "vulnerabilities": [
                    {
                        "title": "Missing access control on privileged update",
                        "description": SCREENING_DESCRIPTION,
                        "severity": "high",
                        "file": "contracts/Admin.sol",
                    }
                ]
            },
        }

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
        king_artifact_path=str(king_root),
        candidate_artifact_path=str(submission_root),
        project_keys=["project-alpha"],
        candidate_submission_id="alice-20260702-10",
        output_root=str(tmp_path / "runs"),
        replicas_per_project=2,
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit="commit-a",
        public_root=str(public_root),
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
    assert result.screening_status == "pass"
    assert result.screening_score == 0
    assert result.screening_review_reasons == []


def test_validate_submission_holds_replay_signals_when_review_enabled(
    tmp_path: Path,
    monkeypatch,
) -> None:
    public_root = tmp_path / "kata-root"
    write_evaluator_lane(public_root)
    monkeypatch.setenv("KATA_ROOT", str(public_root))
    monkeypatch.setenv("KATA_SCREENING_REVIEW_MODE", "1")

    repo_root = tmp_path / "Kata"
    submission_root = init_submission(
        repo_pack="sn60__bitsec",
        mode="miner",
        submission_id="alice-20260702-01",
        output_root=str(repo_root / "submissions"),
        author="alice",
    )
    (submission_root / "agent.py").write_text(
        "PROJECT = 'code4rena_secondswap_2025_02'\n" + VALID_MINER_AGENT,
        encoding="utf-8",
    )

    result = validate_submission(str(submission_root), repo_root=str(repo_root))

    assert result.reasons == []
    assert result.is_valid
    assert result.screening_status == "review"
    assert result.screening_score == 6
    assert any(
        "code4rena_secondswap_2025_02" in reason
        for reason in result.screening_review_reasons
    )
    assert result.evaluator_id == "sn60_bitsec"


def test_validate_submission_keeps_replay_signals_report_only_by_default(
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
    (submission_root / "agent.py").write_text(
        "PROJECT = 'code4rena_secondswap_2025_02'\n" + VALID_MINER_AGENT,
        encoding="utf-8",
    )

    result = validate_submission(str(submission_root), repo_root=str(repo_root))

    assert result.reasons == []
    assert result.is_valid
    assert result.screening_status == "pass"
    assert result.screening_score == 6
    assert any(
        "code4rena_secondswap_2025_02" in reason
        for reason in result.screening_review_reasons
    )


def test_validate_submission_rejects_replay_signals_when_strict_enabled(
    tmp_path: Path,
    monkeypatch,
) -> None:
    public_root = tmp_path / "kata-root"
    write_evaluator_lane(public_root)
    monkeypatch.setenv("KATA_ROOT", str(public_root))
    monkeypatch.setenv("KATA_SCREENING_STRICT_REPLAY", "1")

    repo_root = tmp_path / "Kata"
    submission_root = init_submission(
        repo_pack="sn60__bitsec",
        mode="miner",
        submission_id="alice-20260702-01",
        output_root=str(repo_root / "submissions"),
        author="alice",
    )
    (submission_root / "agent.py").write_text(
        "PROJECT = 'code4rena_secondswap_2025_02'\n" + VALID_MINER_AGENT,
        encoding="utf-8",
    )

    result = validate_submission(str(submission_root), repo_root=str(repo_root))

    assert any("rejected hardcoded benchmark replay" in reason for reason in result.reasons)
    assert any(reason.startswith("agent.py:1: ") for reason in result.reasons)
    assert not result.is_valid


def test_validate_submission_rejects_known_answer_text_when_strict_enabled(
    tmp_path: Path,
    monkeypatch,
) -> None:
    public_root = tmp_path / "kata-root"
    write_evaluator_lane(public_root)
    benchmark_path = write_replay_benchmark(tmp_path)
    monkeypatch.setenv("KATA_ROOT", str(public_root))
    monkeypatch.setenv("KATA_SCREENING_STRICT_REPLAY", "1")
    monkeypatch.setenv("KATA_SN60_BENCHMARK_FILE", str(benchmark_path))

    repo_root = tmp_path / "Kata"
    submission_root = init_submission(
        repo_pack="sn60__bitsec",
        mode="miner",
        submission_id="alice-20260702-01",
        output_root=str(repo_root / "submissions"),
        author="alice",
    )
    (submission_root / "agent.py").write_text(
        "TITLE = 'Exact Replay Title For Validation'\n"
        "ANSWER = (\n"
        "    'ValidationReplayContract knownFunctionName knownStorageSlot copied '\n"
        "    'benchmark answer text should be rejected when strict concrete replay '\n"
        "    'screening is enabled for production intake.'\n"
        ")\n"
        + VALID_MINER_AGENT,
        encoding="utf-8",
    )

    result = validate_submission(str(submission_root), repo_root=str(repo_root))

    assert any("rejected hardcoded benchmark replay" in reason for reason in result.reasons)
    assert any(reason.startswith("agent.py:1: ") for reason in result.reasons)
    assert not result.is_valid


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


def test_validate_submission_reviews_near_copy_of_lane_king(
    tmp_path: Path,
    monkeypatch,
) -> None:
    public_root = tmp_path / "kata-root"
    write_evaluator_lane(public_root)
    monkeypatch.setenv("KATA_ROOT", str(public_root))
    monkeypatch.setenv("KATA_SCREENING_REVIEW_MODE", "1")

    king_root = public_root / "kings" / "sn60__bitsec" / "miner"
    king_root.mkdir(parents=True)
    king_agent = VALID_MINER_AGENT
    (king_root / "agent.py").write_text(king_agent, encoding="utf-8")

    repo_root = tmp_path / "Kata"
    submission_root = init_submission(
        repo_pack="sn60__bitsec",
        mode="miner",
        submission_id="alice-20260702-01",
        output_root=str(repo_root / "submissions"),
    )
    near_copy = king_agent.replace(
        "    return {\n",
        "    x = 0\n    return {\n",
        1,
    )
    (submission_root / "agent.py").write_text(near_copy, encoding="utf-8")

    result = validate_submission(str(submission_root), repo_root=str(repo_root))

    assert result.reasons == []
    assert result.is_valid
    assert result.screening_status == "review"
    assert any(
        "highly similar to the current lane king" in reason
        for reason in result.screening_review_reasons
    )


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

    monkeypatch.setattr(
        "kata.packages.sn60.evaluate.run_sn60_challenge",
        fake_run_sn60_challenge,
    )

    summary = evaluate_submission(
        str(submission_root),
        sn60_project_keys=["project-a"],
    )

    assert summary is sentinel
    assert calls["king_artifact_path"] == str(king_root.resolve())
    assert calls["lane_id"] == "sn60__bitsec"


def test_evaluate_submission_uses_benchmark_project_keys_by_default(
    tmp_path: Path,
    monkeypatch,
) -> None:
    public_root = tmp_path / "kata-root"
    write_evaluator_lane(public_root)
    monkeypatch.setenv("KATA_ROOT", str(public_root))
    seed_lane_king(public_root, "sn60__bitsec")

    sandbox_root = tmp_path / "sandbox"
    benchmark_path = sandbox_root / "validator" / "curated-highs-only-2025-08-08.json"
    benchmark_path.parent.mkdir(parents=True)
    benchmark_path.write_text(
        json.dumps(
            [
                {"project_id": "project-beta", "vulnerabilities": []},
                {"project_id": "project-alpha", "vulnerabilities": []},
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    repo_root = tmp_path / "Kata"
    submission_root = init_submission(
        repo_pack="sn60__bitsec",
        mode="miner",
        submission_id="alice-20260702-05",
        output_root=str(repo_root / "submissions"),
    )
    (submission_root / "agent.py").write_text(VALID_MINER_AGENT, encoding="utf-8")

    sentinel = object()
    calls: dict[str, object] = {}

    def fake_run_sn60_challenge(**kwargs):
        calls.update(kwargs)
        return sentinel

    monkeypatch.delenv("KATA_SN60_PROJECT_KEYS", raising=False)
    monkeypatch.setattr(
        "kata.packages.sn60.evaluate.run_sn60_challenge",
        fake_run_sn60_challenge,
    )

    summary = evaluate_submission(
        str(submission_root),
        sn60_sandbox_root=str(sandbox_root),
        sn60_benchmark_file=str(benchmark_path),
        sn60_sandbox_commit="commit-1",
    )

    assert summary is sentinel
    assert calls["project_keys"] == ["project-alpha", "project-beta"]


def test_evaluate_submission_samples_benchmark_project_keys_from_env(
    tmp_path: Path,
    monkeypatch,
) -> None:
    public_root = tmp_path / "kata-root"
    write_evaluator_lane(public_root)
    monkeypatch.setenv("KATA_ROOT", str(public_root))
    king_root = seed_lane_king(public_root, "sn60__bitsec")

    sandbox_root = tmp_path / "sandbox"
    benchmark_path = sandbox_root / "validator" / "curated-highs-only-2025-08-08.json"
    benchmark_path.parent.mkdir(parents=True)
    benchmark_keys = ["project-alpha", "project-beta", "project-delta", "project-gamma"]
    benchmark_path.write_text(
        json.dumps(
            [{"project_id": project_key, "vulnerabilities": []} for project_key in benchmark_keys]
        )
        + "\n",
        encoding="utf-8",
    )

    repo_root = tmp_path / "Kata"
    submission_root = init_submission(
        repo_pack="sn60__bitsec",
        mode="miner",
        submission_id="alice-20260702-06",
        output_root=str(repo_root / "submissions"),
    )
    (submission_root / "agent.py").write_text(VALID_MINER_AGENT, encoding="utf-8")

    sentinel = object()
    calls: dict[str, object] = {}

    def fake_run_sn60_challenge(**kwargs):
        calls.update(kwargs)
        return sentinel

    monkeypatch.delenv("KATA_SN60_PROJECT_KEYS", raising=False)
    monkeypatch.setenv("KATA_SN60_PROJECT_SAMPLE_SIZE", "2")
    monkeypatch.setenv("KATA_SN60_PROJECT_SAMPLE_SECRET", "validator-secret")
    monkeypatch.setattr(
        "kata.validator_system.project_selection.secrets.token_hex",
        lambda _size: "nonce-1",
    )
    monkeypatch.setattr(
        "kata.packages.sn60.evaluate.run_sn60_challenge",
        fake_run_sn60_challenge,
    )

    summary = evaluate_submission(
        str(submission_root),
        sn60_sandbox_root=str(sandbox_root),
        sn60_benchmark_file=str(benchmark_path),
        sn60_sandbox_commit="commit-1",
    )

    expected = sample_sn60_project_keys(
        sorted(benchmark_keys),
        sample_size=2,
        sample_secret="validator-secret",
        sample_nonce="nonce-1",
        king_artifact_hash=hash_submission_bundle(king_root),
        candidate_artifact_hash=hash_submission_bundle(submission_root),
        candidate_submission_id="alice-20260702-06",
    )
    assert summary is sentinel
    assert calls["project_keys"] == expected
    assert len(calls["project_keys"]) == 2


def test_evaluate_submission_requires_sample_secret_when_sampling(
    tmp_path: Path,
    monkeypatch,
) -> None:
    public_root = tmp_path / "kata-root"
    write_evaluator_lane(public_root)
    monkeypatch.setenv("KATA_ROOT", str(public_root))
    seed_lane_king(public_root, "sn60__bitsec")

    sandbox_root = tmp_path / "sandbox"
    benchmark_path = sandbox_root / "validator" / "curated-highs-only-2025-08-08.json"
    benchmark_path.parent.mkdir(parents=True)
    benchmark_path.write_text(
        json.dumps(
            [
                {"project_id": "project-alpha", "vulnerabilities": []},
                {"project_id": "project-beta", "vulnerabilities": []},
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    repo_root = tmp_path / "Kata"
    submission_root = init_submission(
        repo_pack="sn60__bitsec",
        mode="miner",
        submission_id="alice-20260702-07",
        output_root=str(repo_root / "submissions"),
    )
    (submission_root / "agent.py").write_text(VALID_MINER_AGENT, encoding="utf-8")

    monkeypatch.delenv("KATA_SN60_PROJECT_KEYS", raising=False)
    monkeypatch.setenv("KATA_SN60_PROJECT_SAMPLE_SIZE", "1")
    monkeypatch.delenv("KATA_SN60_PROJECT_SAMPLE_SECRET", raising=False)

    with pytest.raises(ValueError, match="KATA_SN60_PROJECT_SAMPLE_SECRET"):
        evaluate_submission(
            str(submission_root),
            sn60_sandbox_root=str(sandbox_root),
            sn60_benchmark_file=str(benchmark_path),
            sn60_sandbox_commit="commit-1",
        )


def test_explicit_sn60_project_keys_override_sampling_env(
    tmp_path: Path,
    monkeypatch,
) -> None:
    public_root = tmp_path / "kata-root"
    write_evaluator_lane(public_root)
    monkeypatch.setenv("KATA_ROOT", str(public_root))
    seed_lane_king(public_root, "sn60__bitsec")

    repo_root = tmp_path / "Kata"
    submission_root = init_submission(
        repo_pack="sn60__bitsec",
        mode="miner",
        submission_id="alice-20260702-08",
        output_root=str(repo_root / "submissions"),
    )
    (submission_root / "agent.py").write_text(VALID_MINER_AGENT, encoding="utf-8")

    sentinel = object()
    calls: dict[str, object] = {}

    def fake_run_sn60_challenge(**kwargs):
        calls.update(kwargs)
        return sentinel

    monkeypatch.setenv("KATA_SN60_PROJECT_SAMPLE_SIZE", "1")
    monkeypatch.delenv("KATA_SN60_PROJECT_SAMPLE_SECRET", raising=False)
    monkeypatch.setattr(
        "kata.packages.sn60.evaluate.run_sn60_challenge",
        fake_run_sn60_challenge,
    )

    summary = evaluate_submission(
        str(submission_root),
        sn60_project_keys=["project-explicit"],
    )

    assert summary is sentinel
    assert calls["project_keys"] == ["project-explicit"]


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

    monkeypatch.setattr(
        "kata.packages.sn60.evaluate.run_sn60_challenge",
        fake_run_sn60_challenge,
    )

    summary = evaluate_submission(
        str(submission_root),
        sn60_project_keys=["project-a"],
    )

    assert summary is sentinel
    assert calls["lane_id"] == "sn99__custom"
    assert calls["king_artifact_path"] == str(king_root.resolve())


def test_verify_and_promote_sn60_registry_lane_end_to_end(
    tmp_path: Path,
    monkeypatch,
) -> None:
    public_root, submission_root, summary, summary_path = run_registry_lane_sn60_duel(
        tmp_path, monkeypatch
    )

    verification = verify_submission_result(str(submission_root), str(summary_path))
    assert verification.submission_matches_challenge
    assert verification.king_is_current
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


def test_promote_records_published_king_hash_for_non_normalized_agent(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from kata.evaluators.sn60_bitsec import hash_bundle_root

    # An agent.py WITHOUT a trailing newline: publishing normalizes it
    # (write_bundle_files appends "\n"), so the published king bytes differ
    # from the submitted bytes. The recorded king hash must match the PUBLISHED
    # bundle (what future duels hash), or every later duel sees
    # king_is_current=False -> a permanent rerun-stale livelock.
    non_normalized = (
        "def agent_main(project_dir=None, inference_api=None):\n"
        "    source_hint = str(project_dir or '')\n"
        "    finding = {\n"
        "        \"title\": \"Missing access control on privileged update\",\n"
        "        \"description\": (\n"
        "            \"A privileged state-changing function can be called by any \"\n"
        "            \"account, allowing unauthorized changes to protected protocol settings.\"\n"
        "        ) + source_hint[:0],\n"
        "        \"severity\": \"high\",\n"
        "        \"file\": \"contracts/Admin.sol\",\n"
        "    }\n"
        "    return {\"vulnerabilities\": [finding]}"  # no trailing newline
    )
    assert not non_normalized.endswith("\n")

    public_root, submission_root, _summary, summary_path = run_registry_lane_sn60_duel(
        tmp_path, monkeypatch, agent_source=non_normalized
    )
    verification = verify_submission_result(str(submission_root), str(summary_path))
    assert verification.promotion_ready

    result = promote_submission_result(
        str(submission_root), str(summary_path), public_root=str(public_root)
    )
    king_state = load_lane_king_state("sn60__bitsec", public_root=str(public_root))
    published_king_root = public_root / "kings" / "sn60__bitsec" / "miner"

    # The recorded hash equals the hash of the published king exactly as a duel
    # would recompute it — so king_is_current holds on the next challenge.
    assert king_state.current_king_artifact_hash == hash_bundle_root(published_king_root)
    assert result.king.current_king_artifact_hash == hash_bundle_root(published_king_root)


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
    assert verification.king_is_current
    assert not verification.benchmark_is_current
    assert not verification.auto_merge_ready
    assert any("SN60 benchmark lane has changed" in reason for reason in verification.reasons)


def test_verify_sn60_registry_lane_ignores_superseded_challenge_fingerprint(
    tmp_path: Path,
    monkeypatch,
) -> None:
    # The per-run sample fingerprint changes every duel and is never committed to
    # the lane state, so it must NOT gate freshness -- otherwise a verified winner
    # could never be promoted. A differing lane fingerprint leaves the result
    # auto-merge-ready; only the benchmark version and king identity gate it.
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
    assert verification.benchmark_is_current
    assert verification.auto_merge_ready


def test_verify_and_promote_honor_explicit_public_root(
    tmp_path: Path,
    monkeypatch,
) -> None:
    public_root, submission_root, summary, summary_path = run_registry_lane_sn60_duel(
        tmp_path, monkeypatch
    )

    # Point KATA_ROOT at an unrelated directory: an explicit public_root must
    # verify against the same lane state the promotion is written to, not the
    # ambient environment root.
    decoy_root = tmp_path / "decoy-root"
    decoy_root.mkdir()
    monkeypatch.setenv("KATA_ROOT", str(decoy_root))

    verification = verify_submission_result(
        str(submission_root),
        str(summary_path),
        public_root=str(public_root),
    )
    assert verification.king_is_current
    assert verification.benchmark_is_current
    assert verification.auto_merge_ready

    result = promote_submission_result(
        str(submission_root),
        str(summary_path),
        public_root=str(public_root),
    )
    assert result.lane_id == "sn60__bitsec"
    king_state = load_lane_king_state("sn60__bitsec", public_root=str(public_root))
    assert king_state.current_king_artifact_hash == summary.candidate_artifact_hash
    # Nothing was written to the decoy KATA_ROOT.
    assert not (decoy_root / "kings").exists()
    assert not (decoy_root / "lanes").exists()
