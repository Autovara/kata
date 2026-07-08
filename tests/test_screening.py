from __future__ import annotations

import json
from pathlib import Path

from kata.evaluators.sn60_bitsec import Sn60ReplicaContext, resolve_sn60_sandbox_source
from kata.screening import (
    SN60_SCREENING_STAGE_EXECUTION,
    SN60_SCREENING_STAGE_STATIC,
    run_sn60_screening,
    validate_sn60_static_screening,
)
from kata.screening_system import screen_submission

SCREENING_DESCRIPTION = (
    "A privileged state-changing function can be called by any account, "
    "allowing unauthorized changes to protected protocol settings."
)
VALID_FINDING = {
    "title": "Missing access control on privileged update",
    "description": SCREENING_DESCRIPTION,
    "severity": "high",
    "file": "contracts/Admin.sol",
}
VALID_AGENT_SOURCE = (
    "def agent_main(project_dir=None, inference_api=None):\n"
    "    return {'vulnerabilities': [{"
    "'title': 'Missing access control on privileged update', "
    f"'description': {SCREENING_DESCRIPTION!r}, "
    "'severity': 'high', "
    "'file': 'contracts/Admin.sol'}]}\n"
)


def write_bundle(root: Path, agent_source: str, *, helper_source: str | None = None) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "agent.py").write_text(agent_source, encoding="utf-8")
    if helper_source is not None:
        helpers_root = root / "helpers"
        helpers_root.mkdir()
        (helpers_root / "planner.py").write_text(helper_source, encoding="utf-8")


def write_sandbox_source(root: Path) -> Path:
    benchmark_path = root / "validator" / "curated-highs-only-2025-08-08.json"
    benchmark_path.parent.mkdir(parents=True, exist_ok=True)
    benchmark_path.write_text(
        json.dumps([{"project_id": "project-alpha", "vulnerabilities": []}]) + "\n",
        encoding="utf-8",
    )
    return benchmark_path


def test_validate_sn60_static_screening_rejects_helper_files_and_leak_tokens(
    tmp_path: Path,
) -> None:
    bundle_root = tmp_path / "candidate"
    write_bundle(
        bundle_root,
        "KNOWN = 'curated-highs-only'\n"
        + VALID_AGENT_SOURCE,
        helper_source="VALUE = 1\n",
    )

    reasons = validate_sn60_static_screening(bundle_root)

    assert any("do not support helper files in V1" in reason for reason in reasons)
    assert any("benchmark-answer leakage token" in reason for reason in reasons)


def test_screen_submission_wraps_current_static_screening(tmp_path: Path) -> None:
    bundle_root = tmp_path / "candidate"
    write_bundle(
        bundle_root,
        "KNOWN = 'curated-highs-only'\n"
        + VALID_AGENT_SOURCE,
        helper_source="VALUE = 1\n",
    )

    decision = screen_submission(
        submission_root=bundle_root,
        changed_paths=[],
        repo_root=tmp_path,
        public_root=None,
        mode="miner",
    )

    assert decision.status == "reject"
    assert not decision.passed
    assert decision.rejection_messages() == validate_sn60_static_screening(bundle_root)
    assert all(finding.rule_id == "sn60.static" for finding in decision.reject_reasons)


def test_screen_submission_reports_exact_benchmark_replay_signals(tmp_path: Path) -> None:
    bundle_root = tmp_path / "candidate"
    write_bundle(
        bundle_root,
        "PROJECT = 'code4rena_secondswap_2025_02'\n"
        "FINDING = '2024-12-secondswap_H-01'\n"
        + VALID_AGENT_SOURCE,
    )

    decision = screen_submission(
        submission_root=bundle_root,
        changed_paths=[],
        repo_root=tmp_path,
        public_root=None,
        mode="miner",
    )

    assert decision.status == "reject"
    assert not decision.passed
    assert decision.score == 12
    assert any("benchmark-style project id" in reason for reason in decision.rejection_messages())
    assert any("benchmark finding id" in reason for reason in decision.rejection_messages())
    assert [finding.rule_id for finding in decision.review_reasons] == [
        "benchmark_replay.project_id",
        "benchmark_replay.finding_id",
    ]


def test_screen_submission_rejects_replay_signals_even_when_review_is_enabled(
    tmp_path: Path,
) -> None:
    bundle_root = tmp_path / "candidate"
    write_bundle(
        bundle_root,
        "PROJECT = 'code4rena_mantra-dex_2025_03'\n"
        + VALID_AGENT_SOURCE,
    )

    decision = screen_submission(
        submission_root=bundle_root,
        changed_paths=[],
        repo_root=tmp_path,
        public_root=None,
        mode="miner",
        enable_review=True,
    )

    assert decision.status == "reject"
    assert not decision.passed
    assert decision.score == 6
    assert decision.review_reasons[0].line == 1


def test_validate_sn60_static_screening_rejects_source_fingerprint_replay(
    tmp_path: Path,
) -> None:
    bundle_root = tmp_path / "candidate"
    write_bundle(
        bundle_root,
        "def _source_heuristics(records):\n"
        "    findings = []\n"
        "    for rec in records:\n"
        "        text = rec['text']\n"
        "        compact = text.replace(' ', '')\n"
        "        if (\n"
        "            'functiontransferVesting(' in compact\n"
        "            and 'grantorVesting.stepsClaimed' in text\n"
        "            and '_createVesting(_beneficiary, _amount, "
        "grantorVesting.stepsClaimed, true)' in text\n"
        "            and 'releaseRate' in text\n"
        "        ):\n"
        "            findings.append({\n"
        "                'title': 'TokenVesting.transferVesting - purchased vesting "
        "inherits seller claimed steps',\n"
        "                'description': 'The buyer inherits already claimed vesting "
        "steps from the seller.',\n"
        "                'severity': 'high',\n"
        "                'file': 'contracts/TokenVesting.sol',\n"
        "                'contract': 'TokenVesting',\n"
        "                'function': 'transferVesting',\n"
        "                'mechanism': 'A copied benchmark answer is returned when "
        "source strings match.',\n"
        "                'impact': 'The benchmark finding is replayed without analysis.',\n"
        "            })\n"
        "            findings.append({\n"
        "                'title': 'TokenVesting.transferVesting - grantor releaseRate "
        "ignores claimed steps',\n"
        "                'description': 'The release rate is recomputed without "
        "remaining-step accounting.',\n"
        "                'severity': 'high',\n"
        "                'file': 'contracts/TokenVesting.sol',\n"
        "                'contract': 'TokenVesting',\n"
        "                'function': 'transferVesting',\n"
        "                'mechanism': 'A second copied benchmark answer is returned "
        "from the same branch.',\n"
        "                'impact': 'The agent recognizes the benchmark project and "
        "replays answers.',\n"
        "            })\n"
        "    return findings\n"
        + VALID_AGENT_SOURCE,
    )

    reasons = validate_sn60_static_screening(bundle_root)

    assert any("benchmark-specific answer replay" in reason for reason in reasons)


def test_screen_submission_allows_generic_reusable_detector(tmp_path: Path) -> None:
    bundle_root = tmp_path / "candidate"
    write_bundle(
        bundle_root,
        "def transfers_tokens_before_state_update(source):\n"
        "    return '.call(' in source and 'balances[' in source\n"
        + VALID_AGENT_SOURCE,
    )

    decision = screen_submission(
        submission_root=bundle_root,
        changed_paths=[],
        repo_root=tmp_path,
        public_root=None,
        mode="miner",
    )

    assert decision.status == "pass"
    assert decision.review_reasons == []
    assert decision.score == 0


def test_validate_sn60_static_screening_rejects_async_agent_main(
    tmp_path: Path,
) -> None:
    bundle_root = tmp_path / "candidate"
    write_bundle(
        bundle_root,
        "async def agent_main(project_dir=None, inference_api=None):\n"
        "    return {'vulnerabilities': [{'title': 'x'}]}\n",
    )

    reasons = validate_sn60_static_screening(bundle_root)

    assert any("must be a synchronous function" in reason for reason in reasons)


def test_run_sn60_screening_persists_static_failure_without_execution(
    tmp_path: Path,
) -> None:
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = write_sandbox_source(sandbox_root)
    source = resolve_sn60_sandbox_source(
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit="commit-1",
        scorer_version="ScaBenchScorerV2",
    )
    bundle_root = tmp_path / "candidate"
    write_bundle(
        bundle_root,
        "def agent_main(project_dir):\n"
        "    return {'vulnerabilities': []}\n",
    )
    execution_called = False

    def execute(context: Sn60ReplicaContext) -> dict[str, object]:
        nonlocal execution_called
        execution_called = True
        return {"success": True, "report": {"vulnerabilities": [VALID_FINDING]}}

    result = run_sn60_screening(
        candidate_artifact_path=str(bundle_root),
        project_key="project-alpha",
        output_root=str(tmp_path / "runs"),
        sandbox_source=source,
        execution_hook=execute,
    )

    assert not execution_called
    assert not result.passed
    assert result.stage == SN60_SCREENING_STAGE_STATIC
    assert Path(result.result_path).exists()
    assert result.report_path is None


def test_run_sn60_screening_rejects_bad_execution_report(tmp_path: Path) -> None:
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = write_sandbox_source(sandbox_root)
    source = resolve_sn60_sandbox_source(
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit="commit-1",
        scorer_version="ScaBenchScorerV2",
    )
    bundle_root = tmp_path / "candidate"
    write_bundle(
        bundle_root,
        VALID_AGENT_SOURCE,
    )

    def execute(context: Sn60ReplicaContext) -> dict[str, object]:
        return {"success": True, "report": {"findings": []}}

    result = run_sn60_screening(
        candidate_artifact_path=str(bundle_root),
        project_key="project-alpha",
        output_root=str(tmp_path / "runs"),
        sandbox_source=source,
        execution_hook=execute,
    )

    assert not result.passed
    assert result.stage == SN60_SCREENING_STAGE_EXECUTION
    assert any("top-level `vulnerabilities` list" in reason for reason in result.reasons)
    assert Path(result.report_path or "").exists()


def test_validate_sn60_static_screening_rejects_expanded_leak_tokens(
    tmp_path: Path,
) -> None:
    bundle_root = tmp_path / "candidate"
    write_bundle(
        bundle_root,
        "GROUND = 'ground_truth'\n"
        + VALID_AGENT_SOURCE,
    )

    reasons = validate_sn60_static_screening(bundle_root)

    assert any(
        "benchmark-answer leakage token" in reason and "ground_truth" in reason
        for reason in reasons
    )


def test_validate_sn60_static_screening_rejects_validator_secret_reference(
    tmp_path: Path,
) -> None:
    bundle_root = tmp_path / "candidate"
    write_bundle(
        bundle_root,
        "import os\n"
        "def agent_main(project_dir=None, inference_api=None):\n"
        "    os.environ.get('CHUTES_API_KEY')\n"
        "    return {'vulnerabilities': [{"
        "'title': 'Missing access control on privileged update', "
        f"'description': {SCREENING_DESCRIPTION!r}, "
        "'severity': 'high'}]}\n",
    )

    reasons = validate_sn60_static_screening(bundle_root)

    assert any("validator secret reference" in reason for reason in reasons)


def test_validate_sn60_static_screening_rejects_hardcoded_chutes_key(
    tmp_path: Path,
) -> None:
    bundle_root = tmp_path / "candidate"
    write_bundle(
        bundle_root,
        "KEY = 'cpk_abcdefghij1234567890'\n"
        + VALID_AGENT_SOURCE,
    )

    reasons = validate_sn60_static_screening(bundle_root)

    assert any("hardcoded secret token" in reason for reason in reasons)


def test_validate_sn60_static_screening_rejects_direct_empty_report(
    tmp_path: Path,
) -> None:
    bundle_root = tmp_path / "candidate"
    write_bundle(
        bundle_root,
        "def agent_main(project_dir=None, inference_api=None):\n"
        "    return {'vulnerabilities': []}\n",
    )

    reasons = validate_sn60_static_screening(bundle_root)

    assert any("no-op agent" in reason for reason in reasons)


def test_run_sn60_screening_rejects_empty_execution_report(tmp_path: Path) -> None:
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = write_sandbox_source(sandbox_root)
    source = resolve_sn60_sandbox_source(
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit="commit-1",
        scorer_version="ScaBenchScorerV2",
    )
    bundle_root = tmp_path / "candidate"
    write_bundle(bundle_root, VALID_AGENT_SOURCE)

    result = run_sn60_screening(
        candidate_artifact_path=str(bundle_root),
        project_key="project-alpha",
        output_root=str(tmp_path / "runs"),
        sandbox_source=source,
        execution_hook=lambda _context: {"success": True, "report": {"vulnerabilities": []}},
    )

    assert not result.passed
    assert result.stage == SN60_SCREENING_STAGE_EXECUTION
    assert any("at least one candidate vulnerability" in reason for reason in result.reasons)


def test_run_sn60_screening_rejects_thin_finding_description(tmp_path: Path) -> None:
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = write_sandbox_source(sandbox_root)
    source = resolve_sn60_sandbox_source(
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit="commit-1",
        scorer_version="ScaBenchScorerV2",
    )
    bundle_root = tmp_path / "candidate"
    write_bundle(bundle_root, VALID_AGENT_SOURCE)

    result = run_sn60_screening(
        candidate_artifact_path=str(bundle_root),
        project_key="project-alpha",
        output_root=str(tmp_path / "runs"),
        sandbox_source=source,
        execution_hook=lambda _context: {
            "success": True,
            "report": {"vulnerabilities": [{"title": "bug", "description": "too short"}]},
        },
    )

    assert not result.passed
    assert any("useful description" in reason for reason in result.reasons)


def test_run_sn60_screening_rejects_missing_or_low_severity(tmp_path: Path) -> None:
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = write_sandbox_source(sandbox_root)
    source = resolve_sn60_sandbox_source(
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit="commit-1",
        scorer_version="ScaBenchScorerV2",
    )
    bundle_root = tmp_path / "candidate"
    write_bundle(bundle_root, VALID_AGENT_SOURCE)

    result = run_sn60_screening(
        candidate_artifact_path=str(bundle_root),
        project_key="project-alpha",
        output_root=str(tmp_path / "runs"),
        sandbox_source=source,
        execution_hook=lambda _context: {
            "success": True,
            "report": {
                "vulnerabilities": [
                    {
                        "title": "Low issue",
                        "description": SCREENING_DESCRIPTION,
                        "severity": "low",
                        "file": "contracts/Admin.sol",
                    },
                    {
                        "title": "Missing severity",
                        "description": SCREENING_DESCRIPTION,
                        "file": "contracts/Admin.sol",
                    },
                ]
            },
        },
    )

    assert not result.passed
    assert any("unsupported severity `low`" in reason for reason in result.reasons)
    assert any("must include severity `high` or `critical`" in reason for reason in result.reasons)


def test_run_sn60_screening_rejects_missing_source_location(tmp_path: Path) -> None:
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = write_sandbox_source(sandbox_root)
    source = resolve_sn60_sandbox_source(
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit="commit-1",
        scorer_version="ScaBenchScorerV2",
    )
    bundle_root = tmp_path / "candidate"
    write_bundle(bundle_root, VALID_AGENT_SOURCE)

    result = run_sn60_screening(
        candidate_artifact_path=str(bundle_root),
        project_key="project-alpha",
        output_root=str(tmp_path / "runs"),
        sandbox_source=source,
        execution_hook=lambda _context: {
            "success": True,
            "report": {
                "vulnerabilities": [
                    {
                        "title": "Missing access control on privileged update",
                        "description": SCREENING_DESCRIPTION,
                        "severity": "high",
                    }
                ]
            },
        },
    )

    assert not result.passed
    assert any("source location hint" in reason for reason in result.reasons)
