from __future__ import annotations

import json
from pathlib import Path

from kata.evaluators.sn60_bitsec import Sn60ReplicaContext, resolve_sn60_sandbox_source
from kata.screening_system import screen_submission
from kata.screening_system.models import ScreeningFinding
from kata.validator_system.screening import (
    SN60_SCREENING_STAGE_EXECUTION,
    SN60_SCREENING_STAGE_STATIC,
    run_sn60_screening,
    validate_sn60_static_screening,
)

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
    "    source_hint = str(project_dir or '')\n"
    "    finding = {"
    "'title': 'Missing access control on privileged update', "
    f"'description': {SCREENING_DESCRIPTION!r} + source_hint[:0], "
    "'severity': 'high', "
    "'file': 'contracts/Admin.sol'}\n"
    "    return {'vulnerabilities': [finding]}\n"
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


def write_replay_benchmark(root: Path) -> Path:
    benchmark_path = root / "curated-highs-only-2025-08-08.json"
    benchmark_path.write_text(
        json.dumps(
            [
                {
                    "project_id": "sample_project",
                    "name": "Sample Project",
                    "codebases": [
                        {
                            "codebase_id": "SecondSwap_VestingManager_test",
                            "repo_url": "https://example.test/secondswap",
                        }
                    ],
                    "vulnerabilities": [
                        {
                            "finding_id": "2026-01-sample_H-01",
                            "severity": "high",
                            "title": "Exact Replay Title For Screening",
                            "description": (
                                "SecondSwap_VestingManager grantorVesting stepsClaimed "
                                "transferVesting MarketplaceToken allows replayed answer "
                                "text to be detected when a candidate copies a long "
                                "known benchmark explanation into its static report bank."
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
    assert {finding.rule_id for finding in decision.reject_reasons} == {
        "sn60.answer_key_token",
        "sn60.helper_files",
    }


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

    assert decision.status == "pass"
    assert decision.passed
    assert decision.rejection_messages() == []
    assert decision.score == 12
    assert [finding.rule_id for finding in decision.review_reasons] == [
        "benchmark_replay.project_id",
        "benchmark_replay.finding_id",
    ]


def test_screen_submission_can_promote_replay_signals_to_review_status(
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

    assert decision.status == "review"
    assert not decision.passed
    assert decision.score == 6
    assert decision.review_reasons[0].line == 1


def test_screen_submission_rejects_replay_signals_in_strict_mode(
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
        strict_replay=True,
    )

    assert decision.status == "reject"
    assert not decision.passed
    assert decision.review_reasons == []
    assert decision.reject_reasons[0].severity == "reject"
    assert (
        "rejected hardcoded benchmark replay: a hardcoded benchmark-style project id"
        in decision.rejection_messages()[0]
    )
    assert "code4rena_mantra-dex_2025_03" in decision.rejection_messages()[0]


def test_screen_submission_rejects_known_title_and_answer_text_in_strict_mode(
    tmp_path: Path,
    monkeypatch,
) -> None:
    benchmark_path = write_replay_benchmark(tmp_path)
    monkeypatch.setenv("KATA_SN60_BENCHMARK_FILE", str(benchmark_path))
    bundle_root = tmp_path / "candidate"
    write_bundle(
        bundle_root,
        "TITLE = 'Exact Replay Title For Screening'\n"
        "ANSWER = (\n"
        "    'SecondSwap_VestingManager grantorVesting stepsClaimed transferVesting '\n"
        "    'MarketplaceToken allows replayed answer text to be detected when a '\n"
        "    'candidate copies a long known benchmark explanation into its static '\n"
        "    'report bank.'\n"
        ")\n"
        + VALID_AGENT_SOURCE,
    )

    decision = screen_submission(
        submission_root=bundle_root,
        changed_paths=[],
        repo_root=tmp_path,
        public_root=None,
        mode="miner",
        strict_replay=True,
    )

    assert decision.status == "reject"
    rule_ids = {finding.rule_id for finding in decision.reject_reasons}
    assert "benchmark_replay.title_text" in rule_ids
    assert "benchmark_replay.long_answer_text" in rule_ids
    assert all(finding.severity == "reject" for finding in decision.reject_reasons)
    lines_by_rule = {finding.rule_id: finding.line for finding in decision.reject_reasons}
    assert lines_by_rule["benchmark_replay.title_text"] == 1
    assert lines_by_rule["benchmark_replay.long_answer_text"] == 3
    assert all(
        "rejected hardcoded benchmark replay: Remove" not in reason
        for reason in decision.rejection_messages()
    )
    assert any(
        "exact known benchmark finding title text" in reason
        for reason in decision.rejection_messages()
    )
    assert any(
        "exact known benchmark answer text" in reason
        for reason in decision.rejection_messages()
    )


def test_screen_submission_keeps_ambiguous_fingerprint_as_review_in_strict_mode(
    tmp_path: Path,
    monkeypatch,
) -> None:
    benchmark_path = write_replay_benchmark(tmp_path)
    monkeypatch.setenv("KATA_SN60_BENCHMARK_FILE", str(benchmark_path))
    bundle_root = tmp_path / "candidate"
    write_bundle(
        bundle_root,
        "def agent_main(project_dir=None, inference_api=None):\n"
        "    source = ''\n"
        "    if (\n"
        "        'SecondSwap_VestingManager' in source\n"
        "        and 'grantorVesting' in source\n"
        "        and 'stepsClaimed' in source\n"
        "    ):\n"
        "        suspicious = {\n"
        "            'title': 'Suspicious static issue',\n"
        "            'description': 'This is a long enough suspicious static report.',\n"
        "            'severity': 'high',\n"
        "            'file': 'contracts/Example.sol',\n"
        "        }\n"
        "        return {'vulnerabilities': [suspicious]}\n"
        "    generic = {\n"
        "        'title': 'Generic issue',\n"
        f"        'description': {SCREENING_DESCRIPTION!r},\n"
        "        'severity': 'high',\n"
        "        'file': 'contracts/Admin.sol',\n"
        "    }\n"
        "    return {'vulnerabilities': [generic]}\n",
    )

    decision = screen_submission(
        submission_root=bundle_root,
        changed_paths=[],
        repo_root=tmp_path,
        public_root=None,
        mode="miner",
        enable_review=True,
        strict_replay=True,
    )

    assert decision.status == "review"
    assert decision.reject_reasons == []
    rule_ids = {finding.rule_id for finding in decision.review_reasons}
    assert "benchmark_replay.project_fingerprint_branch" in rule_ids
    assert "benchmark_replay.early_return_fingerprint" in rule_ids


def test_screen_submission_attaches_llm_review_for_review_findings(
    tmp_path: Path,
    monkeypatch,
) -> None:
    benchmark_path = write_replay_benchmark(tmp_path)
    monkeypatch.setenv("KATA_SN60_BENCHMARK_FILE", str(benchmark_path))
    monkeypatch.setenv("KATA_SCREENING_LLM_REVIEW", "1")
    bundle_root = tmp_path / "candidate"
    write_bundle(
        bundle_root,
        "def agent_main(project_dir=None, inference_api=None):\n"
        "    source = ''\n"
        "    if 'SecondSwap_VestingManager' in source and 'grantorVesting' in source:\n"
        "        suspicious = {'title': 'x', 'description': 'y'}\n"
        "        return {'vulnerabilities': [suspicious]}\n"
        "    generic = {\n"
        "        'title': 'Generic issue',\n"
        f"        'description': {SCREENING_DESCRIPTION!r},\n"
        "        'severity': 'high',\n"
        "        'file': 'contracts/Admin.sol',\n"
        "    }\n"
        "    return {'vulnerabilities': [generic]}\n",
    )

    def fake_llm_review(**_kwargs):
        return (
            [
                ScreeningFinding(
                    rule_id="llm_review.suspicious",
                    severity="review",
                    path=None,
                    line=None,
                    reason="LLM review supports holding this submission.",
                    evidence="verdict=suspicious; confidence=0.80",
                )
            ],
            [
                ScreeningFinding(
                    rule_id="llm_review.result",
                    severity="note",
                    path=None,
                    line=None,
                    reason="LLM review verdict `suspicious`.",
                    evidence="model=gpt-5.4",
                )
            ],
        )

    monkeypatch.setattr(
        "kata.screening_system.engine.review_suspicious_submission_with_llm",
        fake_llm_review,
    )

    decision = screen_submission(
        submission_root=bundle_root,
        changed_paths=[],
        repo_root=tmp_path,
        public_root=None,
        mode="miner",
        enable_review=True,
    )

    assert decision.status == "review"
    assert any(finding.rule_id == "llm_review.suspicious" for finding in decision.review_reasons)
    assert any(note.rule_id == "llm_review.result" for note in decision.notes)


def test_screen_submission_reviews_large_static_report_bank(tmp_path: Path) -> None:
    bundle_root = tmp_path / "candidate"
    reports = ",\n".join(
        "{'title': 'Issue %s', 'description': %r, 'severity': 'high', 'file': 'A.sol'}"
        % (index, SCREENING_DESCRIPTION)
        for index in range(3)
    )
    write_bundle(
        bundle_root,
        "def agent_main(project_dir=None, inference_api=None):\n"
        f"    reports = [{reports}]\n"
        "    return {'vulnerabilities': reports}\n",
    )

    decision = screen_submission(
        submission_root=bundle_root,
        changed_paths=[],
        repo_root=tmp_path,
        public_root=None,
        mode="miner",
        enable_review=True,
        strict_replay=True,
    )

    assert decision.status == "review"
    assert decision.reject_reasons == []
    assert any(
        finding.rule_id == "benchmark_replay.static_report_bank"
        for finding in decision.review_reasons
    )


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


def test_validate_sn60_static_screening_rejects_constant_canned_report(
    tmp_path: Path,
) -> None:
    bundle_root = tmp_path / "candidate"
    write_bundle(
        bundle_root,
        "def agent_main(project_dir=None, inference_api=None):\n"
        "    return {'vulnerabilities': [{\n"
        "        'title': 'Always same issue',\n"
        f"        'description': {SCREENING_DESCRIPTION!r},\n"
        "        'severity': 'high',\n"
        "        'file': 'contracts/Admin.sol',\n"
        "    }]}\n",
    )

    reasons = validate_sn60_static_screening(bundle_root)

    assert any("constant canned vulnerability report" in reason for reason in reasons)


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
