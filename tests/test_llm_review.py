from __future__ import annotations

import json
from pathlib import Path

from kata.screening_system.llm_review import (
    LlmCommandResult,
    parse_llm_review_json,
    review_suspicious_submission_with_llm,
)
from kata.screening_system.models import ScreeningDecision, ScreeningFinding


def review_finding() -> ScreeningFinding:
    return ScreeningFinding(
        rule_id="benchmark_replay.project_fingerprint_branch",
        severity="review",
        path="agent.py",
        line=4,
        reason="SN60 screening found benchmark-specific fingerprints.",
        evidence="matched_tokens=3; points=4",
    )


def test_llm_review_invokes_codex_and_adds_review_finding(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("KATA_SCREENING_LLM_REVIEW", "1")
    monkeypatch.setenv("KATA_SCREENING_LLM_ARTIFACT_DIR", str(tmp_path / "artifacts"))
    calls: list[tuple[list[str], str, int, Path]] = []

    def fake_runner(
        command: list[str],
        prompt: str,
        timeout_seconds: int,
        cwd: Path,
    ) -> LlmCommandResult:
        calls.append((command, prompt, timeout_seconds, cwd))
        return LlmCommandResult(
            returncode=0,
            stdout="",
            stderr="",
            last_message=json.dumps(
                {
                    "verdict": "suspicious",
                    "confidence": 0.82,
                    "evidence": [{"line": 4, "reason": "fingerprint branch"}],
                    "summary": "The branch looks benchmark-specific.",
                }
            ),
        )

    findings, notes = review_suspicious_submission_with_llm(
        submission_root=tmp_path,
        bundle_files={
            "agent.py": "def agent_main(project_dir=None, inference_api=None):\n"
            "    return {'vulnerabilities': []}\n"
        },
        decision=ScreeningDecision(status="review", review_reasons=[review_finding()]),
        runner=fake_runner,
    )

    assert len(calls) == 1
    command, prompt, timeout_seconds, cwd = calls[0]
    assert command[:4] == ["codex", "exec", "--model", "gpt-5.4"]
    assert "--sandbox" in command
    assert timeout_seconds == 180
    assert cwd == tmp_path.resolve()
    assert "Return JSON only" in prompt
    assert findings[0].rule_id == "llm_review.suspicious"
    assert findings[0].severity == "review"
    assert notes[0].rule_id == "llm_review.result"
    artifacts = list((tmp_path / "artifacts").glob("llm-review-*.json"))
    assert artifacts
    assert "artifact saved for maintainer audit" in notes[0].reason
    assert str(artifacts[0]) not in notes[0].reason


def test_llm_review_is_not_called_for_clean_decision(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("KATA_SCREENING_LLM_REVIEW", "1")

    def fail_runner(
        _command: list[str],
        _prompt: str,
        _timeout_seconds: int,
        _cwd: Path,
    ) -> LlmCommandResult:
        raise AssertionError("LLM runner must not be called for clean submissions")

    findings, notes = review_suspicious_submission_with_llm(
        submission_root=tmp_path,
        bundle_files={"agent.py": "def agent_main():\n    return {}\n"},
        decision=ScreeningDecision(status="pass"),
        runner=fail_runner,
    )

    assert findings == []
    assert notes == []


def test_llm_review_failure_adds_note_not_reject(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("KATA_SCREENING_LLM_REVIEW", "1")

    def failing_runner(
        _command: list[str],
        _prompt: str,
        _timeout_seconds: int,
        _cwd: Path,
    ) -> LlmCommandResult:
        return LlmCommandResult(
            returncode=1,
            stdout="",
            stderr="model unavailable",
            last_message="",
        )

    findings, notes = review_suspicious_submission_with_llm(
        submission_root=tmp_path,
        bundle_files={"agent.py": "def agent_main():\n    return {}\n"},
        decision=ScreeningDecision(status="review", review_reasons=[review_finding()]),
        runner=failing_runner,
    )

    assert findings == []
    assert notes[0].rule_id == "llm_review.result"
    assert "error" in notes[0].reason


def test_parse_llm_review_json_extracts_json_from_markdown() -> None:
    result = parse_llm_review_json(
        "```json\n"
        '{"verdict":"reject","confidence":1.2,"evidence":[{"line":0,"reason":"x"}],'
        '"summary":"confirmed"}\n'
        "```"
    )

    assert result.verdict == "reject"
    assert result.confidence == 1.0
    assert result.evidence[0].line is None
    assert result.summary == "confirmed"
