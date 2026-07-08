from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Literal

from kata.screening_system.models import ScreeningDecision, ScreeningFinding

LLM_REVIEW_ENV = "KATA_SCREENING_LLM_REVIEW"
LLM_MODEL_ENV = "KATA_SCREENING_LLM_MODEL"
LLM_CODEX_BIN_ENV = "KATA_SCREENING_LLM_CODEX_BIN"
LLM_TIMEOUT_ENV = "KATA_SCREENING_LLM_TIMEOUT_SECONDS"
LLM_ARTIFACT_DIR_ENV = "KATA_SCREENING_LLM_ARTIFACT_DIR"
DEFAULT_LLM_MODEL = "gpt-5.4"
DEFAULT_LLM_TIMEOUT_SECONDS = 180
MAX_LLM_SOURCE_CHARS_PER_FILE = 24_000
MAX_LLM_TOTAL_SOURCE_CHARS = 48_000

LlmVerdict = Literal["pass", "suspicious", "reject", "error"]
LlmRunner = Callable[[list[str], str, int, Path], "LlmCommandResult"]


@dataclass(frozen=True)
class LlmEvidence:
    line: int | None = None
    reason: str = ""


@dataclass(frozen=True)
class LlmReviewResult:
    verdict: LlmVerdict
    confidence: float
    summary: str
    evidence: list[LlmEvidence] = field(default_factory=list)
    model: str = DEFAULT_LLM_MODEL
    artifact_path: str | None = None
    error: str | None = None


@dataclass(frozen=True)
class LlmCommandResult:
    returncode: int
    stdout: str
    stderr: str
    last_message: str


def llm_review_enabled(value: bool | None = None) -> bool:
    if value is not None:
        return value
    return os.environ.get(LLM_REVIEW_ENV, "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def review_suspicious_submission_with_llm(
    *,
    submission_root: Path,
    bundle_files: dict[str, str],
    decision: ScreeningDecision,
    runner: LlmRunner | None = None,
    enabled: bool | None = None,
) -> tuple[list[ScreeningFinding], list[ScreeningFinding]]:
    """Return additional review findings and notes from optional LLM review.

    This is deliberately a second-stage review aid. It is never called for clean
    submissions and never converts a PR into a hard reject by itself.
    """
    if not llm_review_enabled(enabled) or not decision.review_reasons:
        return [], []
    result = run_codex_llm_review(
        submission_root=submission_root,
        bundle_files=bundle_files,
        decision=decision,
        runner=runner,
    )
    findings: list[ScreeningFinding] = []
    notes: list[ScreeningFinding] = []
    note = llm_review_note(result)
    if note is not None:
        notes.append(note)
    if result.verdict in {"suspicious", "reject"}:
        findings.append(llm_review_finding(result))
    return findings, notes


def run_codex_llm_review(
    *,
    submission_root: Path,
    bundle_files: dict[str, str],
    decision: ScreeningDecision,
    runner: LlmRunner | None = None,
) -> LlmReviewResult:
    model = os.environ.get(LLM_MODEL_ENV, DEFAULT_LLM_MODEL).strip() or DEFAULT_LLM_MODEL
    timeout_seconds = parse_timeout_seconds()
    prompt = build_llm_review_prompt(bundle_files=bundle_files, decision=decision)
    command = [
        os.environ.get(LLM_CODEX_BIN_ENV, "codex"),
        "exec",
        "--model",
        model,
        "--sandbox",
        "read-only",
        "--skip-git-repo-check",
        "--ephemeral",
        "--color",
        "never",
        "--output-last-message",
    ]
    with tempfile.NamedTemporaryFile("w+", suffix=".txt", encoding="utf-8") as output_file:
        command.extend([output_file.name, "-"])
        try:
            result = (runner or run_llm_command)(
                command,
                prompt,
                timeout_seconds,
                submission_root.expanduser().resolve(),
            )
        except Exception as exc:  # noqa: BLE001 - LLM review must not block screening.
            return record_llm_review_artifact(
                LlmReviewResult(
                    verdict="error",
                    confidence=0.0,
                    summary="LLM review failed before producing a verdict.",
                    model=model,
                    error=str(exc),
                ),
                prompt=prompt,
            )
    if result.returncode != 0:
        return record_llm_review_artifact(
            LlmReviewResult(
                verdict="error",
                confidence=0.0,
                summary="LLM review command failed.",
                model=model,
                error=(result.stderr or result.stdout).strip()[:500],
            ),
            prompt=prompt,
        )
    parsed = parse_llm_review_json(result.last_message or result.stdout)
    parsed_result = LlmReviewResult(
        verdict=parsed.verdict,
        confidence=parsed.confidence,
        summary=parsed.summary,
        evidence=parsed.evidence,
        model=model,
    )
    return record_llm_review_artifact(parsed_result, prompt=prompt)


def run_llm_command(
    command: list[str],
    prompt: str,
    timeout_seconds: int,
    cwd: Path,
) -> LlmCommandResult:
    completed = subprocess.run(
        command,
        input=prompt,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        check=False,
    )
    output_path = Path(command[-2])
    try:
        last_message = output_path.read_text(encoding="utf-8")
    except OSError:
        last_message = ""
    return LlmCommandResult(
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        last_message=last_message,
    )


def build_llm_review_prompt(
    *,
    bundle_files: dict[str, str],
    decision: ScreeningDecision,
) -> str:
    evidence = [
        {
            "rule_id": finding.rule_id,
            "path": finding.path,
            "line": finding.line,
            "reason": finding.reason,
            "evidence": finding.evidence,
        }
        for finding in decision.review_reasons
    ]
    sources = render_source_packet(bundle_files)
    return (
        "Review this Kata SN60 miner agent for screening integrity.\n\n"
        "Cheating means benchmark-specific hardcoded findings, exact project "
        "fingerprint replay, copied current-king logic, answer-key use, or "
        "bypassing real analysis by matching known benchmark signatures.\n\n"
        "Important rules:\n"
        "- Deterministic screening evidence is primary.\n"
        "- Do not reject weak but honest generic analysis.\n"
        "- A generic reusable detector is allowed even if it finds zero bugs.\n"
        "- Return JSON only; no markdown.\n\n"
        "Return this exact JSON shape:\n"
        "{\n"
        '  "verdict": "pass|suspicious|reject",\n'
        '  "confidence": 0.0,\n'
        '  "evidence": [{"line": 0, "reason": "..."}],\n'
        '  "summary": "..."\n'
        "}\n\n"
        "Deterministic screening evidence:\n"
        f"{json.dumps(evidence, indent=2)}\n\n"
        "Submitted source files:\n"
        f"{sources}\n"
    )


def render_source_packet(bundle_files: dict[str, str]) -> str:
    rendered: list[str] = []
    remaining = MAX_LLM_TOTAL_SOURCE_CHARS
    for relative_path, content in sorted(bundle_files.items()):
        if not relative_path.endswith(".py") or remaining <= 0:
            continue
        clipped = content[: min(len(content), MAX_LLM_SOURCE_CHARS_PER_FILE, remaining)]
        remaining -= len(clipped)
        suffix = "\n# [truncated]\n" if len(clipped) < len(content) else ""
        rendered.append(f"\n--- {relative_path} ---\n{clipped}{suffix}")
    return "\n".join(rendered)


def parse_llm_review_json(raw_output: str) -> LlmReviewResult:
    payload = parse_json_object(raw_output)
    verdict = str(payload.get("verdict") or "error").strip().lower()
    if verdict not in {"pass", "suspicious", "reject"}:
        verdict = "error"
    confidence = clamp_float(payload.get("confidence"), minimum=0.0, maximum=1.0)
    evidence_payload = payload.get("evidence") if isinstance(payload, dict) else []
    evidence: list[LlmEvidence] = []
    if isinstance(evidence_payload, list):
        for item in evidence_payload:
            if not isinstance(item, dict):
                continue
            evidence.append(
                LlmEvidence(
                    line=parse_line_number(item.get("line")),
                    reason=str(item.get("reason") or "").strip(),
                )
            )
    summary = str(payload.get("summary") or "").strip()
    return LlmReviewResult(
        verdict=verdict,  # type: ignore[arg-type]
        confidence=confidence,
        summary=summary or "LLM review produced no summary.",
        evidence=evidence,
    )


def parse_json_object(raw_output: str) -> dict[str, Any]:
    text = raw_output.strip()
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, flags=re.DOTALL)
        if match is None:
            return {
                "verdict": "error",
                "confidence": 0.0,
                "summary": "LLM review did not return JSON.",
                "evidence": [],
            }
        try:
            payload = json.loads(match.group(0))
        except json.JSONDecodeError:
            return {
                "verdict": "error",
                "confidence": 0.0,
                "summary": "LLM review returned malformed JSON.",
                "evidence": [],
            }
    return payload if isinstance(payload, dict) else {}


def llm_review_finding(result: LlmReviewResult) -> ScreeningFinding:
    summary = result.summary.strip()[:300]
    return ScreeningFinding(
        rule_id=f"llm_review.{result.verdict}",
        severity="review",
        path=None,
        line=None,
        reason=(
            "LLM review supports holding this submission for manual review: "
            f"{summary}"
        ),
        evidence=f"verdict={result.verdict}; confidence={result.confidence:.2f}",
    )


def llm_review_note(result: LlmReviewResult) -> ScreeningFinding | None:
    summary = result.summary.strip()[:300]
    if not summary:
        return None
    parts = [f"LLM review verdict `{result.verdict}` ({result.confidence:.2f})"]
    if result.artifact_path:
        parts.append("artifact saved for maintainer audit")
    if result.error:
        parts.append(f"error `{result.error[:160]}`")
    return ScreeningFinding(
        rule_id="llm_review.result",
        severity="note",
        path=None,
        line=None,
        reason=f"{'; '.join(parts)}: {summary}",
        evidence=f"model={result.model}",
    )


def record_llm_review_artifact(
    result: LlmReviewResult,
    *,
    prompt: str,
) -> LlmReviewResult:
    artifact_root = os.environ.get(LLM_ARTIFACT_DIR_ENV, "").strip()
    if not artifact_root:
        return result
    root = Path(artifact_root).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    path = root / f"llm-review-{timestamp}-{os.getpid()}.json"
    payload = {
        "schema_version": 1,
        "created_at": datetime.now(UTC).isoformat(),
        "result": {
            **asdict(result),
            "artifact_path": None,
        },
        "prompt": prompt,
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return LlmReviewResult(
        verdict=result.verdict,
        confidence=result.confidence,
        summary=result.summary,
        evidence=result.evidence,
        model=result.model,
        artifact_path=str(path),
        error=result.error,
    )


def parse_timeout_seconds() -> int:
    raw = os.environ.get(LLM_TIMEOUT_ENV, "").strip()
    if not raw:
        return DEFAULT_LLM_TIMEOUT_SECONDS
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_LLM_TIMEOUT_SECONDS
    return max(1, value)


def parse_line_number(value: object) -> int | None:
    try:
        line = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    return line if line > 0 else None


def clamp_float(value: object, *, minimum: float, maximum: float) -> float:
    try:
        number = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return minimum
    return max(minimum, min(maximum, number))
