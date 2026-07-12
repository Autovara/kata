from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path

from kata.screening_system.benchmark_replay import (
    analyze_benchmark_replay,
    is_concrete_replay_finding,
)
from kata.screening_system.llm_review import review_suspicious_submission_with_llm
from kata.screening_system.models import (
    ScreeningDecision,
    ScreeningFinding,
    dedupe_findings,
)
from kata.screening_system.rules import (
    screen_bundle_python_sources,
    screen_bundle_static_policy,
    screen_sn60_static_bundle,
    screen_submission_bundle_files,
)
from kata.screening_system.similarity import screen_current_king_copycat
from kata.submission_system.bundle import load_bundle_files

STRICT_REPLAY_ENV = "KATA_SCREENING_STRICT_REPLAY"
REVIEW_MODE_ENV = "KATA_SCREENING_REVIEW_MODE"


def screen_submission(
    *,
    submission_root: Path,
    public_root: Path | None = None,
    mode: str = "miner",
    repo_pack: str | None = None,
    enable_review: bool | None = None,
    strict_replay: bool | None = None,
) -> ScreeningDecision:
    """Run the screening subsystem for a candidate submission.

    Wraps the SN60 static screening checks in a structured decision object.
    """
    if mode != "miner":
        return ScreeningDecision(status="pass")

    bundle_files = load_bundle_files(submission_root)
    reject_findings = []
    reject_findings.extend(screen_submission_bundle_files(submission_root))
    reject_findings.extend(screen_bundle_python_sources(bundle_files))
    reject_findings.extend(screen_bundle_static_policy(bundle_files))
    reject_findings.extend(screen_sn60_static_bundle(bundle_files))
    review_findings, review_score = analyze_benchmark_replay(bundle_files)
    copycat_rejects, copycat_reviews, copycat_score = screen_current_king_copycat(
        submission_root=submission_root,
        bundle_files=bundle_files,
        repo_pack=repo_pack,
        mode=mode,
        public_root=str(public_root) if public_root is not None else None,
    )
    reject_findings.extend(copycat_rejects)
    review_findings.extend(copycat_reviews)
    review_score += copycat_score
    notes: list[ScreeningFinding] = []
    if resolve_strict_replay(strict_replay):
        concrete_findings = [
            finding for finding in review_findings if is_concrete_replay_finding(finding)
        ]
        reject_findings.extend(promote_replay_findings(concrete_findings))
        review_findings = [
            finding for finding in review_findings if not is_concrete_replay_finding(finding)
        ]
    reject_findings = dedupe_findings(reject_findings)
    review_findings = dedupe_findings(review_findings)
    if reject_findings:
        return ScreeningDecision(
            status="reject",
            reject_reasons=reject_findings,
            review_reasons=review_findings,
            notes=notes,
            score=review_score,
        )
    llm_findings, llm_notes = review_suspicious_submission_with_llm(
        submission_root=submission_root,
        bundle_files=bundle_files,
        decision=ScreeningDecision(
            status="review" if review_findings else "pass",
            review_reasons=review_findings,
            score=review_score,
        ),
    )
    review_findings.extend(llm_findings)
    review_findings = dedupe_findings(review_findings)
    notes.extend(llm_notes)
    if review_findings and resolve_review_mode(enable_review):
        return ScreeningDecision(
            status="review",
            review_reasons=review_findings,
            notes=notes,
            score=review_score,
        )
    return ScreeningDecision(
        status="pass",
        review_reasons=review_findings,
        notes=notes,
        score=review_score,
    )


def resolve_strict_replay(value: bool | None) -> bool:
    if value is not None:
        return value
    raw = os.environ.get(STRICT_REPLAY_ENV, "")
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def resolve_review_mode(value: bool | None) -> bool:
    if value is not None:
        return value
    raw = os.environ.get(REVIEW_MODE_ENV, "")
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def promote_replay_findings(findings: list[ScreeningFinding]) -> list[ScreeningFinding]:
    return [
        replace(
            finding,
            severity="reject",
            reason=render_replay_rejection_reason(finding),
        )
        for finding in findings
    ]


def render_replay_rejection_reason(finding: ScreeningFinding) -> str:
    detail = finding.reason.strip()
    if detail.startswith("SN60 screening found "):
        detail = detail.removeprefix("SN60 screening found ").strip()
    if detail.startswith("SN60 screening "):
        detail = detail.removeprefix("SN60 screening ").strip()
    if not detail:
        detail = (
            "concrete benchmark-specific replay evidence was found "
            f"by `{finding.rule_id}`."
        )
    return (
        "SN60 screening rejected hardcoded benchmark replay: "
        f"{detail} Remove benchmark IDs, known finding IDs, copied finding "
        "titles/answers, and any prewritten benchmark-specific reports."
    )
