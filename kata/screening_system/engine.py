from __future__ import annotations

from pathlib import Path

from kata.agent_bundle import load_bundle_files
from kata.screening import validate_sn60_static_screening
from kata.screening_system.benchmark_replay import analyze_benchmark_replay
from kata.screening_system.models import ScreeningDecision, ScreeningFinding


def screen_submission(
    *,
    submission_root: Path,
    changed_paths: list[str] | None = None,
    repo_root: Path | None = None,
    public_root: Path | None = None,
    pr_author: str | None = None,
    mode: str = "miner",
    enable_review: bool = False,
) -> ScreeningDecision:
    """Run the screening subsystem for a candidate submission.

    Wrap the SN60 static screening checks in a structured decision object. The
    extra arguments are part of the stable subsystem API and can be used by later
    layers.
    """
    del changed_paths, repo_root, public_root, pr_author
    if mode != "miner":
        return ScreeningDecision(status="pass")

    reject_findings = [
        ScreeningFinding(
            rule_id="sn60.static",
            severity="reject",
            path="agent.py",
            line=None,
            reason=reason,
            evidence=reason,
        )
        for reason in validate_sn60_static_screening(submission_root)
    ]
    bundle_files = load_bundle_files(submission_root)
    review_findings, review_score = analyze_benchmark_replay(bundle_files)
    if reject_findings:
        return ScreeningDecision(
            status="reject",
            reject_reasons=reject_findings,
            review_reasons=review_findings,
            score=review_score,
        )
    if review_findings and enable_review:
        return ScreeningDecision(
            status="review",
            review_reasons=review_findings,
            score=review_score,
        )
    return ScreeningDecision(
        status="pass",
        review_reasons=review_findings,
        score=review_score,
    )
