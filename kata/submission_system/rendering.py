from __future__ import annotations

import json
from dataclasses import asdict

from kata.submission_system.models import (
    PullRequestInspectionResult,
    SubmissionDecisionResult,
    SubmissionValidationResult,
    SubmissionVerificationResult,
)


def render_submission_validation(result: SubmissionValidationResult) -> str:
    lines: list[str] = []
    lines.append(f"Submission: {result.submission_path}")
    if result.repo_pack:
        lines.append(f"Subnet pack: {result.repo_pack}")
    if result.mode:
        lines.append(f"Mode: {result.mode}")
    if result.submission_id:
        lines.append(f"Submission id: {result.submission_id}")
    if result.agent_path:
        lines.append(f"Agent file: {result.agent_path}")
    lines.append(f"Status: {'valid' if result.is_valid else 'invalid'}")
    if result.changed_paths:
        lines.append("Changed paths:")
        lines.extend(f"- {path}" for path in result.changed_paths)
    if result.off_scope_paths:
        lines.append("Off-scope paths:")
        lines.extend(f"- {path}" for path in result.off_scope_paths)
    if result.reasons:
        lines.append("Reasons:")
        lines.extend(f"- {reason}" for reason in result.reasons)
    if result.screening_status:
        lines.append(f"Screening status: {result.screening_status}")
    if result.screening_review_reasons:
        lines.append("Screening review reasons:")
        lines.extend(f"- {reason}" for reason in result.screening_review_reasons)
    if result.screening_notes:
        lines.append("Screening notes:")
        lines.extend(f"- {note}" for note in result.screening_notes)
    return "\n".join(lines)


def render_pull_request_inspection(result: PullRequestInspectionResult) -> str:
    lines = [
        f"Action: {result.action}",
        f"Changed paths: {len(result.changed_paths)}",
    ]
    if result.submission_path:
        lines.append(f"Submission path: {result.submission_path}")
    if result.candidate_submission_dirs:
        lines.append("Candidate submission dirs:")
        lines.extend(f"- {path}" for path in result.candidate_submission_dirs)
    if result.reasons:
        lines.append("Reasons:")
        lines.extend(f"- {reason}" for reason in result.reasons)
    return "\n".join(lines)


def render_submission_verification(result: SubmissionVerificationResult) -> str:
    lines: list[str] = []
    lines.append(f"Submission: {result.submission_path}")
    lines.append(f"Challenge summary: {result.challenge_summary_path}")
    lines.append(f"Subnet pack: {result.repo_pack}")
    lines.append(f"Mode: {result.mode}")
    lines.append(f"Submission id: {result.submission_id}")
    lines.append(
        "Submission matches challenge: " + ("yes" if result.submission_matches_challenge else "no")
    )
    lines.append(f"King is current: {'yes' if result.king_is_current else 'no'}")
    lines.append(f"Benchmark lane is current: {'yes' if result.benchmark_is_current else 'no'}")
    lines.append(f"Promotion ready: {'yes' if result.promotion_ready else 'no'}")
    lines.append(f"Auto-merge ready: {'yes' if result.auto_merge_ready else 'no'}")
    if result.reasons:
        lines.append("Reasons:")
        lines.extend(f"- {reason}" for reason in result.reasons)
    return "\n".join(lines)


def render_submission_decision(result: SubmissionDecisionResult) -> str:
    lines = [
        f"Action: {result.action}",
        f"Submission: {result.submission_path}",
        f"Challenge summary: {result.challenge_summary_path}",
        f"Reason: {result.reason}",
        f"Promotion ready: {'yes' if result.promotion_ready else 'no'}",
        f"Auto-merge ready: {'yes' if result.auto_merge_ready else 'no'}",
    ]
    if result.reasons:
        lines.append("Reasons:")
        lines.extend(f"- {reason}" for reason in result.reasons)
    return "\n".join(lines)


def render_submission_json(
    value: SubmissionValidationResult
    | SubmissionVerificationResult
    | PullRequestInspectionResult
    | SubmissionDecisionResult,
) -> str:
    payload = asdict(value)
    if payload.get("repo_pack") is not None:
        payload["subnet_pack"] = payload["repo_pack"]
    metadata = payload.get("metadata")
    if isinstance(metadata, dict):
        if metadata.get("repo_pack") is not None:
            metadata["subnet_pack"] = metadata["repo_pack"]
        payload["metadata"] = metadata
    return json.dumps(payload, indent=2) + "\n"
