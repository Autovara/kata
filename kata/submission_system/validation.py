from __future__ import annotations

from pathlib import Path

from kata.screening_system.engine import screen_submission
from kata.screening_system.models import ScreeningFinding
from kata.screening_system.rules import (
    validate_bundle_python_sources,
    validate_bundle_static_policy,
)
from kata.submission_system.bundle import (
    is_allowed_bundle_relative_path,
    load_bundle_files,
)
from kata.submission_system.constants import (
    SUBMISSION_SCHEMA_VERSION,
    SUBMISSIONS_DIRNAME,
    TOP_LEVEL_SUBMISSION_FILENAMES,
)
from kata.submission_system.models import (
    ChangedPathValidation,
    SubmissionCandidateValidation,
    SubmissionDescriptor,
    SubmissionMetadata,
)
from kata.util import dedupe


def validate_changed_paths(
    descriptor: SubmissionDescriptor,
    changed_paths: list[str],
) -> ChangedPathValidation:
    expected_prefix = (
        Path(SUBMISSIONS_DIRNAME)
        / descriptor.repo_pack
        / descriptor.mode
        / descriptor.submission_id
    ).as_posix() + "/"
    off_scope_paths: list[str] = []
    reasons: list[str] = []
    touched_bundle_file = False

    for changed_path in changed_paths:
        normalized = changed_path.strip("/")
        if not normalized.startswith(expected_prefix):
            off_scope_paths.append(normalized)
            continue
        relative_name = normalized.removeprefix(expected_prefix)
        if (
            "/" not in relative_name and relative_name in TOP_LEVEL_SUBMISSION_FILENAMES
        ) or is_allowed_bundle_relative_path(relative_name):
            if is_allowed_bundle_relative_path(relative_name):
                touched_bundle_file = True
            continue
        off_scope_paths.append(normalized)

    if off_scope_paths:
        reasons.append("Submission PR touches paths outside the allowed submission scope.")
    if not touched_bundle_file:
        reasons.append("Submission PR must modify at least one agent bundle file.")

    return ChangedPathValidation(
        off_scope_paths=off_scope_paths,
        reasons=reasons,
    )


def validate_submission_metadata(
    metadata: SubmissionMetadata,
    descriptor: SubmissionDescriptor,
) -> list[str]:
    reasons: list[str] = []
    if metadata.schema_version != SUBMISSION_SCHEMA_VERSION:
        reasons.append(
            "Unsupported submission schema version: "
            f"{metadata.schema_version}. Expected {SUBMISSION_SCHEMA_VERSION}."
        )
    if metadata.repo_pack != descriptor.repo_pack:
        reasons.append("submission.json subnet_pack does not match the submission path.")
    if metadata.mode != descriptor.mode:
        reasons.append("submission.json mode does not match the submission path.")
    if metadata.submission_id != descriptor.submission_id:
        reasons.append("submission.json submission_id does not match the submission path.")
    return reasons


def validate_submission_candidate(
    *,
    metadata: SubmissionMetadata,
    submission_root: Path,
    public_root: str | None = None,
) -> SubmissionCandidateValidation:
    screening_status: str | None = None
    screening_review_reasons: list[str] = []
    screening_notes: list[str] = []
    screening_score = 0
    if metadata.mode == "miner":
        screening_decision = screen_submission(
            submission_root=submission_root,
            public_root=Path(public_root).expanduser().resolve() if public_root else None,
            mode=metadata.mode,
            repo_pack=metadata.repo_pack,
        )
        screening_status = screening_decision.status
        screening_review_reasons = [
            render_screening_finding(finding) for finding in screening_decision.review_reasons
        ]
        screening_notes = [
            render_screening_finding(finding) for finding in screening_decision.notes
        ]
        screening_score = screening_decision.score
        reasons = [
            render_screening_finding(finding)
            for finding in screening_decision.reject_reasons
        ]
    else:
        bundle_files = load_bundle_files(submission_root)
        reasons = [
            *validate_bundle_python_sources(bundle_files),
            *validate_bundle_static_policy(bundle_files),
        ]
    return SubmissionCandidateValidation(
        reasons=dedupe(reasons),
        screening_status=screening_status,
        screening_review_reasons=dedupe(screening_review_reasons),
        screening_notes=dedupe(screening_notes),
        screening_score=screening_score,
    )


def render_screening_finding(finding: ScreeningFinding) -> str:
    location = ""
    if finding.path:
        location = finding.path
        if finding.line is not None:
            location += f":{finding.line}"
        location += ": "
    return f"{location}{finding.reason}"
