from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class SubmissionMetadata:
    schema_version: int
    repo_pack: str
    mode: str
    submission_id: str
    created_at: str
    author: str | None = None
    title: str | None = None
    notes: str | None = None


@dataclass(frozen=True)
class SubmissionDescriptor:
    root: Path
    repo_pack: str
    mode: str
    submission_id: str
    agent_path: Path
    agent_manifest_path: Path
    metadata_path: Path


@dataclass(frozen=True)
class SubmissionValidationResult:
    submission_path: str
    repo_pack: str | None
    mode: str | None
    submission_id: str | None
    agent_path: str | None
    metadata_path: str | None
    changed_paths: list[str]
    off_scope_paths: list[str]
    reasons: list[str]
    metadata: SubmissionMetadata | None
    evaluator_id: str | None = None
    screening_status: str | None = None
    screening_review_reasons: list[str] = field(default_factory=list)
    screening_notes: list[str] = field(default_factory=list)
    screening_score: int = 0

    @property
    def is_valid(self) -> bool:
        return not self.reasons and not self.off_scope_paths


@dataclass(frozen=True)
class SubmissionCandidateValidation:
    reasons: list[str] = field(default_factory=list)
    screening_status: str | None = None
    screening_review_reasons: list[str] = field(default_factory=list)
    screening_notes: list[str] = field(default_factory=list)
    screening_score: int = 0


@dataclass(frozen=True)
class SubmissionVerificationResult:
    submission_path: str
    challenge_summary_path: str
    repo_pack: str
    mode: str
    submission_id: str
    candidate_artifact_hash: str
    recorded_candidate_artifact_hash: str
    current_king_artifact_hash: str
    recorded_king_artifact_hash: str
    current_validator_model: str
    recorded_validator_model: str
    submission_matches_challenge: bool
    king_is_current: bool
    benchmark_is_current: bool
    promotion_ready: bool
    auto_merge_ready: bool
    reasons: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class PullRequestInspectionResult:
    action: str
    submission_path: str | None
    repo_pack: str | None
    mode: str | None
    submission_id: str | None
    changed_paths: list[str]
    reasons: list[str]
    candidate_submission_dirs: list[str]


@dataclass(frozen=True)
class SubmissionDecisionResult:
    action: str
    submission_path: str
    challenge_summary_path: str
    repo_pack: str
    mode: str
    submission_id: str
    reason: str
    reasons: list[str]
    promotion_ready: bool
    auto_merge_ready: bool


@dataclass(frozen=True)
class ChangedPathValidation:
    off_scope_paths: list[str]
    reasons: list[str]
