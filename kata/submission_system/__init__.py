from kata.submission_system.constants import (
    DEFAULT_AGENT_PLACEHOLDER,
    PR_ACTION_CLOSE_INVALID,
    PR_ACTION_CLOSE_LOSING,
    PR_ACTION_EVALUATE,
    PR_ACTION_MERGE,
    PR_ACTION_RERUN_STALE,
    SUBMISSION_AGENT_FILENAME,
    SUBMISSION_AGENT_MANIFEST_FILENAME,
    SUBMISSION_ID_CONVENTION,
    SUBMISSION_METADATA_FILENAME,
    SUBMISSION_SCHEMA_VERSION,
    SUBMISSIONS_DIRNAME,
    SUPPORTED_SUBMISSION_MODES,
    TOP_LEVEL_SUBMISSION_FILENAMES,
)
from kata.submission_system.layout import (
    agent_defines_required_entrypoint,
    default_submission_agent,
    default_submission_notes,
    default_submissions_root,
    infer_submission_dirs,
    load_submission_metadata,
    normalize_changed_paths,
    read_changed_paths_file,
    read_submission_subnet_pack,
    required_submission_entrypoint_reason,
    resolve_submission_descriptor,
    validate_submission_mode,
    write_submission_metadata,
)
from kata.submission_system.models import (
    ChangedPathValidation,
    PullRequestInspectionResult,
    SubmissionCandidateValidation,
    SubmissionDecisionResult,
    SubmissionDescriptor,
    SubmissionMetadata,
    SubmissionValidationResult,
    SubmissionVerificationResult,
)
from kata.submission_system.rendering import (
    render_pull_request_inspection,
    render_submission_decision,
    render_submission_json,
    render_submission_validation,
    render_submission_verification,
)

_WORKFLOW_EXPORTS = {
    "decide_submission_action",
    "evaluate_submission",
    "init_submission",
    "inspect_pull_request",
    "is_sn60_miner_metadata",
    "promote_submission_result",
    "sn60_lane_benchmark_is_current",
    "validate_submission",
    "validate_submission_target",
    "verify_submission_result",
}

_VALIDATION_EXPORTS = {
    "render_screening_finding",
    "validate_changed_paths",
    "validate_submission_candidate",
    "validate_submission_metadata",
}


def __getattr__(name: str):
    if name in _WORKFLOW_EXPORTS:
        from kata.submission_system import workflow

        return getattr(workflow, name)
    if name in _VALIDATION_EXPORTS:
        from kata.submission_system import validation

        return getattr(validation, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = [
    "DEFAULT_AGENT_PLACEHOLDER",
    "PR_ACTION_CLOSE_INVALID",
    "PR_ACTION_CLOSE_LOSING",
    "PR_ACTION_EVALUATE",
    "PR_ACTION_MERGE",
    "PR_ACTION_RERUN_STALE",
    "SUBMISSION_AGENT_FILENAME",
    "SUBMISSION_AGENT_MANIFEST_FILENAME",
    "SUBMISSION_ID_CONVENTION",
    "SUBMISSION_METADATA_FILENAME",
    "SUBMISSION_SCHEMA_VERSION",
    "SUBMISSIONS_DIRNAME",
    "SUPPORTED_SUBMISSION_MODES",
    "TOP_LEVEL_SUBMISSION_FILENAMES",
    "ChangedPathValidation",
    "PullRequestInspectionResult",
    "SubmissionCandidateValidation",
    "SubmissionDecisionResult",
    "SubmissionDescriptor",
    "SubmissionMetadata",
    "SubmissionValidationResult",
    "SubmissionVerificationResult",
    "agent_defines_required_entrypoint",
    "default_submission_agent",
    "default_submission_notes",
    "default_submissions_root",
    "decide_submission_action",
    "evaluate_submission",
    "infer_submission_dirs",
    "init_submission",
    "inspect_pull_request",
    "is_sn60_miner_metadata",
    "load_submission_metadata",
    "normalize_changed_paths",
    "promote_submission_result",
    "read_changed_paths_file",
    "read_submission_subnet_pack",
    "render_pull_request_inspection",
    "render_screening_finding",
    "render_submission_decision",
    "render_submission_json",
    "render_submission_validation",
    "render_submission_verification",
    "required_submission_entrypoint_reason",
    "resolve_submission_descriptor",
    "sn60_lane_benchmark_is_current",
    "validate_changed_paths",
    "validate_submission",
    "validate_submission_candidate",
    "validate_submission_metadata",
    "validate_submission_mode",
    "validate_submission_target",
    "verify_submission_result",
    "write_submission_metadata",
]
