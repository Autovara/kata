from __future__ import annotations

import ast
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from kata.agent_bundle import (
    AGENT_ENTRY_FILENAME,
    AGENT_MANIFEST_FILENAME,
    find_unexpected_bundle_paths,
    is_allowed_bundle_relative_path,
    load_bundle_files,
    validate_agent_manifest,
    write_agent_manifest,
)
from kata.benchmarks import ensure_active_repo_pack, resolve_eval_pack_path
from kata.challenge import (
    ChallengeSummary,
    load_challenge_summary,
    run_frontier_challenge,
)
from kata.config import resolve_validator_model
from kata.frontier import (
    load_frontier_manifest,
    resolve_baseline_artifact_hash,
    resolve_frontier_artifact_hash,
)
from kata.provenance import sha256_directory

SUBMISSIONS_DIRNAME = "submissions"
SUBMISSION_SCHEMA_VERSION = 2
SUBMISSION_METADATA_FILENAME = "submission.json"
SUBMISSION_AGENT_FILENAME = AGENT_ENTRY_FILENAME
SUBMISSION_AGENT_MANIFEST_FILENAME = AGENT_MANIFEST_FILENAME
TOP_LEVEL_SUBMISSION_FILENAMES = {
    SUBMISSION_METADATA_FILENAME,
    SUBMISSION_AGENT_FILENAME,
    SUBMISSION_AGENT_MANIFEST_FILENAME,
}
SUPPORTED_SUBMISSION_MODES = {"contributor", "reviewer"}
DEFAULT_AGENT_PLACEHOLDER = (
    "Replace this scaffold with a real challenger agent implementation before opening a PR."
)
SUBMISSION_ID_CONVENTION = "<github-username>-YYYYMMDD-NN"
PR_ACTION_CLOSE_INVALID = "close-invalid"
PR_ACTION_EVALUATE = "evaluate"
PR_ACTION_CLOSE_LOSING = "close-losing"
PR_ACTION_RERUN_STALE = "rerun-stale"
PR_ACTION_MERGE = "merge"
MAX_SUBMISSION_BUNDLE_FILES = 16
MAX_SUBMISSION_FILE_BYTES = 64 * 1024
MAX_SUBMISSION_BUNDLE_BYTES = 128 * 1024
FORBIDDEN_ENV_REFERENCE_TOKENS = (
    "KATA_VALIDATOR_API_KEY",
    "KATA_VALIDATOR_API_BASE",
    "KATA_VALIDATOR_MODEL",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GOOGLE_API_KEY",
    "OPENROUTER_API_KEY",
)
SECRET_PATTERN = re.compile(r"(sk-[A-Za-z0-9]{10,}|ghp_[A-Za-z0-9]{10,}|hf_[A-Za-z0-9]{10,})")


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

    @property
    def is_valid(self) -> bool:
        return not self.reasons and not self.off_scope_paths


@dataclass(frozen=True)
class SubmissionVerificationResult:
    submission_path: str
    challenge_summary_path: str
    repo_pack: str
    mode: str
    submission_id: str
    candidate_artifact_hash: str
    recorded_candidate_artifact_hash: str
    current_frontier_artifact_hash: str
    recorded_frontier_artifact_hash: str
    current_validator_model: str
    recorded_validator_model: str
    submission_matches_challenge: bool
    frontier_is_current: bool
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


def init_submission(
    *,
    repo_pack: str,
    mode: str,
    submission_id: str,
    output_root: str | None = None,
    author: str | None = None,
    title: str | None = None,
    notes: str | None = None,
) -> Path:
    validate_submission_mode(mode)
    lane_reasons = validate_submission_lane(repo_pack, mode)
    if lane_reasons:
        raise ValueError("; ".join(lane_reasons))
    effective_author = author.strip() if author and author.strip() else None
    root_base = (
        Path(output_root).expanduser().resolve()
        if output_root
        else default_submissions_root()
    )
    submission_root = root_base / repo_pack / mode / submission_id
    submission_root.mkdir(parents=True, exist_ok=False)
    metadata = SubmissionMetadata(
        schema_version=SUBMISSION_SCHEMA_VERSION,
        repo_pack=repo_pack,
        mode=mode,
        submission_id=submission_id,
        created_at=datetime.now(UTC).isoformat(),
        author=effective_author,
        title=title,
        notes=notes or default_submission_notes(),
    )
    write_submission_metadata(submission_root / SUBMISSION_METADATA_FILENAME, metadata)
    write_agent_manifest(submission_root / SUBMISSION_AGENT_MANIFEST_FILENAME)
    agent_path = submission_root / SUBMISSION_AGENT_FILENAME
    agent_path.write_text(default_submission_agent(mode), encoding="utf-8")
    return submission_root


def validate_submission(
    submission_path: str,
    *,
    changed_paths: list[str] | None = None,
    repo_root: str | None = None,
) -> SubmissionValidationResult:
    reasons: list[str] = []
    off_scope_paths: list[str] = []
    metadata: SubmissionMetadata | None = None

    resolved_repo_root = Path(repo_root).expanduser().resolve() if repo_root else None
    root = Path(submission_path).expanduser().resolve()
    descriptor, descriptor_errors = resolve_submission_descriptor(
        root,
        repo_root=resolved_repo_root,
    )
    reasons.extend(descriptor_errors)
    normalized_changed = normalize_changed_paths(changed_paths or [])

    if descriptor is None:
        return SubmissionValidationResult(
            submission_path=str(root),
            repo_pack=None,
            mode=None,
            submission_id=None,
            agent_path=None,
            metadata_path=None,
            changed_paths=normalized_changed,
            off_scope_paths=[],
            reasons=reasons,
            metadata=None,
        )

    metadata_path = descriptor.metadata_path
    agent_path = descriptor.agent_path
    agent_manifest_path = descriptor.agent_manifest_path

    if normalized_changed:
        changed_scope = validate_changed_paths(descriptor, normalized_changed)
        off_scope_paths.extend(changed_scope.off_scope_paths)
        reasons.extend(changed_scope.reasons)

    if not metadata_path.exists():
        reasons.append(f"Missing required submission file: {metadata_path.name}")
    else:
        try:
            metadata = load_submission_metadata(metadata_path)
        except (ValueError, json.JSONDecodeError) as exc:
            reasons.append(str(exc))

    if not agent_path.exists():
        reasons.append(f"Missing required submission file: {agent_path.name}")
    else:
        agent_text = agent_path.read_text(encoding="utf-8").strip()
        if not agent_text:
            reasons.append("Submission agent file is empty.")
        elif DEFAULT_AGENT_PLACEHOLDER in agent_text:
            reasons.append("Submission agent still contains scaffold placeholder text.")
        if "def solve(" not in agent_text:
            reasons.append("Submission agent must define solve(...).")

    if not agent_manifest_path.exists():
        reasons.append(f"Missing required submission file: {agent_manifest_path.name}")
    else:
        reasons.extend(validate_agent_manifest(agent_manifest_path))

    if metadata is not None:
        reasons.extend(validate_submission_metadata(metadata, descriptor))
        reasons.extend(validate_submission_target(metadata))
        if agent_path.exists():
            reasons.extend(
                validate_submission_candidate(
                    metadata=metadata,
                    submission_root=descriptor.root,
                )
            )

    return SubmissionValidationResult(
        submission_path=str(descriptor.root),
        repo_pack=descriptor.repo_pack,
        mode=descriptor.mode,
        submission_id=descriptor.submission_id,
        agent_path=str(agent_path),
        metadata_path=str(metadata_path),
        changed_paths=normalized_changed,
        off_scope_paths=off_scope_paths,
        reasons=dedupe(reasons),
        metadata=metadata,
    )


def evaluate_submission(
    submission_path: str,
    *,
    agent_command: str,
    output_root: str | None = None,
    agent_timeout_seconds: int | None = None,
    checks_timeout_seconds: int | None = None,
) -> ChallengeSummary:
    validation = validate_submission(submission_path)
    if (
        not validation.is_valid
        or validation.metadata is None
        or validation.agent_path is None
    ):
        raise ValueError(
            "Submission is invalid. Run `kata submission validate` first. "
            + "; ".join(validation.reasons or ["unknown validation failure"])
        )

    return run_frontier_challenge(
        eval_pack_path=validation.metadata.repo_pack,
        mode=validation.metadata.mode,
        candidate_artifact_path=validation.submission_path,
        agent_command=agent_command,
        output_root=output_root,
        agent_timeout_seconds=agent_timeout_seconds,
        checks_timeout_seconds=checks_timeout_seconds,
    )


def inspect_pull_request(
    *,
    repo_root: str,
    changed_paths: list[str],
) -> PullRequestInspectionResult:
    resolved_repo_root = Path(repo_root).expanduser().resolve()
    normalized_changed = normalize_changed_paths(changed_paths)
    candidate_dirs = infer_submission_dirs(normalized_changed)
    reasons: list[str] = []

    if not normalized_changed:
        reasons.append("PR does not contain any changed files.")
        return PullRequestInspectionResult(
            action=PR_ACTION_CLOSE_INVALID,
            submission_path=None,
            repo_pack=None,
            mode=None,
            submission_id=None,
            changed_paths=[],
            reasons=reasons,
            candidate_submission_dirs=[],
        )

    if not candidate_dirs:
        reasons.append(
            "PR does not contain an agent submission under "
            "`submissions/<repo-pack>/<mode>/<submission-id>`."
        )
        return PullRequestInspectionResult(
            action=PR_ACTION_CLOSE_INVALID,
            submission_path=None,
            repo_pack=None,
            mode=None,
            submission_id=None,
            changed_paths=normalized_changed,
            reasons=reasons,
            candidate_submission_dirs=[],
        )

    if len(candidate_dirs) > 1:
        reasons.append("PR touches multiple submission directories. Submit exactly one challenger.")
        return PullRequestInspectionResult(
            action=PR_ACTION_CLOSE_INVALID,
            submission_path=None,
            repo_pack=None,
            mode=None,
            submission_id=None,
            changed_paths=normalized_changed,
            reasons=reasons,
            candidate_submission_dirs=candidate_dirs,
        )

    relative_dir = candidate_dirs[0]
    descriptor, descriptor_errors = resolve_submission_descriptor(
        resolved_repo_root / relative_dir,
        repo_root=resolved_repo_root,
        require_exists=False,
    )
    reasons.extend(descriptor_errors)
    if descriptor is None:
        return PullRequestInspectionResult(
            action=PR_ACTION_CLOSE_INVALID,
            submission_path=None,
            repo_pack=None,
            mode=None,
            submission_id=None,
            changed_paths=normalized_changed,
            reasons=dedupe(reasons),
            candidate_submission_dirs=candidate_dirs,
        )

    changed_scope = validate_changed_paths(descriptor, normalized_changed)
    reasons.extend(changed_scope.reasons)
    if changed_scope.off_scope_paths:
        reasons.append(
            "PR changes files outside the allowed submission directory or adds unsupported files."
        )
    reasons.extend(validate_submission_lane(descriptor.repo_pack, descriptor.mode))

    action = PR_ACTION_EVALUATE if not reasons else PR_ACTION_CLOSE_INVALID
    return PullRequestInspectionResult(
        action=action,
        submission_path=str((resolved_repo_root / relative_dir).resolve()),
        repo_pack=descriptor.repo_pack,
        mode=descriptor.mode,
        submission_id=descriptor.submission_id,
        changed_paths=normalized_changed,
        reasons=dedupe(reasons),
        candidate_submission_dirs=candidate_dirs,
    )


def verify_submission_result(
    submission_path: str,
    challenge_summary_path: str,
) -> SubmissionVerificationResult:
    validation = validate_submission(submission_path)
    if (
        not validation.is_valid
        or validation.metadata is None
        or validation.agent_path is None
    ):
        raise ValueError(
            "Submission is invalid. Run `kata submission validate` first. "
            + "; ".join(validation.reasons or ["unknown validation failure"])
        )

    summary = load_challenge_summary(challenge_summary_path)
    manifest = load_frontier_manifest(validation.metadata.repo_pack)
    mode_config = manifest.modes.get(validation.metadata.mode)
    if mode_config is None:
        raise ValueError(
            f"Mode is not configured in frontier manifest: {validation.metadata.mode}"
        )

    candidate_hash = hash_submission_bundle(Path(validation.submission_path))
    current_frontier_hash = resolve_frontier_artifact_hash(mode_config)
    current_validator_model = resolve_validator_model()

    expected_manifest_path = (
        resolve_eval_pack_path(validation.metadata.repo_pack) / "frontier.json"
    ).resolve()
    submission_matches = (
        summary.mode == validation.metadata.mode
        and summary.candidate_artifact_hash == candidate_hash
        and Path(summary.manifest_path).resolve() == expected_manifest_path
    )
    frontier_is_current = summary.frontier_artifact_hash == current_frontier_hash
    benchmark_is_current = (
        summary.evaluator_version == (mode_config.evaluator_version or summary.evaluator_version)
        and summary.validator_model == current_validator_model
        and summary.primary_pool_fingerprint == mode_config.primary_pool_fingerprint
        and summary.holdout_pool_fingerprint == mode_config.holdout_pool_fingerprint
    )

    reasons: list[str] = []
    if not submission_matches:
        reasons.append("Challenge result does not match the current submission payload.")
    if not frontier_is_current:
        reasons.append("Challenge result is stale because the frontier artifact has changed.")
    if summary.validator_model != current_validator_model:
        reasons.append("Challenge result is stale because the validator model has changed.")
    elif not benchmark_is_current:
        reasons.append("Challenge result is stale because the benchmark lane has changed.")
    if not summary.promotion_ready:
        reasons.append(f"Challenge is not promotion-ready: {summary.promotion_reason}")

    return SubmissionVerificationResult(
        submission_path=validation.submission_path,
        challenge_summary_path=str(Path(challenge_summary_path).expanduser().resolve()),
        repo_pack=validation.metadata.repo_pack,
        mode=validation.metadata.mode,
        submission_id=validation.metadata.submission_id,
        candidate_artifact_hash=candidate_hash,
        recorded_candidate_artifact_hash=summary.candidate_artifact_hash,
        current_frontier_artifact_hash=current_frontier_hash,
        recorded_frontier_artifact_hash=summary.frontier_artifact_hash,
        current_validator_model=current_validator_model,
        recorded_validator_model=summary.validator_model,
        submission_matches_challenge=submission_matches,
        frontier_is_current=frontier_is_current,
        benchmark_is_current=benchmark_is_current,
        promotion_ready=summary.promotion_ready,
        auto_merge_ready=submission_matches
        and frontier_is_current
        and benchmark_is_current
        and summary.promotion_ready,
        reasons=reasons,
    )


def decide_submission_action(
    submission_path: str,
    challenge_summary_path: str,
) -> SubmissionDecisionResult:
    validation = validate_submission(submission_path)
    if not validation.is_valid or validation.metadata is None:
        reasons = validation.reasons or ["Submission is invalid."]
        return SubmissionDecisionResult(
            action=PR_ACTION_CLOSE_INVALID,
            submission_path=validation.submission_path,
            challenge_summary_path=str(Path(challenge_summary_path).expanduser().resolve()),
            repo_pack=validation.repo_pack or "unknown",
            mode=validation.mode or "unknown",
            submission_id=validation.submission_id or "unknown",
            reason="Submission is invalid and should be auto-closed.",
            reasons=reasons,
            promotion_ready=False,
            auto_merge_ready=False,
        )

    verification = verify_submission_result(submission_path, challenge_summary_path)
    if verification.auto_merge_ready:
        return SubmissionDecisionResult(
            action=PR_ACTION_MERGE,
            submission_path=verification.submission_path,
            challenge_summary_path=verification.challenge_summary_path,
            repo_pack=verification.repo_pack,
            mode=verification.mode,
            submission_id=verification.submission_id,
            reason="Submission beat the current frontier and is safe to auto-merge.",
            reasons=[],
            promotion_ready=verification.promotion_ready,
            auto_merge_ready=verification.auto_merge_ready,
        )

    stale_reasons = [
        reason
        for reason in verification.reasons
        if "stale" in reason or "does not match" in reason
    ]
    if stale_reasons:
        return SubmissionDecisionResult(
            action=PR_ACTION_RERUN_STALE,
            submission_path=verification.submission_path,
            challenge_summary_path=verification.challenge_summary_path,
            repo_pack=verification.repo_pack,
            mode=verification.mode,
            submission_id=verification.submission_id,
            reason="Submission result is stale and must be rerun against the current frontier.",
            reasons=stale_reasons,
            promotion_ready=verification.promotion_ready,
            auto_merge_ready=False,
        )

    losing_reasons = verification.reasons or [
        "Submission did not satisfy the promotion rule against the current frontier."
    ]
    return SubmissionDecisionResult(
        action=PR_ACTION_CLOSE_LOSING,
        submission_path=verification.submission_path,
        challenge_summary_path=verification.challenge_summary_path,
        repo_pack=verification.repo_pack,
        mode=verification.mode,
        submission_id=verification.submission_id,
        reason="Submission lost to the current frontier and should be auto-closed.",
        reasons=losing_reasons,
        promotion_ready=verification.promotion_ready,
        auto_merge_ready=False,
    )


def render_submission_validation(result: SubmissionValidationResult) -> str:
    lines: list[str] = []
    lines.append(f"Submission: {result.submission_path}")
    if result.repo_pack:
        lines.append(f"Repo pack: {result.repo_pack}")
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
    lines.append(f"Repo pack: {result.repo_pack}")
    lines.append(f"Mode: {result.mode}")
    lines.append(f"Submission id: {result.submission_id}")
    lines.append(
        "Submission matches challenge: "
        + ("yes" if result.submission_matches_challenge else "no")
    )
    lines.append(f"Frontier is current: {'yes' if result.frontier_is_current else 'no'}")
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


def render_pr_comment(action: str, title: str, reasons: list[str]) -> str:
    lines = [f"### {title}", ""]
    if reasons:
        lines.append("Reasons:")
        lines.extend(f"- {reason}" for reason in reasons)
    else:
        lines.append("No additional reasons recorded.")
    lines.append("")
    lines.append(f"Action: `{action}`")
    return "\n".join(lines)


def render_submission_json(
    value: SubmissionValidationResult
    | SubmissionVerificationResult
    | PullRequestInspectionResult
    | SubmissionDecisionResult,
) -> str:
    payload = asdict(value)
    metadata = payload.get("metadata")
    if isinstance(metadata, dict):
        payload["metadata"] = metadata
    return json.dumps(payload, indent=2) + "\n"


@dataclass(frozen=True)
class ChangedPathValidation:
    off_scope_paths: list[str]
    reasons: list[str]


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
            "/" not in relative_name
            and relative_name in TOP_LEVEL_SUBMISSION_FILENAMES
        ) or is_allowed_bundle_relative_path(relative_name):
            if is_allowed_bundle_relative_path(relative_name):
                touched_bundle_file = True
            continue
        else:
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
        reasons.append(
            "submission.json repo_pack does not match the submission path."
        )
    if metadata.mode != descriptor.mode:
        reasons.append("submission.json mode does not match the submission path.")
    if metadata.submission_id != descriptor.submission_id:
        reasons.append(
            "submission.json submission_id does not match the submission path."
        )
    return reasons


def validate_submission_target(metadata: SubmissionMetadata) -> list[str]:
    return validate_submission_lane(metadata.repo_pack, metadata.mode)


def validate_submission_candidate(
    *,
    metadata: SubmissionMetadata,
    submission_root: Path,
) -> list[str]:
    reasons: list[str] = []
    unexpected_paths = find_unexpected_bundle_paths(submission_root)
    if unexpected_paths:
        reasons.append(
            "Submission bundle contains unsupported files: " + ", ".join(unexpected_paths)
        )

    symlink_paths = find_bundle_symlink_paths(submission_root)
    if symlink_paths:
        reasons.append(
            "Submission bundle must not contain symlinks: " + ", ".join(symlink_paths)
        )

    bundle_paths = find_bundle_relative_paths(submission_root)
    if len(bundle_paths) > MAX_SUBMISSION_BUNDLE_FILES:
        reasons.append(
            "Submission bundle is too large. "
            f"Found {len(bundle_paths)} files; limit is {MAX_SUBMISSION_BUNDLE_FILES}."
        )

    total_bytes = 0
    for relative_path in bundle_paths:
        file_path = submission_root / relative_path
        file_bytes = file_path.stat().st_size
        total_bytes += file_bytes
        if file_bytes > MAX_SUBMISSION_FILE_BYTES:
            reasons.append(
                f"Submission bundle file is too large: {relative_path} "
                f"({file_bytes} bytes; limit is {MAX_SUBMISSION_FILE_BYTES})."
            )
    if total_bytes > MAX_SUBMISSION_BUNDLE_BYTES:
        reasons.append(
            "Submission bundle total size is too large. "
            f"Found {total_bytes} bytes; limit is {MAX_SUBMISSION_BUNDLE_BYTES}."
        )

    bundle_files = load_bundle_files(submission_root)
    reasons.extend(validate_bundle_python_sources(bundle_files))
    reasons.extend(validate_bundle_static_policy(bundle_files))
    reasons.extend(
        validate_submission_not_copycat(
            metadata=metadata,
            submission_root=submission_root,
            bundle_files=bundle_files,
        )
    )
    return dedupe(reasons)


def validate_submission_lane(repo_pack: str, mode: str) -> list[str]:
    reasons: list[str] = []
    try:
        ensure_active_repo_pack(repo_pack)
    except (FileNotFoundError, ValueError) as exc:
        reasons.append(str(exc))
        return reasons

    try:
        resolve_eval_pack_path(repo_pack)
    except FileNotFoundError as exc:
        reasons.append(str(exc))
        return reasons

    try:
        manifest = load_frontier_manifest(repo_pack)
    except FileNotFoundError:
        reasons.append(
            "Frontier manifest does not exist for the target repo pack. "
            "Initialize the frontier before accepting PR submissions."
        )
        return reasons
    if mode not in manifest.modes:
        reasons.append(
            f"Mode is not configured in the frontier manifest: {mode}"
        )
    return reasons


def resolve_submission_descriptor(
    submission_root: Path,
    *,
    repo_root: Path | None,
    require_exists: bool = True,
) -> tuple[SubmissionDescriptor | None, list[str]]:
    reasons: list[str] = []
    root = submission_root.resolve()
    if require_exists:
        if not root.exists():
            return None, [f"Submission path does not exist: {submission_root}"]
        if not root.is_dir():
            return None, [f"Submission path must be a directory: {submission_root}"]

    if repo_root is not None:
        try:
            relative = root.relative_to(repo_root)
        except ValueError:
            return None, ["Submission path must live under the Kata repo root."]
        parts = relative.parts
    else:
        parts = root.parts
        if SUBMISSIONS_DIRNAME in parts:
            parts = parts[parts.index(SUBMISSIONS_DIRNAME) :]

    if len(parts) < 4 or parts[0] != SUBMISSIONS_DIRNAME:
        reasons.append(
            "Submission path must match "
            "`submissions/<repo-pack>/<mode>/<submission-id>`."
        )
        return None, reasons

    repo_pack = parts[1]
    mode = parts[2]
    submission_id = parts[3]
    if mode not in SUPPORTED_SUBMISSION_MODES:
        reasons.append(
            "Submission mode must be one of: "
            + ", ".join(sorted(SUPPORTED_SUBMISSION_MODES))
        )
    return (
        SubmissionDescriptor(
            root=root,
            repo_pack=repo_pack,
            mode=mode,
            submission_id=submission_id,
            agent_path=root / SUBMISSION_AGENT_FILENAME,
            agent_manifest_path=root / SUBMISSION_AGENT_MANIFEST_FILENAME,
            metadata_path=root / SUBMISSION_METADATA_FILENAME,
        ),
        reasons,
    )


def load_submission_metadata(path: Path) -> SubmissionMetadata:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"Submission metadata must contain a JSON object: {path}")
    return SubmissionMetadata(
        schema_version=int(payload["schema_version"]),
        repo_pack=str(payload["repo_pack"]),
        mode=str(payload["mode"]),
        submission_id=str(payload["submission_id"]),
        created_at=str(payload["created_at"]),
        author=str(payload["author"]) if payload.get("author") is not None else None,
        title=str(payload["title"]) if payload.get("title") is not None else None,
        notes=str(payload["notes"]) if payload.get("notes") is not None else None,
    )


def write_submission_metadata(path: Path, metadata: SubmissionMetadata) -> None:
    path.write_text(json.dumps(asdict(metadata), indent=2) + "\n", encoding="utf-8")


def validate_submission_mode(mode: str) -> None:
    if mode not in SUPPORTED_SUBMISSION_MODES:
        raise ValueError(
            "Submission mode must be one of: "
            + ", ".join(sorted(SUPPORTED_SUBMISSION_MODES))
        )


def default_submissions_root() -> Path:
    return Path.cwd().resolve() / SUBMISSIONS_DIRNAME


def default_submission_agent(mode: str) -> str:
    return (
        "from __future__ import annotations\n\n"
        f'\"\"\"Kata submission scaffold for the {mode} lane.\"\"\"\n\n'
        "def solve(repo_path: str, issue: str, model: str, api_base: str, api_key: str) -> dict:\n"
        f"    # {DEFAULT_AGENT_PLACEHOLDER}\n"
        "    return {\n"
        "        \"success\": False,\n"
        "        \"message\": \"scaffold agent - replace before submitting\",\n"
        "        \"diff\": \"\",\n"
        "    }\n"
    )


def default_submission_notes() -> str:
    return (
        "Recommended conventions:\n"
        f"- author: your GitHub username\n"
        f"- submission_id: {SUBMISSION_ID_CONVENTION}\n"
        "- implement a real agent in agent.py before opening the PR\n"
        "- optional helper modules may live under helpers/*.py\n"
    )


def infer_submission_dirs(changed_paths: list[str]) -> list[str]:
    candidate_dirs: list[str] = []
    for changed_path in changed_paths:
        parts = Path(changed_path).parts
        if len(parts) < 5 or parts[0] != SUBMISSIONS_DIRNAME:
            continue
        candidate_dir = Path(*parts[:4]).as_posix()
        if candidate_dir not in candidate_dirs:
            candidate_dirs.append(candidate_dir)
    return candidate_dirs


def read_changed_paths_file(path: str) -> list[str]:
    file_path = Path(path).expanduser().resolve()
    return [
        line.strip()
        for line in file_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def normalize_changed_paths(changed_paths: list[str]) -> list[str]:
    normalized: list[str] = []
    for changed_path in changed_paths:
        value = changed_path.strip()
        if not value:
            continue
        normalized.append(value.strip("/"))
    return normalized


def dedupe(values: list[str]) -> list[str]:
    unique: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value in seen:
            continue
        unique.append(value)
        seen.add(value)
    return unique


def hash_submission_bundle(root: Path) -> str:
    bundle_root = root.expanduser().resolve()
    relative_paths = sorted(
        path for path in find_bundle_relative_paths(bundle_root)
    )
    return sha256_directory(bundle_root, include=relative_paths)


def find_bundle_relative_paths(root: Path) -> list[str]:
    relative_paths = [
        path.relative_to(root).as_posix()
        for path in sorted(root.rglob("*"))
        if path.is_file() and is_allowed_bundle_relative_path(path.relative_to(root).as_posix())
    ]
    return relative_paths


def find_bundle_symlink_paths(root: Path) -> list[str]:
    return [
        path.relative_to(root).as_posix()
        for path in sorted(root.rglob("*"))
        if path.is_symlink()
    ]


def validate_bundle_python_sources(bundle_files: dict[str, str]) -> list[str]:
    reasons: list[str] = []
    for relative_path, content in sorted(bundle_files.items()):
        try:
            ast.parse(content, filename=relative_path)
        except SyntaxError as exc:
            line_number = exc.lineno or 1
            reasons.append(
                "Submission bundle contains invalid Python syntax in "
                f"{relative_path}:{line_number}."
            )
    agent_source = bundle_files.get(AGENT_ENTRY_FILENAME, "")
    if agent_source and "def solve(" not in agent_source:
        reasons.append("Submission agent must define solve(...).")
    return reasons


def validate_bundle_static_policy(bundle_files: dict[str, str]) -> list[str]:
    reasons: list[str] = []
    for relative_path, content in sorted(bundle_files.items()):
        for token in FORBIDDEN_ENV_REFERENCE_TOKENS:
            if token in content:
                reasons.append(
                    f"Submission bundle must not read validator/provider secret env vars "
                    f"directly: {relative_path} references `{token}`."
                )
        if SECRET_PATTERN.search(content):
            reasons.append(
                f"Submission bundle appears to contain a hardcoded secret token: {relative_path}."
            )
    return reasons


def validate_submission_not_copycat(
    *,
    metadata: SubmissionMetadata,
    submission_root: Path,
    bundle_files: dict[str, str],
) -> list[str]:
    manifest = load_frontier_manifest(metadata.repo_pack)
    mode_config = manifest.modes.get(metadata.mode)
    if mode_config is None:
        return []

    reasons: list[str] = []
    candidate_hash = hash_submission_bundle(submission_root)
    frontier_hash = resolve_frontier_artifact_hash(mode_config)
    baseline_hash = resolve_baseline_artifact_hash(mode_config)
    if candidate_hash == frontier_hash:
        reasons.append("Submission bundle is an exact copy of the current frontier artifact.")
    if candidate_hash == baseline_hash:
        reasons.append("Submission bundle is an exact copy of the current baseline artifact.")

    candidate_agent = bundle_files.get(AGENT_ENTRY_FILENAME)
    if candidate_agent is None:
        return reasons

    frontier_agent_path = (
        Path(mode_config.frontier_artifact).expanduser().resolve() / AGENT_ENTRY_FILENAME
    )
    if frontier_agent_path.exists() and python_sources_equivalent(
        candidate_agent,
        frontier_agent_path.read_text(encoding="utf-8"),
    ):
        reasons.append(
            "Submission agent duplicates the current frontier agent implementation."
        )

    baseline_agent_path = (
        Path(mode_config.baseline_artifact).expanduser().resolve() / AGENT_ENTRY_FILENAME
    )
    if baseline_agent_path.exists() and python_sources_equivalent(
        candidate_agent,
        baseline_agent_path.read_text(encoding="utf-8"),
    ):
        reasons.append(
            "Submission agent duplicates the current baseline agent implementation."
        )
    return reasons


def python_sources_equivalent(left: str, right: str) -> bool:
    try:
        left_tree = ast.parse(left)
        right_tree = ast.parse(right)
    except SyntaxError:
        return left == right
    return ast.dump(left_tree, include_attributes=False) == ast.dump(
        right_tree,
        include_attributes=False,
    )
