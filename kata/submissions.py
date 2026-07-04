from __future__ import annotations

import ast
import json
import os
import py_compile
import re
import tempfile
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
from kata.ast_utils import (
    find_module_async_function_def,
    find_module_function_def,
    function_supports_no_arg_invocation,
)
from kata.challenge import (
    SN60_VALIDATOR_MODEL,
    ChallengeSummary,
    load_challenge_summary,
    run_sn60_challenge,
)
from kata.evaluators.sn60_bitsec import (
    DEFAULT_REPLICAS_PER_PROJECT,
    SN60_BITSEC_EVALUATOR_ID,
    hash_bundle_root,
    load_sn60_benchmark_project_keys,
    resolve_sn60_sandbox_source,
)
from kata.lane_state import (
    KING_STATE_SCHEMA_VERSION,
    LaneKingState,
    PackRegistryEntry,
    benchmark_snapshot_path,
    challenge_state_path,
    lane_king_state_path,
    load_benchmark_snapshot,
    load_challenge_state,
    load_lane_king_state,
    load_pack_registry,
    write_lane_king_state,
)
from kata.provenance import sha256_directory, short_hash
from kata.public_artifacts import (
    publish_public_king,
    resolve_kata_root,
    resolve_public_king_root,
)
from kata.screening import validate_sn60_static_screening
from kata.util import dedupe

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
SUPPORTED_SUBMISSION_MODES = {"miner"}
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
    "CHUTES_API_KEY",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GOOGLE_API_KEY",
    "OPENROUTER_API_KEY",
)
FORBIDDEN_PROVIDER_SUBSTRINGS = (
    "api.openai.com",
    "openrouter.ai",
    "anthropic.com",
    "generativelanguage.googleapis.com",
    "api.groq.com",
    "api.together.xyz",
    "api.fireworks.ai",
    "api.mistral.ai",
    "api.deepseek.com",
    "deepinfra.com",
    "cohere.ai",
)
FORBIDDEN_SAMPLING_NAMES = {
    "temperature",
    "top_p",
    "top_k",
    "min_p",
    "top_a",
    "frequency_penalty",
    "presence_penalty",
    "repetition_penalty",
    "seed",
    "logit_bias",
    "logprobs",
    "top_logprobs",
}
SECRET_PATTERN = re.compile(
    r"(sk-[A-Za-z0-9]{10,}|ghp_[A-Za-z0-9]{10,}|hf_[A-Za-z0-9]{10,}|cpk_[A-Za-z0-9]{10,})"
)


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
    agent_path.write_text(default_submission_agent(), encoding="utf-8")
    return submission_root


def validate_submission(
    submission_path: str,
    *,
    changed_paths: list[str] | None = None,
    repo_root: str | None = None,
    public_root: str | None = None,
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

    symlink_paths = find_bundle_symlink_paths(descriptor.root)
    if symlink_paths:
        reasons.append(
            "Submission bundle must not contain symlinks: " + ", ".join(symlink_paths)
        )
        return SubmissionValidationResult(
            submission_path=str(descriptor.root),
            repo_pack=descriptor.repo_pack,
            mode=descriptor.mode,
            submission_id=descriptor.submission_id,
            agent_path=str(descriptor.agent_path),
            metadata_path=str(descriptor.metadata_path),
            changed_paths=normalized_changed,
            off_scope_paths=off_scope_paths,
            reasons=dedupe(reasons),
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
        except (ValueError, KeyError, json.JSONDecodeError) as exc:
            reasons.append(str(exc))

    if not agent_path.exists():
        reasons.append(f"Missing required submission file: {agent_path.name}")
    else:
        agent_text = agent_path.read_text(encoding="utf-8").strip()
        if not agent_text:
            reasons.append("Submission agent file is empty.")
        elif DEFAULT_AGENT_PLACEHOLDER in agent_text:
            reasons.append("Submission agent still contains scaffold placeholder text.")
        if not agent_defines_required_entrypoint(agent_text):
            reasons.append(required_submission_entrypoint_reason())

    if not agent_manifest_path.exists():
        reasons.append(f"Missing required submission file: {agent_manifest_path.name}")
    else:
        reasons.extend(validate_agent_manifest(agent_manifest_path))

    if metadata is not None:
        reasons.extend(validate_submission_metadata(metadata, descriptor))
        reasons.extend(
            validate_submission_target(metadata, public_root=public_root)
        )
        if agent_path.exists():
            reasons.extend(
                validate_submission_candidate(
                    metadata=metadata,
                    submission_root=descriptor.root,
                    public_root=public_root,
                )
            )

    evaluator_entry = find_evaluator_pack_entry(
        descriptor.repo_pack, descriptor.mode, public_root=public_root
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
        evaluator_id=evaluator_entry.evaluator_id if evaluator_entry else None,
    )


def evaluate_submission(
    submission_path: str,
    *,
    output_root: str | None = None,
    sn60_project_keys: list[str] | None = None,
    sn60_replicas_per_project: int | None = None,
    sn60_sandbox_root: str | None = None,
    sn60_benchmark_file: str | None = None,
    sn60_sandbox_commit: str | None = None,
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
    if not is_sn60_miner_metadata(validation.metadata):
        raise ValueError(
            "Submission does not target a registered SN60 evaluator lane. "
            "Register the lane in the pack registry before evaluating."
        )
    project_keys = resolve_sn60_project_keys(
        configured_keys=sn60_project_keys,
        sandbox_root=sn60_sandbox_root,
        benchmark_file=sn60_benchmark_file,
        sandbox_commit=sn60_sandbox_commit,
    )
    if not project_keys:
        raise ValueError(
            "SN60 miner evaluation requires at least one project key in the "
            "resolved benchmark snapshot."
        )
    lane_id, king_artifact_path = resolve_sn60_king_artifact(validation.metadata)
    return run_sn60_challenge(
        king_artifact_path=king_artifact_path,
        candidate_artifact_path=validation.submission_path,
        project_keys=project_keys,
        candidate_submission_id=validation.metadata.submission_id,
        lane_id=lane_id,
        output_root=output_root,
        replicas_per_project=sn60_replicas_per_project or DEFAULT_REPLICAS_PER_PROJECT,
        sandbox_root=sn60_sandbox_root,
        benchmark_file=sn60_benchmark_file,
        sandbox_commit=sn60_sandbox_commit,
    )


def parse_sn60_project_keys_from_env() -> list[str]:
    configured = os.environ.get("KATA_SN60_PROJECT_KEYS", "")
    return [part.strip() for part in configured.split(",") if part.strip()]


def resolve_sn60_project_keys(
    *,
    configured_keys: list[str] | None,
    sandbox_root: str | None,
    benchmark_file: str | None,
    sandbox_commit: str | None,
) -> list[str]:
    explicit_keys = configured_keys or parse_sn60_project_keys_from_env()
    if explicit_keys:
        return explicit_keys
    sandbox_source = resolve_sn60_sandbox_source(
        sandbox_root=sandbox_root,
        benchmark_file=benchmark_file,
        sandbox_commit=sandbox_commit,
        scorer_version="ScaBenchScorerV2",
    )
    return load_sn60_benchmark_project_keys(sandbox_source)


def is_sn60_miner_metadata(metadata: SubmissionMetadata) -> bool:
    entry = find_evaluator_pack_entry(metadata.repo_pack, metadata.mode)
    return entry is not None and entry.evaluator_id == SN60_BITSEC_EVALUATOR_ID


def resolve_sn60_lane_king_hash(
    lane_id: str,
    *,
    repo_pack: str,
    mode: str,
    public_root: str | None = None,
) -> str | None:
    """Resolve the current king artifact hash for a registry-backed SN60 lane."""
    if lane_king_state_path(lane_id, public_root=public_root).exists():
        king = load_lane_king_state(lane_id, public_root=public_root)
        if king.current_king_artifact_hash:
            return king.current_king_artifact_hash
    king_root = resolve_public_king_root(
        public_root=public_root, repo_pack=repo_pack, mode=mode
    )
    if (king_root / SUBMISSION_AGENT_FILENAME).exists():
        return hash_submission_bundle(king_root)
    return None


def sn60_lane_benchmark_is_current(
    lane_id: str,
    summary: ChallengeSummary,
    *,
    public_root: str | None = None,
) -> bool:
    """Freshness check against the lane's recorded benchmark snapshot and fingerprint."""
    if not benchmark_snapshot_path(lane_id, public_root=public_root).exists():
        return False
    snapshot = load_benchmark_snapshot(lane_id, public_root=public_root)
    expected_version = f"{snapshot.scorer_version}@{short_hash(snapshot.sandbox_commit_hash)}"
    if summary.evaluator_version != expected_version:
        return False
    if challenge_state_path(lane_id, public_root=public_root).exists():
        challenge_state = load_challenge_state(lane_id, public_root=public_root)
        if challenge_state.freshness_fingerprint != summary.primary_pool_fingerprint:
            return False
    return True


def resolve_sn60_king_artifact(metadata: SubmissionMetadata) -> tuple[str, str]:
    """Resolve (lane_id, king_artifact_path) for an SN60 duel from the pack registry."""
    entry = find_evaluator_pack_entry(metadata.repo_pack, metadata.mode)
    if entry is None:
        raise ValueError(
            "No evaluator-backed lane is registered for "
            f"`{metadata.repo_pack}/{metadata.mode}`."
        )
    king_root = resolve_public_king_root(
        public_root=None,
        repo_pack=metadata.repo_pack,
        mode=metadata.mode,
    )
    if not (king_root / SUBMISSION_AGENT_FILENAME).exists():
        raise ValueError(
            f"SN60 lane king artifact is not seeded: {king_root}. "
            "Seed the current king under kings/<subnet-pack>/<mode>/ before running duels."
        )
    return entry.lane_id, str(king_root)


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
            "`submissions/<subnet-pack>/<mode>/<submission-id>`."
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
    *,
    public_root: str | None = None,
) -> SubmissionVerificationResult:
    validation = validate_submission(submission_path, public_root=public_root)
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
    candidate_hash = hash_submission_bundle(Path(validation.submission_path))
    evaluator_entry = find_evaluator_pack_entry(
        validation.metadata.repo_pack,
        validation.metadata.mode,
        public_root=public_root,
    )
    if evaluator_entry is None:
        raise ValueError(
            "No evaluator-backed lane is registered for "
            f"`{validation.metadata.repo_pack}/{validation.metadata.mode}`."
        )
    current_king_hash = (
        resolve_sn60_lane_king_hash(
            evaluator_entry.lane_id,
            repo_pack=validation.metadata.repo_pack,
            mode=validation.metadata.mode,
            public_root=public_root,
        )
        or ""
    )
    lane_benchmark_is_current = sn60_lane_benchmark_is_current(
        evaluator_entry.lane_id, summary, public_root=public_root
    )
    submission_matches = (
        summary.mode == validation.metadata.mode
        and summary.candidate_artifact_hash == candidate_hash
    )
    king_is_current = summary.king_artifact_hash == current_king_hash
    benchmark_is_current = (
        summary.validator_model == SN60_VALIDATOR_MODEL and lane_benchmark_is_current
    )
    current_promotion_ready = summary.promotion_ready

    reasons: list[str] = []
    if not submission_matches:
        reasons.append("Challenge result does not match the current submission payload.")
    if not king_is_current:
        reasons.append("Challenge result is stale because the king artifact has changed.")
    if not benchmark_is_current:
        reasons.append("Challenge result is stale because the SN60 benchmark lane has changed.")
    if not current_promotion_ready:
        reasons.append(f"Challenge is not promotion-ready: {summary.promotion_reason}")

    return SubmissionVerificationResult(
        submission_path=validation.submission_path,
        challenge_summary_path=str(Path(challenge_summary_path).expanduser().resolve()),
        repo_pack=validation.metadata.repo_pack,
        mode=validation.metadata.mode,
        submission_id=validation.metadata.submission_id,
        candidate_artifact_hash=candidate_hash,
        recorded_candidate_artifact_hash=summary.candidate_artifact_hash,
        current_king_artifact_hash=current_king_hash,
        recorded_king_artifact_hash=summary.king_artifact_hash,
        current_validator_model=SN60_VALIDATOR_MODEL,
        recorded_validator_model=summary.validator_model,
        submission_matches_challenge=submission_matches,
        king_is_current=king_is_current,
        benchmark_is_current=benchmark_is_current,
        promotion_ready=current_promotion_ready,
        auto_merge_ready=submission_matches
        and king_is_current
        and benchmark_is_current
        and current_promotion_ready,
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
            reason="Submission beat the current king and is safe to auto-merge.",
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
            reason="Submission result is stale and must be rerun against the current king.",
            reasons=stale_reasons,
            promotion_ready=verification.promotion_ready,
            auto_merge_ready=False,
        )

    losing_reasons = verification.reasons or [
        "Submission did not satisfy the promotion rule against the current king."
    ]
    return SubmissionDecisionResult(
        action=PR_ACTION_CLOSE_LOSING,
        submission_path=verification.submission_path,
        challenge_summary_path=verification.challenge_summary_path,
        repo_pack=verification.repo_pack,
        mode=verification.mode,
        submission_id=verification.submission_id,
        reason="Submission lost to the current king and should be auto-closed.",
        reasons=losing_reasons,
        promotion_ready=verification.promotion_ready,
        auto_merge_ready=False,
    )


def promote_submission_result(
    submission_path: str,
    challenge_summary_path: str,
    *,
    public_root: str | None = None,
) -> LanePromotionResult:
    # Verify against the same root the promotion will be written to, so an
    # explicit --public-root cannot check one lane state and publish to
    # another.
    verification = verify_submission_result(
        submission_path, challenge_summary_path, public_root=public_root
    )
    if not verification.auto_merge_ready:
        raise ValueError(
            "Submission is not safe to promote. "
            + "; ".join(
                verification.reasons
                or ["submission result is not auto-merge ready"]
            )
        )
    summary = load_challenge_summary(challenge_summary_path)
    evaluator_entry = find_evaluator_pack_entry(
        verification.repo_pack, verification.mode, public_root=public_root
    )
    if evaluator_entry is None:
        raise ValueError(
            "No evaluator-backed lane is registered for "
            f"`{verification.repo_pack}/{verification.mode}`."
        )
    return promote_lane_king(
        entry=evaluator_entry,
        verification=verification,
        summary=summary,
        public_root=public_root,
    )


@dataclass(frozen=True)
class LanePromotionResult:
    lane_id: str
    king_root: str
    king: LaneKingState


def promote_lane_king(
    *,
    entry: PackRegistryEntry,
    verification: SubmissionVerificationResult,
    summary: ChallengeSummary,
    public_root: str | None = None,
):
    published = publish_public_king(
        public_root=str(resolve_kata_root(public_root)),
        repo_pack=verification.repo_pack,
        mode=verification.mode,
        submission_id=verification.submission_id,
        challenge_run_id=summary.run_id,
        candidate_artifact_path=verification.submission_path,
        candidate_artifact_hash=verification.candidate_artifact_hash,
        # Hash the published king the same way a later duel will, so
        # king_is_current stays true even for non-normalized submissions.
        artifact_hasher=hash_bundle_root,
    )
    now = datetime.now(UTC).isoformat()
    king = LaneKingState(
        schema_version=KING_STATE_SCHEMA_VERSION,
        current_king_submission_id=verification.submission_id,
        current_king_artifact_hash=published.king_artifact_hash,
        promotion_source_pr=None,
        promotion_timestamp=now,
        updated_at=now,
    )
    write_lane_king_state(entry.lane_id, king, public_root=public_root)
    return LanePromotionResult(
        lane_id=entry.lane_id,
        king_root=str(published.king_root),
        king=king,
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
        "Submission matches challenge: "
        + ("yes" if result.submission_matches_challenge else "no")
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
            "submission.json subnet_pack does not match the submission path."
        )
    if metadata.mode != descriptor.mode:
        reasons.append("submission.json mode does not match the submission path.")
    if metadata.submission_id != descriptor.submission_id:
        reasons.append(
            "submission.json submission_id does not match the submission path."
        )
    return reasons


def validate_submission_target(
    metadata: SubmissionMetadata,
    *,
    public_root: str | None = None,
) -> list[str]:
    return validate_submission_lane(
        metadata.repo_pack, metadata.mode, public_root=public_root
    )


def validate_submission_candidate(
    *,
    metadata: SubmissionMetadata,
    submission_root: Path,
    public_root: str | None = None,
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
    if metadata.mode == "miner":
        reasons.extend(validate_sn60_static_screening(submission_root))

    reasons.extend(validate_bundle_python_sources(bundle_files))
    reasons.extend(validate_bundle_static_policy(bundle_files))
    reasons.extend(
        validate_submission_not_copycat(
            metadata=metadata,
            submission_root=submission_root,
            bundle_files=bundle_files,
            public_root=public_root,
        )
    )
    return dedupe(reasons)


def find_evaluator_pack_entry(
    repo_pack: str,
    mode: str,
    *,
    public_root: str | None = None,
) -> PackRegistryEntry | None:
    # A missing registry loads as empty (returns None below); a *corrupt* one
    # must surface loudly. Swallowing the load error here would report every
    # submission as "no lane registered" and auto-close PRs, hiding the real
    # cause — a broken registry file.
    registry = load_pack_registry(public_root=public_root)
    for pack in registry.packs:
        if pack.repo_pack == repo_pack and pack.mode == mode:
            return pack
    return None


def validate_submission_lane(
    repo_pack: str,
    mode: str,
    *,
    public_root: str | None = None,
) -> list[str]:
    entry = find_evaluator_pack_entry(repo_pack, mode, public_root=public_root)
    if entry is None:
        return [
            "No evaluator-backed lane is registered in the pack registry for "
            f"`{repo_pack}/{mode}`."
        ]
    if not entry.active:
        return [
            "Evaluator-backed lane is not active in the pack registry: "
            f"{entry.lane_id}"
        ]
    return []


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
            "`submissions/<subnet-pack>/<mode>/<submission-id>`."
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
    try:
        return SubmissionMetadata(
            schema_version=int(payload["schema_version"]),
            repo_pack=read_submission_subnet_pack(payload),
            mode=str(payload["mode"]),
            submission_id=str(payload["submission_id"]),
            created_at=str(payload["created_at"]),
            author=str(payload["author"]) if payload.get("author") is not None else None,
            title=str(payload["title"]) if payload.get("title") is not None else None,
            notes=str(payload["notes"]) if payload.get("notes") is not None else None,
        )
    except KeyError as exc:
        raise ValueError(
            f"Submission metadata is missing required field: {exc.args[0]}"
        ) from exc


def read_submission_subnet_pack(payload: dict[str, object]) -> str:
    value = payload.get("subnet_pack", payload.get("repo_pack"))
    if value is None:
        raise KeyError("subnet_pack")
    return str(value)


def write_submission_metadata(path: Path, metadata: SubmissionMetadata) -> None:
    payload = asdict(metadata)
    payload["subnet_pack"] = payload.pop("repo_pack")
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def validate_submission_mode(mode: str) -> None:
    if mode not in SUPPORTED_SUBMISSION_MODES:
        raise ValueError(
            "Submission mode must be one of: "
            + ", ".join(sorted(SUPPORTED_SUBMISSION_MODES))
        )


def default_submissions_root() -> Path:
    return Path.cwd().resolve() / SUBMISSIONS_DIRNAME


def default_submission_agent() -> str:
    return (
        "from __future__ import annotations\n\n"
        '\"\"\"Kata submission scaffold for the miner lane.\"\"\"\n\n'
        "def agent_main(\n"
        "    project_dir: str | None = None,\n"
        "    inference_api: str | None = None,\n"
        ") -> dict:\n"
        f"    # {DEFAULT_AGENT_PLACEHOLDER}\n"
        "    return {\n"
        "        \"vulnerabilities\": [],\n"
        "    }\n"
    )


def default_submission_notes() -> str:
    lines = [
        "Recommended conventions:",
        "- author: your GitHub username",
        f"- submission_id: {SUBMISSION_ID_CONVENTION}",
        "- implement a real agent in agent.py before opening the PR",
        "- SN60 miner submissions in V1 must stay self-contained in agent.py",
    ]
    return "\n".join(lines) + "\n"


def required_submission_entrypoint_reason() -> str:
    return "Submission agent must define agent_main(...)."


def agent_defines_required_entrypoint(agent_source: str) -> bool:
    pattern = re.compile(r"(?m)^(?:async\s+)?def\s+agent_main\s*\(")
    return pattern.search(agent_source) is not None


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
        if not path.is_symlink()
        and path.is_file()
        and is_allowed_bundle_relative_path(path.relative_to(root).as_posix())
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
            continue
        temp_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                "w",
                suffix=".py",
                encoding="utf-8",
                delete=False,
            ) as handle:
                handle.write(content)
                temp_path = Path(handle.name)
            py_compile.compile(str(temp_path), doraise=True)
        except py_compile.PyCompileError:
            reasons.append(
                "Submission bundle failed Python compile smoke check in "
                f"{relative_path}."
            )
        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)
    agent_source = bundle_files.get(AGENT_ENTRY_FILENAME, "")
    if agent_source and not agent_defines_required_entrypoint(agent_source):
        reasons.append(required_submission_entrypoint_reason())
    return reasons


def validate_bundle_static_policy(bundle_files: dict[str, str]) -> list[str]:
    reasons: list[str] = []
    parsed_trees: dict[str, ast.AST] = {}
    for relative_path, content in sorted(bundle_files.items()):
        try:
            parsed_trees[relative_path] = ast.parse(content, filename=relative_path)
        except SyntaxError:
            continue
        for token in FORBIDDEN_ENV_REFERENCE_TOKENS:
            if token in content:
                reasons.append(
                    f"Submission bundle must not read validator/provider secret env vars "
                    f"directly: {relative_path} references `{token}`."
                )
        lowered = content.lower()
        for token in FORBIDDEN_PROVIDER_SUBSTRINGS:
            if token in lowered:
                reasons.append(
                    f"Submission bundle must not hardcode provider endpoints directly: "
                    f"{relative_path} references `{token}`."
                )
        if SECRET_PATTERN.search(content):
            reasons.append(
                f"Submission bundle appears to contain a hardcoded secret token: {relative_path}."
            )
    reasons.extend(validate_bundle_miner_contract(parsed_trees))
    reasons.extend(validate_bundle_sampling_policy(parsed_trees))
    return reasons




def validate_bundle_miner_contract(parsed_trees: dict[str, ast.AST]) -> list[str]:
    agent_tree = parsed_trees.get(AGENT_ENTRY_FILENAME)
    if agent_tree is None:
        return []
    agent_main_fn = find_module_function_def(agent_tree, "agent_main")
    if agent_main_fn is None:
        if find_module_async_function_def(agent_tree, "agent_main") is not None:
            return [
                "Submission agent_main must be a synchronous function; the SN60 "
                "sandbox runner calls agent_main() directly and does not await "
                "coroutines."
            ]
        return [required_submission_entrypoint_reason()]

    if not function_supports_no_arg_invocation(agent_main_fn):
        return ["Submission agent must support no-argument invocation: agent_main()."]

    for return_node in iter_non_nested_function_returns(agent_main_fn):
        if return_node.value is None or not isinstance(return_node.value, ast.Dict):
            continue
        if not dict_contains_string_key(return_node.value, "vulnerabilities"):
            return [
                "Submission agent must return a Bitsec-compatible report with "
                "top-level `vulnerabilities`."
            ]
    return []


def dict_literal_string_keys(node: ast.Dict) -> list[str]:
    keys: list[str] = []
    for key, value in zip(node.keys, node.values):
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            keys.append(key.value)
        elif key is None and isinstance(value, ast.Dict):
            # `{**{"temperature": 0}}` pairs a None key with the inner dict
            # literal; recurse so nested merges cannot hide sampling params.
            keys.extend(dict_literal_string_keys(value))
    return keys


def validate_bundle_sampling_policy(parsed_trees: dict[str, ast.AST]) -> list[str]:
    reasons: list[str] = []
    for relative_path, tree in sorted(parsed_trees.items()):
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            for keyword in node.keywords:
                if keyword.arg is not None:
                    if keyword.arg in FORBIDDEN_SAMPLING_NAMES:
                        reasons.append(
                            "Submission bundle must not control model sampling parameters "
                            f"directly: {relative_path} uses `{keyword.arg}`."
                        )
                    continue
                # `**expr` unpacking: `keyword.arg` is None and the forbidden
                # names, if any, are hidden inside `keyword.value` instead of
                # being visible as a plain keyword name above.
                if isinstance(keyword.value, ast.Dict):
                    forbidden = sorted(
                        set(dict_literal_string_keys(keyword.value))
                        & FORBIDDEN_SAMPLING_NAMES
                    )
                    for name in forbidden:
                        reasons.append(
                            "Submission bundle must not control model sampling parameters "
                            f"directly: {relative_path} uses `**` unpacking with `{name}`."
                        )
                else:
                    reasons.append(
                        "Submission bundle must not pass a dynamic `**` keyword-argument "
                        f"unpacking to a call in {relative_path}; its contents cannot be "
                        "statically verified to exclude model sampling parameters."
                    )
    return reasons


def iter_non_nested_function_returns(function_node: ast.FunctionDef):
    stack: list[ast.AST] = list(reversed(function_node.body))
    while stack:
        node = stack.pop()
        if isinstance(node, ast.Return):
            yield node
            continue
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        stack.extend(reversed(list(ast.iter_child_nodes(node))))


def dict_contains_string_key(node: ast.Dict, key_name: str) -> bool:
    for key in node.keys:
        if isinstance(key, ast.Constant) and key.value == key_name:
            return True
    return False






def validate_submission_not_copycat(
    *,
    metadata: SubmissionMetadata,
    submission_root: Path,
    bundle_files: dict[str, str],
    public_root: str | None = None,
) -> list[str]:
    evaluator_entry = find_evaluator_pack_entry(
        metadata.repo_pack, metadata.mode, public_root=public_root
    )
    if evaluator_entry is None:
        return []
    reasons = validate_submission_not_copycat_of_lane_king(
        lane_id=evaluator_entry.lane_id,
        submission_root=submission_root,
        public_root=public_root,
    )
    candidate_agent = bundle_files.get(AGENT_ENTRY_FILENAME)
    if candidate_agent is not None:
        king_agent_path = (
            resolve_public_king_root(
                public_root=public_root,
                repo_pack=metadata.repo_pack,
                mode=metadata.mode,
            )
            / AGENT_ENTRY_FILENAME
        )
        if king_agent_path.exists() and python_sources_equivalent(
            candidate_agent,
            king_agent_path.read_text(encoding="utf-8"),
        ):
            reasons.append(
                "Submission agent duplicates the current lane king implementation."
            )
    return dedupe(reasons)


def validate_submission_not_copycat_of_lane_king(
    *,
    lane_id: str,
    submission_root: Path,
    public_root: str | None = None,
) -> list[str]:
    if not lane_king_state_path(lane_id, public_root=public_root).exists():
        return []
    king = load_lane_king_state(lane_id, public_root=public_root)
    if king.current_king_artifact_hash is None:
        return []
    candidate_hash = hash_submission_bundle(submission_root)
    if candidate_hash == king.current_king_artifact_hash:
        return [
            "Submission bundle is an exact copy of the current lane king artifact."
        ]
    return []


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
