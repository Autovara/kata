from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from kata import validator_system as _validator_system
from kata.packages.dispatch import plugin_for_evaluator
from kata.promotion_system import LanePromotionResult
from kata.promotion_system import (
    find_evaluator_pack_entry as find_evaluator_pack_entry,
)
from kata.promotion_system import (
    promote_lane_king as promote_lane_king,
)
from kata.promotion_system import (
    resolve_lane_king_hash as resolve_lane_king_hash,
)
from kata.promotion_system import (
    validate_submission_lane as validate_submission_lane,
)
from kata.screening_system.rules import (
    find_bundle_symlink_paths,
    hash_submission_bundle,
)
from kata.submission_system.bundle import (
    validate_agent_manifest,
    write_agent_manifest,
)
from kata.submission_system.constants import (
    DEFAULT_AGENT_PLACEHOLDER,
    PR_ACTION_CLOSE_INVALID,
    PR_ACTION_CLOSE_LOSING,
    PR_ACTION_EVALUATE,
    PR_ACTION_MERGE,
    PR_ACTION_RERUN_STALE,
    SUBMISSION_AGENT_FILENAME,
    SUBMISSION_AGENT_MANIFEST_FILENAME,
    SUBMISSION_METADATA_FILENAME,
    SUBMISSION_SCHEMA_VERSION,
)
from kata.submission_system.layout import (
    agent_defines_required_entrypoint,
    default_submission_agent,
    default_submission_notes,
    default_submissions_root,
    infer_submission_dirs,
    load_submission_metadata,
    normalize_changed_paths,
    required_submission_entrypoint_reason,
    resolve_submission_descriptor,
    validate_submission_mode,
    write_submission_metadata,
)
from kata.submission_system.models import (
    PullRequestInspectionResult,
    SubmissionCandidateValidation,
    SubmissionDecisionResult,
    SubmissionMetadata,
    SubmissionValidationResult,
    SubmissionVerificationResult,
)
from kata.submission_system.validation import (
    validate_changed_paths,
    validate_submission_candidate,
    validate_submission_metadata,
)
from kata.util import dedupe

ChallengeSummary = _validator_system.ChallengeSummary
load_challenge_summary = _validator_system.load_challenge_summary


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
        Path(output_root).expanduser().resolve() if output_root else default_submissions_root()
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
    candidate_validation = SubmissionCandidateValidation()

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
        reasons.append("Submission bundle must not contain symlinks: " + ", ".join(symlink_paths))
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
        reasons.extend(validate_submission_target(metadata, public_root=public_root))
        if agent_path.exists():
            candidate_validation = validate_submission_candidate(
                metadata=metadata,
                submission_root=descriptor.root,
                public_root=public_root,
            )
            reasons.extend(candidate_validation.reasons)

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
        screening_status=candidate_validation.screening_status,
        screening_review_reasons=candidate_validation.screening_review_reasons,
        screening_notes=candidate_validation.screening_notes,
        screening_score=candidate_validation.screening_score,
    )


def plugin_for_submission(
    metadata: SubmissionMetadata, *, public_root: str | None = None
):
    """The subnet plugin registered for this submission's lane, or ``None``."""
    entry = find_evaluator_pack_entry(
        metadata.repo_pack, metadata.mode, public_root=public_root
    )
    if entry is None:
        return None
    return plugin_for_evaluator(entry.evaluator_id)


def is_evaluable_submission(metadata: SubmissionMetadata) -> bool:
    # A submission is evaluable when a subnet plugin is registered for its lane; the
    # dispatch is by evaluator id, not a hardcoded subnet check.
    return plugin_for_submission(metadata) is not None


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
    if not validation.is_valid or validation.metadata is None or validation.agent_path is None:
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
    # Freshness is checked against the lane's plugin identity, not a hardcoded model.
    plugin = plugin_for_evaluator(evaluator_entry.evaluator_id)
    validator_identity = (
        plugin.validator_identity if plugin is not None else ""
    )
    current_king_hash = (
        resolve_lane_king_hash(
            evaluator_entry.lane_id,
            repo_pack=validation.metadata.repo_pack,
            mode=validation.metadata.mode,
            public_root=public_root,
        )
        or ""
    )
    lane_benchmark_is_current = (
        plugin.benchmark_is_current(
            lane_id=evaluator_entry.lane_id, summary=summary, public_root=public_root
        )
        if plugin is not None
        else True
    )
    submission_matches = (
        summary.mode == validation.metadata.mode
        and summary.candidate_artifact_hash == candidate_hash
    )
    king_is_current = summary.king_artifact_hash == current_king_hash
    benchmark_is_current = (
        summary.validator_model == validator_identity and lane_benchmark_is_current
    )
    current_promotion_ready = summary.promotion_ready

    reasons: list[str] = []
    if not submission_matches:
        reasons.append("Challenge result does not match the current submission payload.")
    if not king_is_current:
        reasons.append("Challenge result is stale because the king artifact has changed.")
    if not benchmark_is_current:
        reasons.append("Challenge result is stale because the benchmark lane has changed.")
    if not current_promotion_ready:
        reasons.append(f"Challenge is not promotion-ready: {summary.promotion_reason}")
    if plugin is not None:
        reasons.extend(
            plugin.extra_verification_reasons(
                lane_id=evaluator_entry.lane_id, summary=summary, public_root=public_root
            )
        )

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
        current_validator_model=validator_identity,
        recorded_validator_model=summary.validator_model,
        submission_matches_challenge=submission_matches,
        king_is_current=king_is_current,
        benchmark_is_current=benchmark_is_current,
        promotion_ready=current_promotion_ready,
        auto_merge_ready=submission_matches
        and king_is_current
        and benchmark_is_current
        and current_promotion_ready
        and not reasons,
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

    # Classify "rerun (stale)" vs "close (losing)" from the structured verification
    # flags, not by substring-matching the human-readable reason text: a result is
    # stale/rerunnable when the payload, king, or benchmark it was scored against no
    # longer matches the current state, regardless of how the reason is worded.
    stale_reasons: list[str] = []
    if not verification.submission_matches_challenge:
        stale_reasons.append(
            "Challenge result does not match the current submission payload."
        )
    if not verification.king_is_current:
        stale_reasons.append(
            "Challenge result is stale because the king artifact has changed."
        )
    if not verification.benchmark_is_current:
        stale_reasons.append(
            "Challenge result is stale because the benchmark lane has changed."
        )
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
            + "; ".join(verification.reasons or ["submission result is not auto-merge ready"])
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


def validate_submission_target(
    metadata: SubmissionMetadata,
    *,
    public_root: str | None = None,
) -> list[str]:
    return validate_submission_lane(metadata.repo_pack, metadata.mode, public_root=public_root)
