from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from kata.evaluators.sn60_bitsec import (
    Sn60DuelSummary,
    Sn60ProjectAggregate,
    Sn60ReplicaResult,
    Sn60SandboxSource,
    Sn60VariantSummary,
    hash_bundle_root,
)
from kata.screening_system.rules import hash_submission_bundle
from kata.state_system.lane import (
    KING_STATE_SCHEMA_VERSION,
    LaneKingState,
    PackRegistryEntry,
    lane_king_state_path,
    load_lane_king_state,
    load_pack_registry,
    write_lane_king_state,
)
from kata.state_system.public_artifacts import (
    publish_public_king,
    resolve_kata_root,
    resolve_public_king_root,
)
from kata.submission_system import SUBMISSION_AGENT_FILENAME, SubmissionMetadata
from kata.validator_system import ChallengeSummary
from kata.validator_system.challenge import record_sn60_lane_provenance


@dataclass(frozen=True)
class LanePromotionResult:
    lane_id: str
    king_root: str
    king: LaneKingState


def find_evaluator_pack_entry(
    repo_pack: str,
    mode: str,
    *,
    public_root: str | None = None,
) -> PackRegistryEntry | None:
    # A missing registry loads as empty (returns None below); a corrupt registry
    # must surface loudly so production does not close valid PRs for the wrong
    # reason.
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
            f"No evaluator-backed lane is registered in the pack registry for `{repo_pack}/{mode}`."
        ]
    if not entry.active:
        return [f"Evaluator-backed lane is not active in the pack registry: {entry.lane_id}"]
    return []


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
    king_root = resolve_public_king_root(public_root=public_root, repo_pack=repo_pack, mode=mode)
    if (king_root / SUBMISSION_AGENT_FILENAME).exists():
        return hash_submission_bundle(king_root)
    return None


def resolve_sn60_king_artifact(metadata: SubmissionMetadata) -> tuple[str, str]:
    """Resolve (lane_id, king_artifact_path) for an SN60 duel from the pack registry."""
    entry = find_evaluator_pack_entry(metadata.repo_pack, metadata.mode)
    if entry is None:
        raise ValueError(
            f"No evaluator-backed lane is registered for `{metadata.repo_pack}/{metadata.mode}`."
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


def promote_lane_king(
    *,
    entry: PackRegistryEntry,
    verification,
    summary: ChallengeSummary,
    public_root: str | None = None,
) -> LanePromotionResult:
    record_promotion_lane_provenance(
        entry=entry,
        verification=verification,
        summary=summary,
        public_root=public_root,
    )
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


def record_promotion_lane_provenance(
    *,
    entry: PackRegistryEntry,
    verification,
    summary: ChallengeSummary,
    public_root: str | None,
) -> None:
    """Persist lane challenge/promotion records for a promoted round winner."""
    duel_summary = load_sn60_duel_summary(summary.primary.run_summary_path)
    screening_result = {
        "schema_version": 1,
        "run_id": summary.run_id,
        "status": "passed",
        "stage": "round",
        "artifact_path": verification.submission_path,
        "artifact_hash": verification.candidate_artifact_hash,
        "project_key": None,
        "report_path": None,
        "result_path": None,
        "reasons": [],
        "details": {"source": "promotion"},
        "sandbox_source": {
            "sandbox_root": duel_summary.sandbox_source.sandbox_root,
            "benchmark_file": duel_summary.sandbox_source.benchmark_file,
            "benchmark_sha256": duel_summary.sandbox_source.benchmark_sha256,
            "sandbox_commit": duel_summary.sandbox_source.sandbox_commit,
            "scorer_version": duel_summary.sandbox_source.scorer_version,
        },
        "created_at": summary.created_at,
    }
    record_sn60_lane_provenance(
        lane_id=entry.lane_id,
        candidate_submission_id=verification.submission_id,
        duel_summary=duel_summary,
        screening_result=screening_result,
        public_root=public_root,
    )


def load_sn60_duel_summary(path: str) -> Sn60DuelSummary:
    payload = json.loads(Path(path).expanduser().resolve().read_text(encoding="utf-8"))
    return Sn60DuelSummary(
        schema_version=int(payload["schema_version"]),
        run_id=str(payload["run_id"]),
        created_at=str(payload["created_at"]),
        output_root=str(payload["output_root"]),
        project_keys=[str(item) for item in payload.get("project_keys") or []],
        replicas_per_project=int(payload["replicas_per_project"]),
        sandbox_source=Sn60SandboxSource(**dict(payload["sandbox_source"])),
        king=parse_sn60_variant_summary(payload["king"]),
        candidate=parse_sn60_variant_summary(payload["candidate"]),
    )


def parse_sn60_variant_summary(payload: dict[str, object]) -> Sn60VariantSummary:
    return Sn60VariantSummary(
        variant_name=str(payload["variant_name"]),
        artifact_path=str(payload["artifact_path"]),
        artifact_hash=str(payload["artifact_hash"]),
        successful_runs=int(payload["successful_runs"]),
        invalid_runs=int(payload["invalid_runs"]),
        pass_count=int(payload["pass_count"]),
        codebase_pass_count=int(payload["codebase_pass_count"]),
        aggregated_score=float(payload["aggregated_score"]),
        average_detection_rate=float(payload["average_detection_rate"]),
        true_positives=int(payload["true_positives"]),
        total_expected=int(payload["total_expected"]),
        total_found=int(payload["total_found"]),
        precision=float(payload["precision"]),
        f1_score=float(payload["f1_score"]),
        project_summaries=[
            Sn60ProjectAggregate(**dict(item))
            for item in payload.get("project_summaries") or []
            if isinstance(item, dict)
        ],
        replica_results=[
            Sn60ReplicaResult(**dict(item))
            for item in payload.get("replica_results") or []
            if isinstance(item, dict)
        ],
    )
