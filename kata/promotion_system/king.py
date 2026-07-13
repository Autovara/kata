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
    KING_METADATA_FILENAME,
    PublicKingMetadata,
    publish_public_king,
    resolve_kata_root,
    resolve_public_king_root,
)
from kata.submission_system import SUBMISSION_AGENT_FILENAME, SubmissionMetadata
from kata.submission_system.bundle import load_bundle_files, replace_bundle_contents
from kata.validator_system import ChallengeSummary
from kata.validator_system.challenge import record_sn60_lane_provenance


@dataclass(frozen=True)
class CurrentKingInfo:
    lane_id: str
    repo_pack: str
    mode: str
    submission_id: str | None
    artifact_hash: str | None
    promotion_timestamp: str | None
    challenge_run_id: str | None
    king_root: str


@dataclass(frozen=True)
class KingExportResult:
    lane_id: str
    submission_id: str
    output_path: str
    artifact_hash: str


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


def load_current_king_info(
    lane_id: str,
    *,
    public_root: str | None = None,
) -> CurrentKingInfo:
    """Load the current king metadata for a registered lane."""
    registry = load_pack_registry(public_root=public_root)
    entry = next((pack for pack in registry.packs if pack.lane_id == lane_id), None)
    if entry is None:
        raise ValueError(f"No lane is registered with id `{lane_id}`.")
    king_root = resolve_public_king_root(
        public_root=public_root,
        repo_pack=entry.repo_pack,
        mode=entry.mode,
    )
    lane_king = maybe_load_lane_king_state(lane_id, public_root=public_root)
    public_metadata = maybe_load_public_king_metadata(king_root)
    return CurrentKingInfo(
        lane_id=lane_id,
        repo_pack=entry.repo_pack,
        mode=entry.mode,
        submission_id=lane_king.current_king_submission_id if lane_king else None,
        artifact_hash=lane_king.current_king_artifact_hash if lane_king else None,
        promotion_timestamp=lane_king.promotion_timestamp if lane_king else None,
        challenge_run_id=public_metadata.challenge_run_id if public_metadata else None,
        king_root=str(king_root),
    )


def export_lane_king(
    lane_id: str,
    *,
    output_path: str,
    public_root: str | None = None,
) -> KingExportResult:
    """Copy the published king bundle to a local directory for mining."""
    info = load_current_king_info(lane_id, public_root=public_root)
    if info.submission_id is None:
        raise ValueError(f"Lane `{lane_id}` has no crowned king to export.")
    king_root = Path(info.king_root)
    if not (king_root / SUBMISSION_AGENT_FILENAME).exists():
        raise ValueError(
            f"King artifact is missing at {king_root}. "
            "Seed the current king under kings/<subnet-pack>/<mode>/ before exporting."
        )
    destination = Path(output_path).expanduser().resolve()
    replace_bundle_contents(destination, load_bundle_files(king_root))
    artifact_hash = info.artifact_hash or hash_bundle_root(destination)
    return KingExportResult(
        lane_id=lane_id,
        submission_id=info.submission_id,
        output_path=str(destination),
        artifact_hash=artifact_hash,
    )


def maybe_load_lane_king_state(
    lane_id: str,
    *,
    public_root: str | None,
) -> LaneKingState | None:
    path = lane_king_state_path(lane_id, public_root=public_root)
    if not path.exists():
        return None
    return load_lane_king_state(lane_id, public_root=public_root)


def maybe_load_public_king_metadata(king_root: Path) -> PublicKingMetadata | None:
    metadata_path = king_root / KING_METADATA_FILENAME
    if not metadata_path.exists():
        return None
    payload = json.loads(metadata_path.read_text(encoding="utf-8"))
    return PublicKingMetadata(
        repo_pack=str(payload["repo_pack"]),
        mode=str(payload["mode"]),
        submission_id=str(payload["submission_id"]),
        challenge_run_id=str(payload["challenge_run_id"]),
        king_artifact_hash=str(payload["king_artifact_hash"]),
        candidate_artifact_hash=str(payload["candidate_artifact_hash"]),
    )


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
    king_payload = payload["king"]
    if (
        isinstance(king_payload, dict)
        and king_payload.get("evaluation_skipped") is True
        and "variant_name" not in king_payload
    ):
        king_payload = skipped_king_variant_payload(king_payload)
    return Sn60DuelSummary(
        schema_version=int(payload["schema_version"]),
        run_id=str(payload["run_id"]),
        created_at=str(payload["created_at"]),
        output_root=str(payload["output_root"]),
        project_keys=[str(item) for item in payload.get("project_keys") or []],
        replicas_per_project=int(payload["replicas_per_project"]),
        sandbox_source=Sn60SandboxSource(**dict(payload["sandbox_source"])),
        king=parse_sn60_variant_summary(king_payload),
        candidate=parse_sn60_variant_summary(payload["candidate"]),
    )


def skipped_king_variant_payload(payload: dict[str, object]) -> dict[str, object]:
    return {
        "variant_name": "king",
        "artifact_path": str(payload["artifact_path"]),
        "artifact_hash": str(payload["artifact_hash"]),
        "successful_runs": 0,
        "invalid_runs": 0,
        "pass_count": 0,
        "codebase_pass_count": 0,
        "aggregated_score": 0.0,
        "average_detection_rate": 0.0,
        "true_positives": 0,
        "total_expected": 0,
        "total_found": 0,
        "precision": 0.0,
        "f1_score": 0.0,
        "project_summaries": [],
        "replica_results": [],
    }


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
