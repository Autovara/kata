"""Reading and writing lane state.

The only module here that touches the filesystem. It composes `paths` (where) with `codecs` (what),
so a change to either is visible as a change to one of them rather than as a diff spread across a
single large module.
"""

from __future__ import annotations

from pathlib import Path

from kata.state.lanes.codecs import (
    maybe_load,
    parse_benchmark_snapshot,
    parse_challenge_state,
    parse_lane_king_state,
    parse_lane_metadata,
    parse_pack_registry,
    parse_promotion_record,
    read_json,
    serialize_lane_metadata,
    serialize_pack_registry,
    write_json_dataclass,
)
from kata.state.lanes.models import (
    LANE_METADATA_FILENAME,
    PACK_REGISTRY_SCHEMA_VERSION,
    BenchmarkSnapshotState,
    ChallengeState,
    EvaluatorLaneMetadata,
    EvaluatorLaneState,
    LaneKingState,
    PackRegistry,
    PackRegistryEntry,
    PromotionRecord,
)
from kata.state.lanes.paths import (
    benchmark_snapshot_path,
    challenge_state_path,
    lane_king_state_path,
    lane_metadata_path,
    pack_registry_path,
    promotion_record_path,
    resolve_lanes_root,
)
from kata.util import write_json


def load_pack_registry(*, public_root: str | None = None) -> PackRegistry:
    path = pack_registry_path(public_root=public_root)
    if not path.exists():
        return PackRegistry(
            schema_version=PACK_REGISTRY_SCHEMA_VERSION,
            packs=[],
            updated_at="",
        )
    return parse_pack_registry(read_json(path))


def write_pack_registry(
    registry: PackRegistry,
    *,
    public_root: str | None = None,
) -> Path:
    return write_json(
        pack_registry_path(public_root=public_root),
        serialize_pack_registry(registry),
    )


def upsert_pack_registry_entry(
    metadata: EvaluatorLaneMetadata,
    *,
    public_root: str | None = None,
) -> Path:
    registry = load_pack_registry(public_root=public_root)
    entry = PackRegistryEntry(
        lane_id=metadata.lane_id,
        subnet_pack=metadata.subnet_pack,
        mode=metadata.mode,
        evaluator_id=metadata.evaluator_id,
        active=metadata.active,
    )
    packs = [pack for pack in registry.packs if pack.lane_id != entry.lane_id]
    packs.append(entry)
    packs.sort(key=lambda pack: pack.lane_id)
    return write_pack_registry(
        PackRegistry(
            schema_version=PACK_REGISTRY_SCHEMA_VERSION,
            packs=packs,
            updated_at=metadata.updated_at,
        ),
        public_root=public_root,
    )


def sync_pack_registry(*, public_root: str | None = None) -> PackRegistry:
    """Rebuild the pack registry from lane.json files on disk (migration/repair)."""
    lanes_root = resolve_lanes_root(public_root)
    packs: list[PackRegistryEntry] = []
    latest_updated_at = ""
    if lanes_root.exists():
        for child in sorted(lanes_root.iterdir(), key=lambda item: item.name):
            metadata_path = child / LANE_METADATA_FILENAME
            if not child.is_dir() or not metadata_path.exists():
                continue
            metadata = parse_lane_metadata(read_json(metadata_path))
            packs.append(
                PackRegistryEntry(
                    lane_id=metadata.lane_id,
                    subnet_pack=metadata.subnet_pack,
                    mode=metadata.mode,
                    evaluator_id=metadata.evaluator_id,
                    active=metadata.active,
                )
            )
            latest_updated_at = max(latest_updated_at, metadata.updated_at)
    registry = PackRegistry(
        schema_version=PACK_REGISTRY_SCHEMA_VERSION,
        packs=packs,
        updated_at=latest_updated_at,
    )
    write_pack_registry(registry, public_root=public_root)
    return registry


def write_lane_metadata(
    metadata: EvaluatorLaneMetadata,
    *,
    public_root: str | None = None,
) -> Path:
    path = lane_metadata_path(metadata.lane_id, public_root=public_root)
    written = write_json(path, serialize_lane_metadata(metadata))
    # The central pack registry is the only discovery source; keep it in sync
    # with every lane metadata write.
    upsert_pack_registry_entry(metadata, public_root=public_root)
    return written


def write_lane_king_state(
    lane_id: str,
    state: LaneKingState,
    *,
    public_root: str | None = None,
) -> Path:
    path = lane_king_state_path(lane_id, public_root=public_root)
    return write_json_dataclass(path, state)


def write_benchmark_snapshot(
    lane_id: str,
    snapshot: BenchmarkSnapshotState,
    *,
    public_root: str | None = None,
) -> Path:
    path = benchmark_snapshot_path(lane_id, public_root=public_root)
    return write_json_dataclass(path, snapshot)


def write_challenge_state(
    lane_id: str,
    state: ChallengeState,
    *,
    public_root: str | None = None,
) -> Path:
    path = challenge_state_path(lane_id, public_root=public_root)
    return write_json_dataclass(path, state)


def write_promotion_record(
    lane_id: str,
    record: PromotionRecord,
    *,
    public_root: str | None = None,
) -> Path:
    path = promotion_record_path(lane_id, public_root=public_root)
    return write_json_dataclass(path, record)


def load_lane_metadata(
    lane_id: str,
    *,
    public_root: str | None = None,
) -> EvaluatorLaneMetadata:
    payload = read_json(lane_metadata_path(lane_id, public_root=public_root))
    return parse_lane_metadata(payload)


def load_lane_king_state(
    lane_id: str,
    *,
    public_root: str | None = None,
) -> LaneKingState:
    payload = read_json(lane_king_state_path(lane_id, public_root=public_root))
    return parse_lane_king_state(payload)


def load_benchmark_snapshot(
    lane_id: str,
    *,
    public_root: str | None = None,
) -> BenchmarkSnapshotState:
    payload = read_json(benchmark_snapshot_path(lane_id, public_root=public_root))
    return parse_benchmark_snapshot(payload)


def load_challenge_state(
    lane_id: str,
    *,
    public_root: str | None = None,
) -> ChallengeState:
    payload = read_json(challenge_state_path(lane_id, public_root=public_root))
    return parse_challenge_state(payload)


def load_promotion_record(
    lane_id: str,
    *,
    public_root: str | None = None,
) -> PromotionRecord:
    payload = read_json(promotion_record_path(lane_id, public_root=public_root))
    return parse_promotion_record(payload)


def load_evaluator_lane_state(
    lane_id: str,
    *,
    public_root: str | None = None,
) -> EvaluatorLaneState:
    return EvaluatorLaneState(
        lane=load_lane_metadata(lane_id, public_root=public_root),
        king=maybe_load(
            lane_king_state_path(lane_id, public_root=public_root),
            parse_lane_king_state,
        ),
        benchmark_snapshot=maybe_load(
            benchmark_snapshot_path(lane_id, public_root=public_root),
            parse_benchmark_snapshot,
        ),
        challenge_state=maybe_load(
            challenge_state_path(lane_id, public_root=public_root),
            parse_challenge_state,
        ),
        promotion_record=maybe_load(
            promotion_record_path(lane_id, public_root=public_root),
            parse_promotion_record,
        ),
    )


def list_lane_ids(*, public_root: str | None = None) -> list[str]:
    registry = load_pack_registry(public_root=public_root)
    return [pack.lane_id for pack in registry.packs]


def discover_active_lane_ids(*, public_root: str | None = None) -> list[str]:
    registry = load_pack_registry(public_root=public_root)
    return [pack.lane_id for pack in registry.packs if pack.active]


