"""Lane registry, king state, and benchmark snapshot persistence."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from kata.state.artifacts import resolve_kata_root
from kata.util import write_json

LANES_DIRNAME = "lanes"
PACK_REGISTRY_FILENAME = "registry.json"
LANE_METADATA_FILENAME = "lane.json"
KING_STATE_FILENAME = "king.json"
BENCHMARK_SNAPSHOT_FILENAME = "benchmark_snapshot.json"
CHALLENGE_STATE_FILENAME = "challenge_state.json"
PROMOTION_RECORD_FILENAME = "promotion_record.json"

PACK_REGISTRY_SCHEMA_VERSION = 1
LANE_METADATA_SCHEMA_VERSION = 1
KING_STATE_SCHEMA_VERSION = 1
BENCHMARK_SNAPSHOT_SCHEMA_VERSION = 1
CHALLENGE_STATE_SCHEMA_VERSION = 1
PROMOTION_RECORD_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class PackRegistryEntry:
    lane_id: str
    repo_pack: str
    mode: str
    evaluator_id: str
    active: bool


@dataclass(frozen=True)
class PackRegistry:
    schema_version: int
    packs: list[PackRegistryEntry]
    updated_at: str


@dataclass(frozen=True)
class EvaluatorLaneMetadata:
    schema_version: int
    lane_id: str
    repo_pack: str
    mode: str
    evaluator_id: str
    evaluator_policy_version: str
    active: bool
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class LaneKingState:
    schema_version: int
    current_king_submission_id: str | None
    current_king_artifact_hash: str | None
    promotion_source_pr: str | None
    promotion_timestamp: str | None
    updated_at: str


@dataclass(frozen=True)
class BenchmarkSnapshotState:
    schema_version: int
    sandbox_mirror_source: str
    sandbox_commit_hash: str
    benchmark_dataset_id: str | None
    benchmark_dataset_hash: str
    project_list_hash: str
    project_keys: list[str] = field(default_factory=list)
    container_images: list[str] = field(default_factory=list)
    scorer_version: str | None = None
    updated_at: str = ""


@dataclass(frozen=True)
class ChallengeState:
    schema_version: int
    candidate_submission_id: str
    candidate_artifact_hash: str
    king_artifact_hash: str
    screening_result: dict[str, object]
    selected_project_keys: list[str]
    validator_replica_count: int
    run_ids: list[str]
    freshness_fingerprint: str
    updated_at: str


@dataclass(frozen=True)
class PromotionRecord:
    schema_version: int
    final_metrics: dict[str, object]
    local_replica_scores: dict[str, list[float]]
    pass_counts: dict[str, int]
    true_positives: dict[str, int]
    invalid_runs: dict[str, int]
    final_winner: str
    recorded_at: str


@dataclass(frozen=True)
class EvaluatorLaneState:
    lane: EvaluatorLaneMetadata
    king: LaneKingState | None = None
    benchmark_snapshot: BenchmarkSnapshotState | None = None
    challenge_state: ChallengeState | None = None
    promotion_record: PromotionRecord | None = None


def resolve_lanes_root(public_root: str | None = None) -> Path:
    return resolve_kata_root(public_root) / LANES_DIRNAME


def pack_registry_path(*, public_root: str | None = None) -> Path:
    return resolve_lanes_root(public_root) / PACK_REGISTRY_FILENAME


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
        repo_pack=metadata.repo_pack,
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
                    repo_pack=metadata.repo_pack,
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


def resolve_lane_root(lane_id: str, *, public_root: str | None = None) -> Path:
    validate_lane_id(lane_id)
    return resolve_lanes_root(public_root) / lane_id


def lane_metadata_path(lane_id: str, *, public_root: str | None = None) -> Path:
    return resolve_lane_root(lane_id, public_root=public_root) / LANE_METADATA_FILENAME


def lane_king_state_path(lane_id: str, *, public_root: str | None = None) -> Path:
    return resolve_lane_root(lane_id, public_root=public_root) / KING_STATE_FILENAME


def benchmark_snapshot_path(lane_id: str, *, public_root: str | None = None) -> Path:
    return resolve_lane_root(lane_id, public_root=public_root) / BENCHMARK_SNAPSHOT_FILENAME


def challenge_state_path(lane_id: str, *, public_root: str | None = None) -> Path:
    return resolve_lane_root(lane_id, public_root=public_root) / CHALLENGE_STATE_FILENAME


def promotion_record_path(lane_id: str, *, public_root: str | None = None) -> Path:
    return resolve_lane_root(lane_id, public_root=public_root) / PROMOTION_RECORD_FILENAME


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


def validate_lane_id(lane_id: str) -> None:
    normalized = lane_id.strip()
    if not normalized:
        raise ValueError("Lane id must be a non-empty string.")
    if normalized != lane_id:
        raise ValueError("Lane id must not include surrounding whitespace.")
    parts = normalized.split("/")
    if len(parts) != 1:
        raise ValueError("Lane id must not contain path separators.")
    if normalized in {".", ".."}:
        raise ValueError("Lane id is invalid.")


def maybe_load(path: Path, parser):
    if not path.exists():
        return None
    return parser(read_json(path))


def write_json_dataclass(path: Path, value) -> Path:
    return write_json(path, asdict(value))


def serialize_pack_registry(registry: PackRegistry) -> dict[str, object]:
    payload = asdict(registry)
    packs = payload.get("packs")
    if isinstance(packs, list):
        for pack in packs:
            if isinstance(pack, dict):
                pack["subnet_pack"] = pack.pop("repo_pack")
    return payload


def serialize_lane_metadata(metadata: EvaluatorLaneMetadata) -> dict[str, object]:
    payload = asdict(metadata)
    payload["subnet_pack"] = payload.pop("repo_pack")
    return payload


def read_json(path: Path) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"Expected a JSON object in {path}.")
    return payload


def parse_pack_registry(payload: dict[str, object]) -> PackRegistry:
    packs_payload = payload.get("packs")
    if not isinstance(packs_payload, list):
        raise ValueError("Pack registry requires `packs` to be a JSON array.")
    packs: list[PackRegistryEntry] = []
    for entry in packs_payload:
        if not isinstance(entry, dict):
            raise ValueError("Pack registry entries must be JSON objects.")
        lane_id = str(entry["lane_id"])
        validate_lane_id(lane_id)
        packs.append(
            PackRegistryEntry(
                lane_id=lane_id,
                repo_pack=read_subnet_pack_field(entry),
                mode=str(entry["mode"]),
                evaluator_id=str(entry["evaluator_id"]),
                active=require_bool(entry["active"], field_name="active"),
            )
        )
    return PackRegistry(
        schema_version=int(payload["schema_version"]),
        packs=packs,
        updated_at=str(payload.get("updated_at", "")),
    )


def parse_lane_metadata(payload: dict[str, object]) -> EvaluatorLaneMetadata:
    lane_id = str(payload["lane_id"])
    validate_lane_id(lane_id)
    return EvaluatorLaneMetadata(
        schema_version=int(payload["schema_version"]),
        lane_id=lane_id,
        repo_pack=read_subnet_pack_field(payload),
        mode=str(payload["mode"]),
        evaluator_id=str(payload["evaluator_id"]),
        evaluator_policy_version=str(payload["evaluator_policy_version"]),
        active=require_bool(payload["active"], field_name="active"),
        created_at=str(payload["created_at"]),
        updated_at=str(payload["updated_at"]),
    )


def parse_lane_king_state(payload: dict[str, object]) -> LaneKingState:
    return LaneKingState(
        schema_version=int(payload["schema_version"]),
        current_king_submission_id=optional_string(payload.get("current_king_submission_id")),
        current_king_artifact_hash=optional_string(payload.get("current_king_artifact_hash")),
        promotion_source_pr=optional_string(payload.get("promotion_source_pr")),
        promotion_timestamp=optional_string(payload.get("promotion_timestamp")),
        updated_at=str(payload["updated_at"]),
    )


def parse_benchmark_snapshot(payload: dict[str, object]) -> BenchmarkSnapshotState:
    return BenchmarkSnapshotState(
        schema_version=int(payload["schema_version"]),
        sandbox_mirror_source=str(payload["sandbox_mirror_source"]),
        sandbox_commit_hash=str(payload["sandbox_commit_hash"]),
        benchmark_dataset_id=optional_string(payload.get("benchmark_dataset_id")),
        benchmark_dataset_hash=str(payload["benchmark_dataset_hash"]),
        project_list_hash=str(payload["project_list_hash"]),
        project_keys=string_list(payload.get("project_keys")),
        container_images=string_list(payload.get("container_images")),
        scorer_version=optional_string(payload.get("scorer_version")),
        updated_at=str(payload["updated_at"]),
    )


def parse_challenge_state(payload: dict[str, object]) -> ChallengeState:
    screening_result = payload.get("screening_result")
    if not isinstance(screening_result, dict):
        raise ValueError("Challenge state requires `screening_result` to be a JSON object.")
    return ChallengeState(
        schema_version=int(payload["schema_version"]),
        candidate_submission_id=str(payload["candidate_submission_id"]),
        candidate_artifact_hash=str(payload["candidate_artifact_hash"]),
        king_artifact_hash=str(payload["king_artifact_hash"]),
        screening_result=screening_result,
        selected_project_keys=string_list(payload.get("selected_project_keys")),
        validator_replica_count=int(payload["validator_replica_count"]),
        run_ids=string_list(payload.get("run_ids")),
        freshness_fingerprint=str(payload["freshness_fingerprint"]),
        updated_at=str(payload["updated_at"]),
    )


def parse_promotion_record(payload: dict[str, object]) -> PromotionRecord:
    final_metrics = payload.get("final_metrics")
    replica_scores = payload.get("local_replica_scores")
    pass_counts = payload.get("pass_counts")
    true_positives = payload.get("true_positives")
    invalid_runs = payload.get("invalid_runs")
    if not isinstance(final_metrics, dict):
        raise ValueError("Promotion record requires `final_metrics` to be a JSON object.")
    if not isinstance(replica_scores, dict):
        raise ValueError("Promotion record requires `local_replica_scores` to be a JSON object.")
    if not isinstance(pass_counts, dict):
        raise ValueError("Promotion record requires `pass_counts` to be a JSON object.")
    if not isinstance(true_positives, dict):
        raise ValueError("Promotion record requires `true_positives` to be a JSON object.")
    if not isinstance(invalid_runs, dict):
        raise ValueError("Promotion record requires `invalid_runs` to be a JSON object.")
    return PromotionRecord(
        schema_version=int(payload["schema_version"]),
        final_metrics=final_metrics,
        local_replica_scores=float_list_map(replica_scores),
        pass_counts=int_map(pass_counts),
        true_positives=int_map(true_positives),
        invalid_runs=int_map(invalid_runs),
        final_winner=str(payload["final_winner"]),
        recorded_at=str(payload["recorded_at"]),
    )


def string_list(value: object) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("Expected a JSON array of strings.")
    return [str(item) for item in value]


def int_map(value: dict[str, object]) -> dict[str, int]:
    return {str(key): int(item) for key, item in value.items()}


def float_list_map(value: dict[str, object]) -> dict[str, list[float]]:
    normalized: dict[str, list[float]] = {}
    for key, item in value.items():
        if not isinstance(item, list):
            raise ValueError("Expected replica score values to be JSON arrays.")
        normalized[str(key)] = [float(entry) for entry in item]
    return normalized


def optional_string(value: object) -> str | None:
    if value is None:
        return None
    return str(value)


def read_subnet_pack_field(payload: dict[str, object]) -> str:
    value = payload.get("subnet_pack", payload.get("repo_pack"))
    if value is None:
        raise KeyError("subnet_pack")
    return str(value)


def require_bool(value: object, *, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"Expected `{field_name}` to be a JSON boolean.")
    return value
