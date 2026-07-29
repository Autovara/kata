"""Lane state: the shapes, and the schema versions that identify them.

Deliberately free of I/O and path logic. These dataclasses are what every other module here agrees
on, and a model module that could touch the filesystem would make "what is a lane?" depend on where
one happens to be stored.
"""

from __future__ import annotations

from dataclasses import dataclass, field

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
    subnet_pack: str
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
    subnet_pack: str
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
