"""Turning lane state into JSON and back, with validation.

Separated from the store because parsing is where a corrupt or stale file is REFUSED, and that
decision should be readable without the surrounding read/write machinery. Every parser here is
strict: an unexpected shape raises rather than being coerced into a default that would look like
healthy state.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from kata.state.lanes.models import (
    BenchmarkSnapshotState,
    ChallengeState,
    EvaluatorLaneMetadata,
    LaneKingState,
    PackRegistry,
    PackRegistryEntry,
    PromotionRecord,
    validate_lane_id,
)
from kata.util import write_json


def maybe_load(path: Path, parser):
    if not path.exists():
        return None
    return parser(read_json(path))


def write_json_dataclass(path: Path, value) -> Path:
    return write_json(path, asdict(value))


def serialize_pack_registry(registry: PackRegistry) -> dict[str, object]:
    return asdict(registry)


def serialize_lane_metadata(metadata: EvaluatorLaneMetadata) -> dict[str, object]:
    return asdict(metadata)


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
                subnet_pack=read_subnet_pack_field(entry),
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
        subnet_pack=read_subnet_pack_field(payload),
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
