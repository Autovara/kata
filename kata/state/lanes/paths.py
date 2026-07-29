"""Where each lane artifact lives under the competition root.

Pure functions of a root and a lane id. Nothing here reads or writes, so a caller can ask "which
file would this be?" without creating it.
"""

from __future__ import annotations

from pathlib import Path

from kata.state.artifacts import resolve_kata_root
from kata.state.lanes.models import (
    BENCHMARK_SNAPSHOT_FILENAME,
    CHALLENGE_STATE_FILENAME,
    KING_STATE_FILENAME,
    LANE_METADATA_FILENAME,
    LANES_DIRNAME,
    PACK_REGISTRY_FILENAME,
    PROMOTION_RECORD_FILENAME,
    validate_lane_id,
)


def resolve_lanes_root(public_root: str | None = None) -> Path:
    return resolve_kata_root(public_root) / LANES_DIRNAME


def pack_registry_path(*, public_root: str | None = None) -> Path:
    return resolve_lanes_root(public_root) / PACK_REGISTRY_FILENAME


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
