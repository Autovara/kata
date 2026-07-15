from __future__ import annotations

import json
from pathlib import Path

import pytest

from kata.state.lanes import (
    BENCHMARK_SNAPSHOT_SCHEMA_VERSION,
    CHALLENGE_STATE_SCHEMA_VERSION,
    KING_STATE_SCHEMA_VERSION,
    LANE_METADATA_SCHEMA_VERSION,
    PACK_REGISTRY_SCHEMA_VERSION,
    PROMOTION_RECORD_SCHEMA_VERSION,
    BenchmarkSnapshotState,
    ChallengeState,
    EvaluatorLaneMetadata,
    LaneKingState,
    PromotionRecord,
    discover_active_lane_ids,
    list_lane_ids,
    load_benchmark_snapshot,
    load_challenge_state,
    load_evaluator_lane_state,
    load_lane_king_state,
    load_lane_metadata,
    load_pack_registry,
    load_promotion_record,
    pack_registry_path,
    promotion_record_path,
    resolve_lane_root,
    resolve_lanes_root,
    sync_pack_registry,
    validate_lane_id,
    write_benchmark_snapshot,
    write_challenge_state,
    write_lane_king_state,
    write_lane_metadata,
    write_promotion_record,
)


def test_write_and_load_evaluator_lane_state_round_trip(tmp_path: Path) -> None:
    lane = EvaluatorLaneMetadata(
        schema_version=LANE_METADATA_SCHEMA_VERSION,
        lane_id="sn60__bitsec",
        repo_pack="sn60__bitsec",
        mode="miner",
        evaluator_id="sn60_bitsec",
        evaluator_policy_version="v1",
        active=True,
        created_at="2026-07-01T00:00:00+00:00",
        updated_at="2026-07-01T00:00:00+00:00",
    )
    king = LaneKingState(
        schema_version=KING_STATE_SCHEMA_VERSION,
        current_king_submission_id="alice-20260701-01",
        current_king_artifact_hash="king-hash",
        promotion_source_pr="42",
        promotion_timestamp="2026-07-01T01:00:00+00:00",
        updated_at="2026-07-01T01:00:00+00:00",
    )
    snapshot = BenchmarkSnapshotState(
        schema_version=BENCHMARK_SNAPSHOT_SCHEMA_VERSION,
        sandbox_mirror_source="sandbox/",
        sandbox_commit_hash="abc123",
        benchmark_dataset_id="curated-highs-only-2025-08-08",
        benchmark_dataset_hash="dataset-hash",
        project_list_hash="projects-hash",
        project_keys=["p1", "p2"],
        container_images=["ghcr.io/bitsec-ai/p1:latest"],
        scorer_version="scorer-v2",
        updated_at="2026-07-01T01:30:00+00:00",
    )
    challenge = ChallengeState(
        schema_version=CHALLENGE_STATE_SCHEMA_VERSION,
        candidate_submission_id="bob-20260701-01",
        candidate_artifact_hash="candidate-hash",
        king_artifact_hash="king-hash",
        screening_result={"status": "passed", "reason": "ok"},
        selected_project_keys=["p1", "p2"],
        validator_replica_count=3,
        run_ids=["run-a", "run-b"],
        freshness_fingerprint="fresh-hash",
        updated_at="2026-07-01T02:00:00+00:00",
    )
    promotion = PromotionRecord(
        schema_version=PROMOTION_RECORD_SCHEMA_VERSION,
        final_metrics={"aggregated_score": 0.75},
        local_replica_scores={"candidate": [0.75, 0.5, 1.0], "king": [0.5, 0.5, 0.25]},
        pass_counts={"candidate": 3, "king": 2},
        true_positives={"candidate": 11, "king": 8},
        invalid_runs={"candidate": 0, "king": 1},
        final_winner="candidate",
        recorded_at="2026-07-01T03:00:00+00:00",
    )

    write_lane_metadata(lane, public_root=str(tmp_path))
    write_lane_king_state(lane.lane_id, king, public_root=str(tmp_path))
    write_benchmark_snapshot(lane.lane_id, snapshot, public_root=str(tmp_path))
    write_challenge_state(lane.lane_id, challenge, public_root=str(tmp_path))
    write_promotion_record(lane.lane_id, promotion, public_root=str(tmp_path))

    assert load_lane_metadata(lane.lane_id, public_root=str(tmp_path)) == lane
    assert load_lane_king_state(lane.lane_id, public_root=str(tmp_path)) == king
    assert load_benchmark_snapshot(lane.lane_id, public_root=str(tmp_path)) == snapshot
    assert load_challenge_state(lane.lane_id, public_root=str(tmp_path)) == challenge
    assert load_promotion_record(lane.lane_id, public_root=str(tmp_path)) == promotion

    loaded = load_evaluator_lane_state(lane.lane_id, public_root=str(tmp_path))
    assert loaded.lane == lane
    assert loaded.king == king
    assert loaded.benchmark_snapshot == snapshot
    assert loaded.challenge_state == challenge
    assert loaded.promotion_record == promotion


def test_load_promotion_record_ignores_legacy_reward_label_metadata(
    tmp_path: Path,
) -> None:
    path = promotion_record_path("sn60__bitsec", public_root=str(tmp_path))
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps(
            {
                "schema_version": PROMOTION_RECORD_SCHEMA_VERSION,
                "final_metrics": {},
                "local_replica_scores": {"candidate": [], "king": []},
                "pass_counts": {"candidate": 0, "king": 0},
                "true_positives": {"candidate": 0, "king": 0},
                "invalid_runs": {"candidate": 0, "king": 0},
                "final_winner": "king",
                "reward_label_applied": "kata:reward:xl",
                "recorded_at": "2026-07-01T03:00:00+00:00",
            }
        ),
        encoding="utf-8",
    )

    record = load_promotion_record("sn60__bitsec", public_root=str(tmp_path))

    assert record.final_winner == "king"


def test_lane_discovery_filters_for_lane_metadata_and_active_state(tmp_path: Path) -> None:
    active_lane = EvaluatorLaneMetadata(
        schema_version=LANE_METADATA_SCHEMA_VERSION,
        lane_id="sn60__bitsec",
        repo_pack="sn60__bitsec",
        mode="miner",
        evaluator_id="sn60_bitsec",
        evaluator_policy_version="v1",
        active=True,
        created_at="2026-07-01T00:00:00+00:00",
        updated_at="2026-07-01T00:00:00+00:00",
    )
    inactive_lane = EvaluatorLaneMetadata(
        schema_version=LANE_METADATA_SCHEMA_VERSION,
        lane_id="legacy__repo",
        repo_pack="legacy__repo",
        mode="contributor",
        evaluator_id="repo_repair",
        evaluator_policy_version="v1",
        active=False,
        created_at="2026-07-01T00:00:00+00:00",
        updated_at="2026-07-01T00:00:00+00:00",
    )
    write_lane_metadata(active_lane, public_root=str(tmp_path))
    write_lane_metadata(inactive_lane, public_root=str(tmp_path))

    stray_dir = resolve_lanes_root(str(tmp_path)) / "stray"
    stray_dir.mkdir(parents=True)
    (stray_dir / "note.txt").write_text("ignore me\n", encoding="utf-8")

    assert list_lane_ids(public_root=str(tmp_path)) == ["legacy__repo", "sn60__bitsec"]
    assert discover_active_lane_ids(public_root=str(tmp_path)) == ["sn60__bitsec"]


def test_load_evaluator_lane_state_leaves_optional_files_absent(tmp_path: Path) -> None:
    lane = EvaluatorLaneMetadata(
        schema_version=LANE_METADATA_SCHEMA_VERSION,
        lane_id="sn60__bitsec",
        repo_pack="sn60__bitsec",
        mode="miner",
        evaluator_id="sn60_bitsec",
        evaluator_policy_version="v1",
        active=True,
        created_at="2026-07-01T00:00:00+00:00",
        updated_at="2026-07-01T00:00:00+00:00",
    )
    write_lane_metadata(lane, public_root=str(tmp_path))

    state = load_evaluator_lane_state(lane.lane_id, public_root=str(tmp_path))
    assert state.lane == lane
    assert state.king is None
    assert state.benchmark_snapshot is None
    assert state.challenge_state is None
    assert state.promotion_record is None


def test_validate_lane_id_rejects_invalid_values() -> None:
    with pytest.raises(ValueError, match="non-empty"):
        validate_lane_id("")
    with pytest.raises(ValueError, match="surrounding whitespace"):
        validate_lane_id(" sn60__bitsec ")
    with pytest.raises(ValueError, match="path separators"):
        validate_lane_id("sn60__bitsec/miner")


def test_resolve_lane_root_uses_public_root(tmp_path: Path) -> None:
    lane_root = resolve_lane_root("sn60__bitsec", public_root=str(tmp_path))
    assert lane_root == tmp_path / "lanes" / "sn60__bitsec"


def test_load_lane_metadata_requires_boolean_active_field(tmp_path: Path) -> None:
    lane_root = resolve_lane_root("sn60__bitsec", public_root=str(tmp_path))
    lane_root.mkdir(parents=True, exist_ok=True)
    (lane_root / "lane.json").write_text(
        """
{
  "schema_version": 1,
  "lane_id": "sn60__bitsec",
  "repo_pack": "sn60__bitsec",
  "mode": "miner",
  "evaluator_id": "sn60_bitsec",
  "evaluator_policy_version": "v1",
  "active": "false",
  "created_at": "2026-07-01T00:00:00+00:00",
  "updated_at": "2026-07-01T00:00:00+00:00"
}
""".strip()
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="JSON boolean"):
        load_lane_metadata("sn60__bitsec", public_root=str(tmp_path))


def test_load_lane_metadata_accepts_subnet_pack_field(tmp_path: Path) -> None:
    lane_root = resolve_lane_root("sn60__bitsec", public_root=str(tmp_path))
    lane_root.mkdir(parents=True, exist_ok=True)
    (lane_root / "lane.json").write_text(
        """
{
  "schema_version": 1,
  "lane_id": "sn60__bitsec",
  "subnet_pack": "sn60__bitsec",
  "mode": "miner",
  "evaluator_id": "sn60_bitsec",
  "evaluator_policy_version": "v1",
  "active": true,
  "created_at": "2026-07-01T00:00:00+00:00",
  "updated_at": "2026-07-01T00:00:00+00:00"
}
""".strip()
        + "\n",
        encoding="utf-8",
    )

    metadata = load_lane_metadata("sn60__bitsec", public_root=str(tmp_path))

    assert metadata.repo_pack == "sn60__bitsec"


def build_lane_metadata(
    lane_id: str,
    *,
    active: bool = True,
    evaluator_id: str = "sn60_bitsec",
    updated_at: str = "2026-07-01T00:00:00+00:00",
) -> EvaluatorLaneMetadata:
    return EvaluatorLaneMetadata(
        schema_version=LANE_METADATA_SCHEMA_VERSION,
        lane_id=lane_id,
        repo_pack=lane_id,
        mode="miner",
        evaluator_id=evaluator_id,
        evaluator_policy_version="v1",
        active=active,
        created_at="2026-07-01T00:00:00+00:00",
        updated_at=updated_at,
    )


def test_write_lane_metadata_registers_pack_in_central_registry(tmp_path: Path) -> None:
    write_lane_metadata(build_lane_metadata("sn60__bitsec"), public_root=str(tmp_path))

    registry_path = pack_registry_path(public_root=str(tmp_path))
    assert registry_path == resolve_lanes_root(str(tmp_path)) / "registry.json"
    assert registry_path.exists()
    lane_payload = json.loads(
        (resolve_lane_root("sn60__bitsec", public_root=str(tmp_path)) / "lane.json").read_text(
            encoding="utf-8"
        )
    )
    registry_payload = json.loads(registry_path.read_text(encoding="utf-8"))
    assert lane_payload["subnet_pack"] == "sn60__bitsec"
    assert "repo_pack" not in lane_payload
    assert registry_payload["packs"][0]["subnet_pack"] == "sn60__bitsec"
    assert "repo_pack" not in registry_payload["packs"][0]

    registry = load_pack_registry(public_root=str(tmp_path))
    assert registry.schema_version == PACK_REGISTRY_SCHEMA_VERSION
    assert [pack.lane_id for pack in registry.packs] == ["sn60__bitsec"]
    assert registry.packs[0].evaluator_id == "sn60_bitsec"
    assert registry.packs[0].active is True


def test_lane_discovery_uses_registry_only(tmp_path: Path) -> None:
    write_lane_metadata(build_lane_metadata("sn60__bitsec"), public_root=str(tmp_path))

    # A lane directory with valid lane.json but no registry entry must NOT be
    # discovered: the central registry is the only discovery source.
    orphan_root = resolve_lanes_root(str(tmp_path)) / "orphan__lane"
    orphan_root.mkdir(parents=True)
    (orphan_root / "lane.json").write_text(
        (resolve_lane_root("sn60__bitsec", public_root=str(tmp_path)) / "lane.json")
        .read_text(encoding="utf-8")
        .replace("sn60__bitsec", "orphan__lane"),
        encoding="utf-8",
    )

    assert list_lane_ids(public_root=str(tmp_path)) == ["sn60__bitsec"]
    assert discover_active_lane_ids(public_root=str(tmp_path)) == ["sn60__bitsec"]

    # After a registry sync the orphan lane is registered again.
    sync_pack_registry(public_root=str(tmp_path))
    assert list_lane_ids(public_root=str(tmp_path)) == ["orphan__lane", "sn60__bitsec"]


def test_registry_upsert_updates_active_flag_without_duplicates(tmp_path: Path) -> None:
    write_lane_metadata(build_lane_metadata("sn60__bitsec"), public_root=str(tmp_path))
    write_lane_metadata(
        build_lane_metadata("sn60__bitsec", active=False, updated_at="2026-07-02T00:00:00+00:00"),
        public_root=str(tmp_path),
    )

    registry = load_pack_registry(public_root=str(tmp_path))
    assert [pack.lane_id for pack in registry.packs] == ["sn60__bitsec"]
    assert registry.packs[0].active is False
    assert registry.updated_at == "2026-07-02T00:00:00+00:00"
    assert discover_active_lane_ids(public_root=str(tmp_path)) == []


def test_load_pack_registry_returns_empty_registry_when_missing(tmp_path: Path) -> None:
    registry = load_pack_registry(public_root=str(tmp_path))
    assert registry.packs == []
    assert list_lane_ids(public_root=str(tmp_path)) == []
    assert discover_active_lane_ids(public_root=str(tmp_path)) == []
