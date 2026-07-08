from __future__ import annotations

import json
import types
from pathlib import Path

from kata.evaluators.sn60_bitsec import hash_bundle_root
from kata.promotion_system import (
    find_evaluator_pack_entry,
    promote_lane_king,
    resolve_sn60_lane_king_hash,
    validate_submission_lane,
)
from kata.screening_system.rules import hash_submission_bundle
from kata.state_system.lane import (
    LANE_METADATA_SCHEMA_VERSION,
    EvaluatorLaneMetadata,
    load_challenge_state,
    load_lane_king_state,
    load_promotion_record,
    write_lane_metadata,
)
from kata.submission_system.bundle import AGENT_MANIFEST_FILENAME, write_agent_manifest


def write_lane(public_root: Path, *, active: bool = True) -> None:
    write_lane_metadata(
        EvaluatorLaneMetadata(
            schema_version=LANE_METADATA_SCHEMA_VERSION,
            lane_id="sn60__bitsec",
            repo_pack="sn60__bitsec",
            mode="miner",
            evaluator_id="sn60_bitsec",
            evaluator_policy_version="v1",
            active=active,
            created_at="2026-07-01T00:00:00+00:00",
            updated_at="2026-07-01T00:00:00+00:00",
        ),
        public_root=str(public_root),
    )


def write_bundle(root: Path, source: str = "def agent_main():\n    return {}\n") -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "agent.py").write_text(source, encoding="utf-8")
    write_agent_manifest(root / AGENT_MANIFEST_FILENAME)


def write_duel_summary(
    path: Path,
    *,
    king_hash: str,
    candidate_hash: str,
    candidate_path: str,
) -> None:
    payload = {
        "schema_version": 1,
        "run_id": "sn60-run-1",
        "created_at": "2026-07-08T00:00:00+00:00",
        "output_root": str(path.parent),
        "project_keys": ["project-alpha"],
        "replicas_per_project": 1,
        "sandbox_source": {
            "sandbox_root": "/srv/sandbox",
            "benchmark_file": "/srv/kata-benchmark/high.json",
            "benchmark_sha256": "bench-sha",
            "sandbox_commit": "sandbox-sha",
            "scorer_version": "ScaBenchScorerV2",
        },
        "king": variant_summary(
            "king",
            artifact_path="/kings/sn60__bitsec/miner",
            artifact_hash=king_hash,
            true_positives=1,
            total_found=1,
            aggregated_score=0.25,
        ),
        "candidate": variant_summary(
            "candidate",
            artifact_path=candidate_path,
            artifact_hash=candidate_hash,
            true_positives=3,
            total_found=3,
            aggregated_score=0.75,
        ),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def variant_summary(
    variant_name: str,
    *,
    artifact_path: str,
    artifact_hash: str,
    true_positives: int,
    total_found: int,
    aggregated_score: float,
) -> dict[str, object]:
    return {
        "variant_name": variant_name,
        "artifact_path": artifact_path,
        "artifact_hash": artifact_hash,
        "successful_runs": 1,
        "invalid_runs": 0,
        "pass_count": 1,
        "codebase_pass_count": 1,
        "aggregated_score": aggregated_score,
        "average_detection_rate": aggregated_score,
        "true_positives": true_positives,
        "total_expected": 4,
        "total_found": total_found,
        "precision": true_positives / total_found,
        "f1_score": 0.5,
        "project_summaries": [
            {
                "project_key": "project-alpha",
                "replica_count": 1,
                "successful_runs": 1,
                "invalid_runs": 0,
                "pass_count": 1,
                "passed": True,
                "average_detection_rate": aggregated_score,
                "true_positives": true_positives,
                "total_expected": 4,
                "total_found": total_found,
                "precision": true_positives / total_found,
                "f1_score": 0.5,
            }
        ],
        "replica_results": [
            {
                "project_key": "project-alpha",
                "replica_index": 0,
                "report_path": "/tmp/report.json",
                "evaluation_path": "/tmp/evaluation.json",
                "execution_success": True,
                "evaluation_status": "success",
                "score": aggregated_score,
                "detection_rate": aggregated_score,
                "result": "pass",
                "true_positives": true_positives,
                "total_expected": 4,
                "total_found": total_found,
                "precision": true_positives / total_found,
                "f1_score": 0.5,
            }
        ],
    }


def test_find_evaluator_pack_entry_and_validate_lane(tmp_path: Path) -> None:
    write_lane(tmp_path)

    entry = find_evaluator_pack_entry("sn60__bitsec", "miner", public_root=str(tmp_path))

    assert entry is not None
    assert entry.lane_id == "sn60__bitsec"
    assert validate_submission_lane("sn60__bitsec", "miner", public_root=str(tmp_path)) == []


def test_resolve_sn60_lane_king_hash_falls_back_to_published_king(
    tmp_path: Path,
) -> None:
    write_bundle(tmp_path / "kings/sn60__bitsec/miner")

    assert resolve_sn60_lane_king_hash(
        "sn60__bitsec",
        repo_pack="sn60__bitsec",
        mode="miner",
        public_root=str(tmp_path),
    ) == hash_submission_bundle(tmp_path / "kings/sn60__bitsec/miner")


def test_promote_lane_king_publishes_bundle_and_updates_lane_state(
    tmp_path: Path,
) -> None:
    write_lane(tmp_path)
    write_bundle(tmp_path / "kings/sn60__bitsec/miner")
    candidate_root = tmp_path / "candidate"
    write_bundle(candidate_root, "def agent_main():\n    return {'ok': True}\n")
    entry = find_evaluator_pack_entry("sn60__bitsec", "miner", public_root=str(tmp_path))
    assert entry is not None
    verification = types.SimpleNamespace(
        repo_pack="sn60__bitsec",
        mode="miner",
        submission_id="alice-20260708-01",
        submission_path=str(candidate_root),
        candidate_artifact_hash=hash_submission_bundle(candidate_root),
    )
    duel_summary_path = tmp_path / "runs/sn60-run-1/duel_summary.json"
    write_duel_summary(
        duel_summary_path,
        king_hash=hash_bundle_root(tmp_path / "kings/sn60__bitsec/miner"),
        candidate_hash=hash_submission_bundle(candidate_root),
        candidate_path=str(candidate_root),
    )
    summary = types.SimpleNamespace(
        run_id="sn60-run-1",
        primary=types.SimpleNamespace(run_summary_path=str(duel_summary_path)),
        created_at="2026-07-08T00:00:00+00:00",
    )

    result = promote_lane_king(
        entry=entry,
        verification=verification,
        summary=summary,  # type: ignore[arg-type]
        public_root=str(tmp_path),
    )

    king_root = tmp_path / "kings/sn60__bitsec/miner"
    king_state = load_lane_king_state("sn60__bitsec", public_root=str(tmp_path))
    assert result.king_root == str(king_root)
    assert (king_root / "agent.py").read_text(encoding="utf-8").strip() == (
        "def agent_main():\n    return {'ok': True}"
    )
    assert king_state.current_king_submission_id == "alice-20260708-01"
    assert king_state.current_king_artifact_hash == hash_bundle_root(king_root)
    assert result.king.current_king_artifact_hash == hash_bundle_root(king_root)
    challenge_state = load_challenge_state("sn60__bitsec", public_root=str(tmp_path))
    promotion_record = load_promotion_record("sn60__bitsec", public_root=str(tmp_path))
    assert challenge_state.candidate_submission_id == "alice-20260708-01"
    assert challenge_state.selected_project_keys == ["project-alpha"]
    assert promotion_record.final_winner == "candidate"
    assert promotion_record.true_positives == {"king": 1, "candidate": 3}
