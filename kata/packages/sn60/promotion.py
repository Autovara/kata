"""SN60 promotion provenance: parse the duel summary and record lane provenance.

Moved out of the generic promotion module (``kata/promotion_system/king.py``) so the platform
promotion path stays subnet-blind; the SN60 plugin calls these via
``record_promotion_provenance``. Relocates to ``kata-sn60`` in Phase 3.
"""

from __future__ import annotations

import json
from pathlib import Path

from kata.evaluators.sn60_bitsec import (
    Sn60DuelSummary,
    Sn60ProjectAggregate,
    Sn60ReplicaResult,
    Sn60SandboxSource,
    Sn60VariantSummary,
)
from kata.packages.sn60.validator_system.challenge import record_sn60_lane_provenance


def record_sn60_promotion_provenance(
    *,
    entry,
    verification,
    summary,
    public_root: str | None,
) -> None:
    """Persist SN60 lane challenge/promotion records for a promoted round winner."""
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
