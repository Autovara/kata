from __future__ import annotations

import json
from pathlib import Path

from kata.challenge import (
    SN60_MINER_LANE_ID,
    evaluate_sn60_promotion,
    load_challenge_summary,
    run_sn60_challenge,
)
from kata.evaluators.sn60_bitsec import (
    Sn60ProjectAggregate,
    Sn60ReplicaContext,
    Sn60ReplicaResult,
    Sn60VariantSummary,
)
from kata.lane_state import (
    load_benchmark_snapshot,
    load_challenge_state,
    load_promotion_record,
)

SCREENING_DESCRIPTION = (
    "A privileged state-changing function can be called by any account, "
    "allowing unauthorized changes to protected protocol settings."
)
VALID_SCREENING_REPORT = {
    "vulnerabilities": [
        {
            "title": "Missing access control on privileged update",
            "description": SCREENING_DESCRIPTION,
            "severity": "high",
            "file": "contracts/Admin.sol",
        }
    ]
}


def write_bundle(root: Path, title: str) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "agent.py").write_text(
        "def agent_main(project_dir=None, inference_api=None):\n"
        f"    return {{'vulnerabilities': [{{'title': '{title}'}}]}}\n",
        encoding="utf-8",
    )


def write_sandbox_source(root: Path) -> Path:
    benchmark_path = root / "validator" / "curated-highs-only-2025-08-08.json"
    benchmark_path.parent.mkdir(parents=True, exist_ok=True)
    benchmark_path.write_text(
        json.dumps(
            [
                {
                    "project_id": "project-alpha",
                    "vulnerabilities": [{"title": "expected"}],
                }
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return benchmark_path


def test_run_sn60_challenge_decides_winner_and_records_lane_provenance(
    tmp_path: Path,
) -> None:
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = write_sandbox_source(sandbox_root)
    king_root = tmp_path / "king"
    candidate_root = tmp_path / "candidate"
    write_bundle(king_root, "king")
    write_bundle(candidate_root, "candidate")

    def execute(context: Sn60ReplicaContext) -> dict[str, object]:
        # Screening now reuses the duel's candidate reports, so the duel report
        # must itself be a well-formed findings report (as a real agent produces).
        return {"success": True, "report": VALID_SCREENING_REPORT}

    def evaluate(
        context: Sn60ReplicaContext,
        report_payload: dict[str, object],
    ) -> dict[str, object]:
        detection_rate = 1.0 if context.variant_name == "candidate" else 0.25
        return {
            "status": "success",
            "result": {
                "project": context.project_key,
                "timestamp": "2026-07-01T00:00:00+00:00",
                "total_expected": 4,
                "total_found": len(report_payload["report"]["vulnerabilities"]),
                "true_positives": int(detection_rate * 4),
                "false_negatives": 4 - int(detection_rate * 4),
                "false_positives": 0,
                "detection_rate": detection_rate,
                "precision": 1.0,
                "f1_score": detection_rate,
                "result": "PASS" if detection_rate == 1.0 else "FAIL",
            },
        }

    def screen(context: Sn60ReplicaContext) -> dict[str, object]:
        return {"success": True, "report": VALID_SCREENING_REPORT}

    summary = run_sn60_challenge(
        king_artifact_path=str(king_root),
        candidate_artifact_path=str(candidate_root),
        project_keys=["project-alpha"],
        candidate_submission_id="miner-sn60-1",
        output_root=str(tmp_path / "runs"),
        replicas_per_project=2,
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit="sandbox-commit-1",
        public_root=str(tmp_path / "public"),
        screening_hook=screen,
        execution_hook=execute,
        evaluation_hook=evaluate,
    )

    assert summary.mode == "miner"
    assert summary.promotion_ready
    assert summary.primary.variant_scores == {"king": 25.0, "candidate": 100.0}
    assert summary.primary.variant_successes == {"king": 0, "candidate": 1}
    assert summary.primary.total_task_weight == 1.0
    assert summary.primary.candidate_beats_king
    assert summary.primary_pool_fingerprint

    persisted = load_challenge_summary(
        str(Path(summary.manifest_path).with_name("challenge_summary.json"))
    )
    assert persisted.run_id == summary.run_id
    assert persisted.promotion_ready

    challenge_state = load_challenge_state(
        SN60_MINER_LANE_ID,
        public_root=str(tmp_path / "public"),
    )
    promotion_record = load_promotion_record(
        SN60_MINER_LANE_ID,
        public_root=str(tmp_path / "public"),
    )
    assert challenge_state.candidate_submission_id == "miner-sn60-1"
    assert challenge_state.freshness_fingerprint == summary.primary_pool_fingerprint
    assert promotion_record.final_winner == "candidate"
    assert promotion_record.final_metrics["promotion_ready"] is True
    assert promotion_record.final_metrics["candidate_aggregated_score"] == 1.0
    assert promotion_record.final_metrics["king_aggregated_score"] == 0.25
    assert promotion_record.pass_counts == {"king": 0, "candidate": 1}
    assert promotion_record.local_replica_scores["candidate"] == [1.0, 1.0]

    snapshot = load_benchmark_snapshot(
        SN60_MINER_LANE_ID,
        public_root=str(tmp_path / "public"),
    )
    assert snapshot.sandbox_commit_hash == "sandbox-commit-1"
    assert snapshot.project_keys == ["project-alpha"]
    assert snapshot.benchmark_dataset_id == "curated-highs-only-2025-08-08.json"
    assert snapshot.benchmark_dataset_hash
    assert snapshot.project_list_hash
    assert snapshot.container_images == ["ghcr.io/bitsec-ai/project-alpha:latest"]
    assert snapshot.scorer_version == "ScaBenchScorerV2"
    assert (
        Path(summary.manifest_path).with_name("screening_result.json")
    ).exists()


def test_run_sn60_challenge_screens_without_a_second_inference_pass(
    tmp_path: Path,
) -> None:
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = write_sandbox_source(sandbox_root)
    king_root = tmp_path / "king"
    candidate_root = tmp_path / "candidate"
    write_bundle(king_root, "king")
    write_bundle(candidate_root, "candidate")

    candidate_runs = 0

    def execute(context: Sn60ReplicaContext) -> dict[str, object]:
        nonlocal candidate_runs
        if context.variant_name == "candidate":
            candidate_runs += 1
        return {"success": True, "report": VALID_SCREENING_REPORT}

    summary = run_sn60_challenge(
        king_artifact_path=str(king_root),
        candidate_artifact_path=str(candidate_root),
        project_keys=["project-alpha"],
        candidate_submission_id="miner-sn60-1",
        output_root=str(tmp_path / "runs"),
        replicas_per_project=1,
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit="sandbox-commit-1",
        public_root=str(tmp_path / "public"),
        execution_hook=execute,
        evaluation_hook=lambda context, report: {
            "status": "success",
            "result": {"total_expected": 1, "total_found": 1, "true_positives": 1},
        },
    )

    # One project x one replica -> the candidate runs exactly once (in the duel);
    # screening reuses that report instead of a second inference pass.
    assert candidate_runs == 1
    assert Path(summary.manifest_path).with_name("screening_result.json").exists()


def test_evaluate_sn60_promotion_uses_invalid_runs_as_last_tiebreaker() -> None:
    king = build_variant(
        "king", aggregated_score=0.5, codebase_pass_count=1, true_positives=2, invalid_runs=0
    )
    candidate = build_variant(
        "candidate", aggregated_score=0.5, codebase_pass_count=1, true_positives=2, invalid_runs=1
    )

    decision = evaluate_sn60_promotion(king=king, candidate=candidate)

    assert not decision.promotion_ready
    assert decision.final_winner == "king"
    assert decision.reason == "candidate did not beat the current SN60 king"


def test_evaluate_sn60_promotion_does_not_use_pass_count_as_score_tiebreaker() -> None:
    king = build_variant(
        "king",
        aggregated_score=0.5,
        codebase_pass_count=1,
        true_positives=4,
    )
    candidate = build_variant(
        "candidate",
        aggregated_score=0.5,
        codebase_pass_count=2,
        true_positives=4,
    )

    decision = evaluate_sn60_promotion(king=king, candidate=candidate)

    assert not decision.promotion_ready
    assert decision.final_winner == "king"


def test_evaluate_sn60_promotion_uses_true_positives_as_final_tiebreaker() -> None:
    king = build_variant(
        "king",
        aggregated_score=0.5,
        codebase_pass_count=1,
        true_positives=4,
    )
    candidate = build_variant(
        "candidate",
        aggregated_score=0.5,
        codebase_pass_count=1,
        true_positives=6,
    )

    decision = evaluate_sn60_promotion(king=king, candidate=candidate)

    assert decision.promotion_ready
    assert decision.final_winner == "candidate"


def test_evaluate_sn60_promotion_uses_precision_tiebreaker() -> None:
    king = build_variant(
        "king",
        aggregated_score=0.5,
        codebase_pass_count=1,
        true_positives=4,
        total_found=8,
    )
    candidate = build_variant(
        "candidate",
        aggregated_score=0.5,
        codebase_pass_count=1,
        true_positives=4,
        total_found=5,
    )

    decision = evaluate_sn60_promotion(king=king, candidate=candidate)

    assert decision.promotion_ready
    assert decision.final_winner == "candidate"


def test_sn60_freshness_fingerprint_changes_with_sandbox_commit(tmp_path: Path) -> None:
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = write_sandbox_source(sandbox_root)
    king_root = tmp_path / "king"
    candidate_root = tmp_path / "candidate"
    write_bundle(king_root, "king")
    write_bundle(candidate_root, "candidate")

    def execute(context: Sn60ReplicaContext) -> dict[str, object]:
        return {"success": True, "report": VALID_SCREENING_REPORT}

    def evaluate(
        context: Sn60ReplicaContext,
        report_payload: dict[str, object],
    ) -> dict[str, object]:
        return {
            "status": "success",
            "result": {
                "project": context.project_key,
                "timestamp": "2026-07-01T00:00:00+00:00",
                "total_expected": 1,
                "total_found": 0,
                "true_positives": 0,
                "false_negatives": 1,
                "false_positives": 0,
                "detection_rate": 0.0,
                "precision": 0.0,
                "f1_score": 0.0,
                "result": "FAIL",
            },
        }

    def screen(context: Sn60ReplicaContext) -> dict[str, object]:
        return {"success": True, "report": VALID_SCREENING_REPORT}

    first = run_sn60_challenge(
        king_artifact_path=str(king_root),
        candidate_artifact_path=str(candidate_root),
        project_keys=["project-alpha"],
        candidate_submission_id="miner-sn60-1",
        output_root=str(tmp_path / "runs-a"),
        replicas_per_project=1,
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit="commit-a",
        public_root=str(tmp_path / "public-a"),
        screening_hook=screen,
        execution_hook=execute,
        evaluation_hook=evaluate,
    )
    second = run_sn60_challenge(
        king_artifact_path=str(king_root),
        candidate_artifact_path=str(candidate_root),
        project_keys=["project-alpha"],
        candidate_submission_id="miner-sn60-1",
        output_root=str(tmp_path / "runs-b"),
        replicas_per_project=1,
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit="commit-b",
        public_root=str(tmp_path / "public-b"),
        screening_hook=screen,
        execution_hook=execute,
        evaluation_hook=evaluate,
    )

    assert first.primary_pool_fingerprint != second.primary_pool_fingerprint


def test_run_sn60_challenge_fails_screening_when_candidate_reports_no_findings(
    tmp_path: Path,
) -> None:
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = write_sandbox_source(sandbox_root)
    king_root = tmp_path / "king"
    candidate_root = tmp_path / "candidate"
    write_bundle(king_root, "king")
    write_bundle(candidate_root, "candidate")

    def execute(context: Sn60ReplicaContext) -> dict[str, object]:
        # Candidate produces an empty findings report on every sampled project ->
        # it fails the (now duel-reused) execution screening gate.
        if context.variant_name == "candidate":
            return {"success": True, "report": {"vulnerabilities": []}}
        return {"success": True, "report": VALID_SCREENING_REPORT}

    summary = run_sn60_challenge(
        king_artifact_path=str(king_root),
        candidate_artifact_path=str(candidate_root),
        project_keys=["project-alpha"],
        candidate_submission_id="miner-sn60-1",
        output_root=str(tmp_path / "runs"),
        replicas_per_project=1,
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit="sandbox-commit-1",
        public_root=str(tmp_path / "public"),
        execution_hook=execute,
        evaluation_hook=lambda context, report: {"status": "success", "result": {}},
    )

    assert not summary.promotion_ready
    assert "candidate failed SN60 screening" in summary.promotion_reason
    assert Path(summary.manifest_path).name == "screening_result.json"

    challenge_summary_path = Path(summary.manifest_path).with_name("challenge_summary.json")
    assert challenge_summary_path.exists()

    challenge_state = load_challenge_state(
        SN60_MINER_LANE_ID,
        public_root=str(tmp_path / "public"),
    )
    promotion_record = load_promotion_record(
        SN60_MINER_LANE_ID,
        public_root=str(tmp_path / "public"),
    )
    assert challenge_state.screening_result["status"] == "failed"
    assert promotion_record.final_winner == "king"

    snapshot = load_benchmark_snapshot(
        SN60_MINER_LANE_ID,
        public_root=str(tmp_path / "public"),
    )
    assert snapshot.sandbox_commit_hash == "sandbox-commit-1"
    assert snapshot.project_keys == ["project-alpha"]


def build_variant(
    variant_name: str,
    *,
    aggregated_score: float,
    codebase_pass_count: int,
    true_positives: int = 0,
    total_found: int | None = None,
    invalid_runs: int = 0,
) -> Sn60VariantSummary:
    found = true_positives if total_found is None else total_found
    precision = true_positives / found if found else 0.0
    f1_score = (
        2 * precision * aggregated_score / (precision + aggregated_score)
        if precision + aggregated_score > 0
        else 0.0
    )
    replica_results = [
        Sn60ReplicaResult(
            project_key="project-alpha",
            replica_index=1,
            report_path="/tmp/report.json",
            evaluation_path="/tmp/evaluation.json",
            execution_success=True,
            evaluation_status="success" if invalid_runs == 0 else "error",
            score=aggregated_score,
            detection_rate=aggregated_score,
            result="PASS" if codebase_pass_count else "FAIL",
            true_positives=true_positives,
            total_expected=4,
            total_found=found,
            precision=precision,
            f1_score=f1_score,
        )
    ]
    return Sn60VariantSummary(
        variant_name=variant_name,
        artifact_path=f"/tmp/{variant_name}",
        artifact_hash=f"{variant_name}-hash",
        successful_runs=1 - invalid_runs,
        invalid_runs=invalid_runs,
        pass_count=codebase_pass_count,
        codebase_pass_count=codebase_pass_count,
        aggregated_score=aggregated_score,
        average_detection_rate=aggregated_score,
        true_positives=true_positives,
        total_expected=4,
        total_found=found,
        precision=precision,
        f1_score=f1_score,
        project_summaries=[
            Sn60ProjectAggregate(
                project_key="project-alpha",
                replica_count=1,
                successful_runs=1 - invalid_runs,
                invalid_runs=invalid_runs,
                pass_count=codebase_pass_count,
                passed=bool(codebase_pass_count),
                average_detection_rate=aggregated_score,
                true_positives=true_positives,
                total_expected=4,
                total_found=found,
                precision=precision,
                f1_score=f1_score,
            )
        ],
        replica_results=replica_results,
    )
