from __future__ import annotations

import json
from pathlib import Path

import pytest

from kata.challenge import (
    SN60_MINER_LANE_ID,
    evaluate_sn60_promotion,
    load_challenge_summary,
    run_sn60_challenge,
    run_sn60_round,
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
        execution_hook=execute,
        evaluation_hook=evaluate,
    )

    assert first.primary_pool_fingerprint != second.primary_pool_fingerprint


def test_run_sn60_challenge_scores_zero_instead_of_closing_on_empty_output(
    tmp_path: Path,
) -> None:
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = write_sandbox_source(sandbox_root)
    king_root = tmp_path / "king"
    candidate_root = tmp_path / "candidate"
    write_bundle(king_root, "king")
    write_bundle(candidate_root, "candidate")

    def execute(context: Sn60ReplicaContext) -> dict[str, object]:
        # Candidate returns an empty findings report on every project. This is NOT
        # a screening failure: the duel scores it 0 and it simply loses.
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

    # Loses the duel; NOT closed as a screening failure.
    assert not summary.promotion_ready
    assert "failed SN60 screening" not in summary.promotion_reason
    assert "did not beat" in summary.promotion_reason
    assert Path(summary.manifest_path).name == "duel_summary.json"

    # The execution screening result is informational (passed) and records a
    # per-problem findings note for feedback.
    screening_path = Path(summary.manifest_path).with_name("screening_result.json")
    screening = json.loads(screening_path.read_text(encoding="utf-8"))
    assert screening["status"] == "passed"
    assert screening["stage"] == "execution"
    finding_quality = screening["details"]["finding_quality"]
    assert finding_quality["total_problems"] == 1
    assert finding_quality["problems_with_findings"] == 0
    assert finding_quality["problems_without_findings"] == 1

    promotion_record = load_promotion_record(
        SN60_MINER_LANE_ID,
        public_root=str(tmp_path / "public"),
    )
    assert promotion_record.final_winner == "king"


def test_run_sn60_challenge_closes_before_duel_on_static_failure(
    tmp_path: Path,
) -> None:
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = write_sandbox_source(sandbox_root)
    king_root = tmp_path / "king"
    candidate_root = tmp_path / "candidate"
    write_bundle(king_root, "king")
    # Candidate source references the benchmark answer key -> static screening fails.
    candidate_root.mkdir(parents=True, exist_ok=True)
    (candidate_root / "agent.py").write_text(
        "def agent_main(project_dir=None, inference_api=None):\n"
        "    # cheat: peek at expected_findings from the answer key\n"
        "    return {'vulnerabilities': [{'title': 'x'}]}\n",
        encoding="utf-8",
    )

    duel_started = False

    def execute(context: Sn60ReplicaContext) -> dict[str, object]:
        nonlocal duel_started
        duel_started = True
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

    # The duel never ran, and the PR is closed as a screening failure.
    assert not duel_started
    assert not summary.promotion_ready
    assert "candidate failed SN60 screening" in summary.promotion_reason
    assert Path(summary.manifest_path).name == "screening_result.json"

    challenge_state = load_challenge_state(
        SN60_MINER_LANE_ID,
        public_root=str(tmp_path / "public"),
    )
    promotion_record = load_promotion_record(
        SN60_MINER_LANE_ID,
        public_root=str(tmp_path / "public"),
    )
    assert challenge_state.screening_result["status"] == "failed"
    assert challenge_state.screening_result["stage"] == "static"
    assert promotion_record.final_winner == "king"


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


def _write_detection_bundle(root: Path, detection: float) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "agent.py").write_text(
        f"# detection={detection}\n"
        "def agent_main(project_dir=None, inference_api=None):\n"
        "    return {'vulnerabilities': []}\n",
        encoding="utf-8",
    )


def _detection_hooks():
    """Hooks that read each staged bundle's encoded detection and score it, while
    counting how many times each variant actually executes."""
    ran: dict[str, int] = {}

    def execute(context: Sn60ReplicaContext) -> dict[str, object]:
        ran[context.variant_name] = ran.get(context.variant_name, 0) + 1
        source = (Path(context.bundle_root) / "agent.py").read_text(encoding="utf-8")
        detection = 0.0
        for line in source.splitlines():
            if "# detection=" in line:
                detection = float(line.split("# detection=")[1].strip())
        return {
            "success": True,
            "report": {
                "project": context.project_key,
                "vulnerabilities": [{"title": "v"}],
                "detection": detection,
            },
        }

    def evaluate(
        _context: Sn60ReplicaContext, report_payload: dict[str, object]
    ) -> dict[str, object]:
        detection = report_payload["report"]["detection"]
        return {
            "status": "success",
            "result": {
                "result": "PASS" if detection >= 1.0 else "FAIL",
                "detection_rate": detection,
                "true_positives": int(round(detection * 4)),
                "total_expected": 4,
                "total_found": 4,
                "precision": 1.0,
                "f1_score": detection,
            },
        }

    return ran, execute, evaluate


def test_run_sn60_round_ranks_candidates_and_picks_strict_winner(tmp_path: Path) -> None:
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = write_sandbox_source(sandbox_root)
    king_root = tmp_path / "king"
    _write_detection_bundle(king_root, 0.25)
    candidates = []
    for name, detection in (("cand-a", 0.0), ("cand-b", 0.5), ("cand-c", 0.75)):
        path = tmp_path / name
        _write_detection_bundle(path, detection)
        candidates.append((name, str(path)))
    scoreboard = tmp_path / "king_scoreboard.json"
    progress_path = tmp_path / "round-progress.json"

    ran, execute, evaluate = _detection_hooks()
    result = run_sn60_round(
        king_artifact_path=str(king_root),
        candidates=candidates,
        project_keys=["project-alpha"],
        output_root=str(tmp_path / "runs"),
        replicas_per_project=1,
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit="commit-round-1",
        king_scoreboard_path=str(scoreboard),
        execution_hook=execute,
        evaluation_hook=evaluate,
        progress_path=str(progress_path),
    )

    # Live progress is published: by the end every candidate is scored and the
    # snapshot is marked completed with the winner.
    import json as _json

    progress = _json.loads(progress_path.read_text())
    assert progress["state"] == "completed"
    assert progress["winner_submission_id"] == "cand-c"
    assert {c["submission_id"] for c in progress["candidates"]} == {"cand-a", "cand-b", "cand-c"}
    assert all(c["done"] == c["total"] and c["state"] == "done" for c in progress["candidates"])
    # Each finished candidate carries its full result + per-problem breakdown, and
    # the king's result is published too (for the detail page).
    winner_entry = next(c for c in progress["candidates"] if c["submission_id"] == "cand-c")
    assert winner_entry["aggregated_score"] == 0.75
    assert winner_entry["beats_king"] is True
    assert isinstance(winner_entry["projects"], list) and winner_entry["projects"]
    assert progress["king"]["aggregated_score"] == 0.25
    assert isinstance(progress["king"]["projects"], list) and progress["king"]["projects"]

    # Ranked best-first by detection; the strict winner is the top one that beats the king.
    assert [entry.submission_id for entry in result.entries] == ["cand-c", "cand-b", "cand-a"]
    assert [entry.beats_king for entry in result.entries] == [True, True, False]
    assert result.winner_submission_id == "cand-c"
    assert result.promotion_ready is True
    assert result.king.aggregated_score == 0.25

    # The king was scored once for the round (cached), the three candidates each ran.
    assert ran["king"] == 1
    assert ran["candidate"] == 3
    assert (Path(result.output_root) / "round_summary.json").exists()

    # The winner's promotion artifact is persisted from the duel it already ran,
    # so the king is promoted from this round -- no second duel at merge time.
    assert result.winner_challenge_summary_path is not None
    summary_path = Path(result.winner_challenge_summary_path)
    assert summary_path.exists()
    assert summary_path.name == "challenge_summary.json"


def test_run_sn60_round_has_no_winner_when_none_beats_king(tmp_path: Path) -> None:
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = write_sandbox_source(sandbox_root)
    king_root = tmp_path / "king"
    _write_detection_bundle(king_root, 0.5)
    candidates = []
    for name, detection in (("cand-a", 0.0), ("cand-b", 0.25)):
        path = tmp_path / name
        _write_detection_bundle(path, detection)
        candidates.append((name, str(path)))

    _ran, execute, evaluate = _detection_hooks()
    result = run_sn60_round(
        king_artifact_path=str(king_root),
        candidates=candidates,
        project_keys=["project-alpha"],
        output_root=str(tmp_path / "runs"),
        replicas_per_project=1,
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit="commit-round-2",
        execution_hook=execute,
        evaluation_hook=evaluate,
    )

    assert result.winner_submission_id is None
    assert result.promotion_ready is False
    assert all(entry.beats_king is False for entry in result.entries)
    # No winner -> no promotion artifact to write.
    assert result.winner_challenge_summary_path is None


def test_run_sn60_round_rejects_duplicate_submission_ids(tmp_path: Path) -> None:
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = write_sandbox_source(sandbox_root)
    king_root = tmp_path / "king"
    candidate_root = tmp_path / "candidate"
    _write_detection_bundle(king_root, 0.25)
    _write_detection_bundle(candidate_root, 0.5)

    with pytest.raises(ValueError, match="Duplicate submission id"):
        run_sn60_round(
            king_artifact_path=str(king_root),
            candidates=[("dup", str(candidate_root)), ("dup", str(candidate_root))],
            project_keys=["project-alpha"],
            output_root=str(tmp_path / "runs"),
            sandbox_root=str(sandbox_root),
            benchmark_file=str(benchmark_path),
            sandbox_commit="commit-round-3",
        )
