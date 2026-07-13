"""Phase 3b tests: a full SN60 round through the generic orchestrator.

``run_sn60_plugin_round`` must produce a ``Sn60RoundResult`` whose *contract* fields
(winner, ranking, per-variant scores, king summary, sandbox source, project keys) match
the legacy ``run_sn60_round`` exactly. Internal artifact paths, run ids and timestamps
are allowed to differ (they are not part of the consumed contract).
"""

from __future__ import annotations

import json
from pathlib import Path

from kata.packages.sn60 import Sn60BitsecPlugin, run_sn60_plugin_round
from kata.validator_system import run_sn60_round


def _write_detection_bundle(root: Path, detection: float) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "agent.py").write_text(
        f"# detection={detection}\n"
        "def agent_main(project_dir=None, inference_api=None):\n"
        "    return {'vulnerabilities': []}\n",
        encoding="utf-8",
    )


def _write_benchmark(root: Path) -> Path:
    benchmark_path = root / "validator" / "curated-highs-only-2025-08-08.json"
    benchmark_path.parent.mkdir(parents=True, exist_ok=True)
    benchmark_path.write_text(
        json.dumps([{"project_id": "project-alpha", "vulnerabilities": [{"title": "expected"}]}])
        + "\n",
        encoding="utf-8",
    )
    return benchmark_path


def _detection_hooks():
    def execute(context) -> dict[str, object]:
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

    def evaluate(_context, report_payload: dict[str, object]) -> dict[str, object]:
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

    return execute, evaluate


def _variant_contract(summary) -> dict:
    return {
        "true_positives": summary.true_positives,
        "aggregated_score": summary.aggregated_score,
        "codebase_pass_count": summary.codebase_pass_count,
        "precision": summary.precision,
        "f1_score": summary.f1_score,
        "invalid_runs": summary.invalid_runs,
        "artifact_hash": summary.artifact_hash,
    }


def _sandbox_contract(source) -> dict:
    return {
        "benchmark_sha256": source.benchmark_sha256,
        "sandbox_commit": source.sandbox_commit,
        "scorer_version": source.scorer_version,
    }


def _build_inputs(tmp_path: Path):
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = _write_benchmark(sandbox_root)
    king_root = tmp_path / "king"
    _write_detection_bundle(king_root, 0.25)
    specs = [("cand-a", 0.0), ("cand-b", 0.5), ("cand-c", 0.75)]
    paths = {}
    for name, detection in specs:
        path = tmp_path / name
        _write_detection_bundle(path, detection)
        paths[name] = str(path)
    return sandbox_root, benchmark_path, king_root, specs, paths


def test_run_sn60_plugin_round_matches_legacy_contract(tmp_path: Path) -> None:
    sandbox_root, benchmark_path, king_root, specs, paths = _build_inputs(tmp_path)
    execute, evaluate = _detection_hooks()
    candidates = [(name, paths[name]) for name, _ in specs]

    legacy = run_sn60_round(
        king_artifact_path=str(king_root),
        candidates=candidates,
        project_keys=["project-alpha"],
        output_root=str(tmp_path / "legacy"),
        replicas_per_project=1,
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit="commit-parity",
        king_scoreboard_path=str(tmp_path / "sb.json"),
        execution_hook=execute,
        evaluation_hook=evaluate,
    )

    plugin = Sn60BitsecPlugin(execution_hook=execute, evaluation_hook=evaluate)
    result = run_sn60_plugin_round(
        king_artifact_path=str(king_root),
        candidates=candidates,
        config={
            "sandbox_root": str(sandbox_root),
            "benchmark_file": str(benchmark_path),
            "sandbox_commit": "commit-parity",
            "project_keys": ["project-alpha"],
            "replicas_per_project": 1,
        },
        output_root=str(tmp_path / "generic"),
        plugin=plugin,
    )

    # Top-level contract.
    assert result.winner_submission_id == legacy.winner_submission_id == "cand-c"
    assert result.promotion_ready is legacy.promotion_ready is True
    assert result.promotion_reason == legacy.promotion_reason
    assert result.competition_mode == legacy.competition_mode == "king_duel"
    assert result.project_keys == legacy.project_keys
    assert _sandbox_contract(result.sandbox_source) == _sandbox_contract(legacy.sandbox_source)

    # King summary contract.
    assert _variant_contract(result.king) == _variant_contract(legacy.king)

    # Per-entry contract, in the same ranked order.
    assert [e.submission_id for e in result.entries] == [e.submission_id for e in legacy.entries]
    for got, want in zip(result.entries, legacy.entries):
        assert got.submission_id == want.submission_id
        assert got.beats_king == want.beats_king
        assert got.selected_winner == want.selected_winner
        assert _variant_contract(got.candidate) == _variant_contract(want.candidate)

    # The winner challenge summary was written and is loadable.
    assert result.winner_challenge_summary_path is not None
    assert Path(result.winner_challenge_summary_path).exists()
    assert (Path(result.output_root) / "round_summary.json").exists()


def test_run_sn60_plugin_round_writes_board_progress(tmp_path: Path) -> None:
    # The plugin round must write round-progress.json in the same shape the board
    # reads today (king + per-candidate entries, per-problem breakdowns, winner).
    sandbox_root, benchmark_path, king_root, specs, paths = _build_inputs(tmp_path)
    execute, evaluate = _detection_hooks()
    progress_path = tmp_path / "round-progress.json"

    run_sn60_plugin_round(
        king_artifact_path=str(king_root),
        candidates=[(name, paths[name]) for name, _ in specs],
        config={
            "sandbox_root": str(sandbox_root),
            "benchmark_file": str(benchmark_path),
            "sandbox_commit": "commit-progress",
            "project_keys": ["project-alpha"],
            "replicas_per_project": 1,
        },
        output_root=str(tmp_path / "generic"),
        plugin=Sn60BitsecPlugin(execution_hook=execute, evaluation_hook=evaluate),
        progress_path=str(progress_path),
    )

    progress = json.loads(progress_path.read_text(encoding="utf-8"))
    assert progress["state"] == "completed"
    assert progress["winner_submission_id"] == "cand-c"
    assert {c["submission_id"] for c in progress["candidates"]} == {
        "cand-a",
        "cand-b",
        "cand-c",
    }
    assert all(
        c["done"] == c["total"] and c["state"] == "done" for c in progress["candidates"]
    )
    winner = next(c for c in progress["candidates"] if c["submission_id"] == "cand-c")
    assert winner["aggregated_score"] == 0.75
    assert winner["beats_king"] is True
    assert isinstance(winner["projects"], list) and winner["projects"]
    # The king is scored and published for the detail view.
    assert progress["king"]["state"] == "done"
    assert progress["king"]["aggregated_score"] == 0.25
    assert isinstance(progress["king"]["projects"], list) and progress["king"]["projects"]


def test_run_sn60_plugin_round_no_winner_when_king_unbeaten(tmp_path: Path) -> None:
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = _write_benchmark(sandbox_root)
    king_root = tmp_path / "king"
    _write_detection_bundle(king_root, 0.9)  # tp = 4, unbeatable here
    weak = tmp_path / "weak"
    _write_detection_bundle(weak, 0.1)  # tp = 0
    execute, evaluate = _detection_hooks()

    result = run_sn60_plugin_round(
        king_artifact_path=str(king_root),
        candidates=[("weak", str(weak))],
        config={
            "sandbox_root": str(sandbox_root),
            "benchmark_file": str(benchmark_path),
            "sandbox_commit": "commit-x",
            "project_keys": ["project-alpha"],
            "replicas_per_project": 1,
        },
        output_root=str(tmp_path / "generic"),
        plugin=Sn60BitsecPlugin(execution_hook=execute, evaluation_hook=evaluate),
    )
    assert result.winner_submission_id is None
    assert result.promotion_ready is False
    assert result.promotion_reason == "no candidate beat the current SN60 king"
    assert result.winner_challenge_summary_path is None
    assert result.entries[0].beats_king is False
