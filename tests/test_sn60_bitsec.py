from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from kata.evaluators.sn60_bitsec import (
    Sn60ReplicaContext,
    build_bitsec_execution_command,
    extract_evaluation_metrics,
    project_passes,
    resolve_sn60_sandbox_source,
    run_sn60_bitsec_duel,
    sn60_synthetic_ids,
)


def write_bundle(root: Path, *, agent_source: str, helper_source: str | None = None) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "agent.py").write_text(agent_source, encoding="utf-8")
    if helper_source is not None:
        helpers_root = root / "helpers"
        helpers_root.mkdir()
        (helpers_root / "planner.py").write_text(helper_source, encoding="utf-8")


def write_sandbox_source(root: Path) -> Path:
    benchmark_path = root / "validator" / "curated-highs-only-2025-08-08.json"
    benchmark_path.parent.mkdir(parents=True, exist_ok=True)
    benchmark_path.write_text(
        json.dumps(
            [
                {
                    "project_id": "project-alpha",
                    "vulnerabilities": [{"title": "expected alpha"}],
                }
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return benchmark_path


def test_run_sn60_bitsec_duel_stages_full_bundle_and_persists_outputs(tmp_path: Path) -> None:
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = write_sandbox_source(sandbox_root)
    king_root = tmp_path / "king"
    candidate_root = tmp_path / "candidate"
    write_bundle(
        king_root,
        agent_source="def agent_main():\n    return {'vulnerabilities': []}\n",
        helper_source="VALUE = 'king-helper'\n",
    )
    write_bundle(
        candidate_root,
        agent_source="def agent_main():\n    return {'vulnerabilities': []}\n",
        helper_source="VALUE = 'candidate-helper'\n",
    )

    staged_helpers: dict[tuple[str, str, int], str] = {}

    def execute(context: Sn60ReplicaContext) -> dict[str, object]:
        helper_path = Path(context.bundle_root) / "helpers" / "planner.py"
        staged_helpers[(context.variant_name, context.project_key, context.replica_index)] = (
            helper_path.read_text(encoding="utf-8")
        )
        return {
            "success": True,
            "report": {
                "project": context.project_key,
                "vulnerabilities": [
                    {
                        "title": (
                            f"{context.variant_name}-"
                            f"{context.project_key}-{context.replica_index}"
                        ),
                    }
                ],
            },
        }

    def evaluate(
        context: Sn60ReplicaContext,
        report_payload: dict[str, object],
    ) -> dict[str, object]:
        detection_rate = 1.0 if context.variant_name == "candidate" else 0.25
        if context.project_key == "project-beta" and context.replica_index == 2:
            return {"status": "error", "error": "forced failure", "result": {}}
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
                "matched_findings": [],
                "missed_findings": [],
                "extra_findings": [],
                "undecided_findings": [],
            },
        }

    summary = run_sn60_bitsec_duel(
        king_artifact_path=str(king_root),
        candidate_artifact_path=str(candidate_root),
        project_keys=["project-alpha", "project-beta"],
        output_root=str(tmp_path / "runs"),
        replicas_per_project=2,
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit="sandbox-commit-123",
        execution_hook=execute,
        evaluation_hook=evaluate,
    )

    assert summary.sandbox_source.sandbox_commit == "sandbox-commit-123"
    assert summary.sandbox_source.benchmark_file == str(benchmark_path.resolve())
    assert summary.king.invalid_runs == 1
    assert summary.candidate.invalid_runs == 1
    assert summary.king.average_detection_rate == 0.1875
    assert summary.candidate.average_detection_rate == 0.75
    assert summary.candidate.pass_count == 3
    # candidate passes project-alpha (2/2 runs) but not project-beta (1 pass, 1 invalid)
    assert summary.candidate.codebase_pass_count == 1
    assert summary.candidate.aggregated_score == 0.5
    assert summary.king.codebase_pass_count == 0
    assert summary.king.aggregated_score == 0.0
    candidate_projects = {
        project.project_key: project.passed for project in summary.candidate.project_summaries
    }
    assert candidate_projects == {"project-alpha": True, "project-beta": False}

    duel_summary_path = Path(summary.output_root) / "duel_summary.json"
    assert duel_summary_path.exists()

    persisted = json.loads(duel_summary_path.read_text(encoding="utf-8"))
    assert persisted["run_id"] == summary.run_id
    assert persisted["candidate"]["project_summaries"][0]["project_key"] == "project-alpha"

    candidate_helper = staged_helpers[("candidate", "project-alpha", 1)]
    king_helper = staged_helpers[("king", "project-alpha", 1)]
    assert "candidate-helper" in candidate_helper
    assert "king-helper" in king_helper

    for variant_name in ("king", "candidate"):
        report_path = (
            Path(summary.output_root)
            / variant_name
            / "project-alpha"
            / "replica-01"
            / "reports"
            / "project-alpha"
            / "report.json"
        )
        evaluation_path = report_path.with_name("evaluation.json")
        assert report_path.exists()
        assert evaluation_path.exists()


def test_build_bitsec_execution_command_mounts_bundle_and_sets_pythonpath(tmp_path: Path) -> None:
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = write_sandbox_source(sandbox_root)
    source = resolve_sn60_sandbox_source(
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit="commit-1",
        scorer_version="ScaBenchScorerV2",
    )
    context = Sn60ReplicaContext(
        run_id="run-1",
        variant_name="candidate",
        project_key="project-alpha",
        replica_index=1,
        bundle_root=str(tmp_path / "bundle"),
        reports_root=str(tmp_path / "reports" / "project-alpha"),
        report_path=str(tmp_path / "reports" / "project-alpha" / "report.json"),
        evaluation_path=str(tmp_path / "reports" / "project-alpha" / "evaluation.json"),
        sandbox_source=source,
    )

    command = build_bitsec_execution_command(context)

    assert command[:4] == ["docker", "run", "--rm", "--network"]
    assert "AGENT_FILE=/kata_bundle/agent.py" in command
    assert "PYTHONPATH=/kata_bundle" in command
    assert "INFERENCE_API_KEY" in command
    assert f"PROJECT_KEY={context.project_key}" in command
    assert command[-1] == "ghcr.io/bitsec-ai/project-alpha:latest"
    # Resource envelope matches the SN60 executor.
    assert "--memory" in command and "512m" in command
    assert "--cpus" in command and "0.25" in command
    assert "--pids-limit" in command and "64" in command
    # Execution carries the synthetic numeric identity, not the duel string,
    # so proxy metering is keyed per replica exactly like SN60.
    ids = sn60_synthetic_ids(context)
    assert f"JOB_RUN_ID={ids.job_run_id}" in command
    assert f"AGENT_ID={ids.agent_id}" in command
    assert f"JOB_RUN_ID={context.run_id}" not in command


def _make_context(tmp_path: Path, source, **overrides) -> Sn60ReplicaContext:
    base = dict(
        run_id="run-1",
        variant_name="candidate",
        project_key="project-alpha",
        replica_index=1,
        bundle_root=str(tmp_path / "bundle"),
        reports_root=str(tmp_path / "reports" / "project-alpha"),
        report_path=str(tmp_path / "reports" / "project-alpha" / "report.json"),
        evaluation_path=str(tmp_path / "reports" / "project-alpha" / "evaluation.json"),
        sandbox_source=source,
    )
    base.update(overrides)
    return Sn60ReplicaContext(**base)


def test_build_bitsec_evaluation_command_uses_synthetic_ids_and_eval_max_vulns(
    tmp_path: Path,
) -> None:
    from kata.evaluators.sn60_bitsec import build_bitsec_evaluation_command

    sandbox_root = tmp_path / "sandbox"
    benchmark_path = write_sandbox_source(sandbox_root)
    source = resolve_sn60_sandbox_source(
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit="commit-1",
        scorer_version="ScaBenchScorerV2",
    )
    context = _make_context(tmp_path, source, eval_max_vulns=25)
    ids = sn60_synthetic_ids(context)

    script = build_bitsec_evaluation_command(context)[-1]

    assert f"id={ids.job_run_id}" in script
    assert f"agent_id={ids.agent_id}" in script
    assert f"validator_id={ids.validator_id}" in script
    # eval_max_vulns is threaded from the context, not hardcoded.
    assert "eval_max_vulns=25" in script
    # The old fixed-identity form must be gone.
    assert "MockJobRun(id=1," not in script
    import ast

    ast.parse(script)


def test_sn60_synthetic_ids_are_distinct_and_stable(tmp_path: Path) -> None:
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = write_sandbox_source(sandbox_root)
    source = resolve_sn60_sandbox_source(
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit="commit-1",
        scorer_version="ScaBenchScorerV2",
    )
    king_r1 = sn60_synthetic_ids(_make_context(tmp_path, source, variant_name="king"))
    king_r2 = sn60_synthetic_ids(
        _make_context(tmp_path, source, variant_name="king", replica_index=2)
    )
    cand_r1 = sn60_synthetic_ids(
        _make_context(tmp_path, source, variant_name="candidate")
    )

    # Stable for identical context.
    assert king_r1 == sn60_synthetic_ids(
        _make_context(tmp_path, source, variant_name="king")
    )
    # Distinct job_run_id per replica; distinct agent_id per side.
    assert king_r1.job_run_id != king_r2.job_run_id
    assert king_r1.agent_id == king_r2.agent_id
    assert king_r1.agent_id != cand_r1.agent_id
    assert king_r1.job_run_id != cand_r1.job_run_id
    # King and candidate share the duel-level job_id.
    assert king_r1.job_id == cand_r1.job_id
    assert all(
        1 <= value < 2**31
        for value in (*king_r1, *cand_r1)
    )


def test_resolve_sn60_sandbox_source_rejects_mismatched_benchmark_filename(
    tmp_path: Path,
) -> None:
    sandbox_root = tmp_path / "sandbox"
    write_sandbox_source(sandbox_root)
    renamed = sandbox_root / "validator" / "custom-benchmark.json"
    (sandbox_root / "validator" / "curated-highs-only-2025-08-08.json").rename(renamed)

    with pytest.raises(ValueError, match="must be named"):
        resolve_sn60_sandbox_source(
            sandbox_root=str(sandbox_root),
            benchmark_file=str(renamed),
            sandbox_commit="commit-1",
            scorer_version="ScaBenchScorerV2",
        )


def test_default_evaluation_hook_points_validator_dir_at_recorded_benchmark(
    tmp_path: Path, monkeypatch
) -> None:
    from kata.evaluators.sn60_bitsec import build_default_evaluation_hook

    sandbox_root = tmp_path / "sandbox"
    benchmark_path = write_sandbox_source(sandbox_root)
    source = resolve_sn60_sandbox_source(
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit="commit-1",
        scorer_version="ScaBenchScorerV2",
    )
    context = _make_context(tmp_path, source)
    Path(context.report_path).parent.mkdir(parents=True, exist_ok=True)

    captured = {}

    def fake_run(cmd, *args, **kwargs):
        captured["env"] = kwargs.get("env", {})
        return subprocess.CompletedProcess(cmd, 0, stdout="{}", stderr="")

    monkeypatch.setenv("CHUTES_API_KEY", "scoring-key")
    monkeypatch.setattr(subprocess, "run", fake_run)

    build_default_evaluation_hook(source)(context, {"success": True})

    assert captured["env"]["VALIDATOR_DIR"] == str(benchmark_path.parent)
    # The scorer joins VALIDATOR_DIR + the hardcoded filename, so that must be
    # the exact file whose hash Kata recorded.
    assert (
        Path(captured["env"]["VALIDATOR_DIR"]) / "curated-highs-only-2025-08-08.json"
    ) == benchmark_path


def test_project_passes_requires_two_of_three_runs() -> None:
    assert project_passes(pass_count=2, replica_count=3)
    assert project_passes(pass_count=3, replica_count=3)
    assert not project_passes(pass_count=1, replica_count=3)
    assert not project_passes(pass_count=0, replica_count=3)
    assert project_passes(pass_count=1, replica_count=1)
    assert not project_passes(pass_count=1, replica_count=2)
    assert not project_passes(pass_count=0, replica_count=0)


def test_resolve_sn60_sandbox_source_rejects_mismatched_pinned_commit(
    tmp_path: Path,
) -> None:
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = write_sandbox_source(sandbox_root)
    subprocess.run(["git", "init", "--quiet", str(sandbox_root)], check=True)
    subprocess.run(["git", "-C", str(sandbox_root), "add", "-A"], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(sandbox_root),
            "-c",
            "user.name=kata-test",
            "-c",
            "user.email=kata-test@example.com",
            "commit",
            "--quiet",
            "-m",
            "seed",
        ],
        check=True,
    )
    head = subprocess.run(
        ["git", "-C", str(sandbox_root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    source = resolve_sn60_sandbox_source(
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit=head,
        scorer_version="ScaBenchScorerV2",
    )
    assert source.sandbox_commit == head

    with pytest.raises(ValueError, match="does not match the checked-out sandbox"):
        resolve_sn60_sandbox_source(
            sandbox_root=str(sandbox_root),
            benchmark_file=str(benchmark_path),
            sandbox_commit="0" * 40,
            scorer_version="ScaBenchScorerV2",
        )


def test_extract_evaluation_metrics_gates_all_metrics_on_success() -> None:
    metrics = extract_evaluation_metrics(
        {
            "status": "error",
            "result": {
                "detection_rate": 1.0,
                "true_positives": 8,
                "total_expected": 8,
                "total_found": 8,
                "result": "PASS",
            },
        }
    )

    assert metrics["evaluation_status"] == "error"
    assert metrics["score"] == 0.0
    assert metrics["detection_rate"] == 0.0
    # A failed evaluation must not contribute a PASS or true positives; the
    # king variant is never invalid-gated, so ungated metrics would inflate
    # the promotion bar.
    assert metrics["result"] is None
    assert metrics["true_positives"] == 0
    assert metrics["total_expected"] == 0
    assert metrics["total_found"] == 0


def test_extract_evaluation_metrics_keeps_metrics_for_success() -> None:
    metrics = extract_evaluation_metrics(
        {
            "status": "success",
            "result": {
                "detection_rate": 0.75,
                "true_positives": 6,
                "total_expected": 8,
                "total_found": 7,
                "result": "PASS",
            },
        }
    )

    assert metrics["evaluation_status"] == "success"
    assert metrics["score"] == 0.75
    assert metrics["result"] == "PASS"
    assert metrics["true_positives"] == 6
    assert metrics["total_expected"] == 8
    assert metrics["total_found"] == 7


def test_execution_subprocess_env_strips_validator_scoring_secrets(
    monkeypatch,
) -> None:
    from kata.evaluators.sn60_bitsec import execution_subprocess_env

    monkeypatch.setenv("CHUTES_API_KEY", "scoring-key")
    monkeypatch.setenv("KATA_VALIDATOR_API_KEY", "validator-key")
    monkeypatch.setenv("INFERENCE_API_KEY", "miner-key")

    env = execution_subprocess_env()

    assert "CHUTES_API_KEY" not in env
    assert "KATA_VALIDATOR_API_KEY" not in env
    assert env["INFERENCE_API_KEY"] == "miner-key"


def test_build_bitsec_evaluation_command_quotes_interpolated_values(
    tmp_path: Path,
) -> None:
    from kata.evaluators.sn60_bitsec import build_bitsec_evaluation_command

    context = Sn60ReplicaContext(
        run_id="run-1",
        variant_name="candidate",
        project_key="project'; import os; os.system('x'); '",
        replica_index=1,
        bundle_root=str(tmp_path / "bundle"),
        reports_root=str(tmp_path / "reports" / "project-a"),
        report_path=str(tmp_path / "reports" / "project-a" / "report.json"),
        evaluation_path=str(tmp_path / "reports" / "project-a" / "evaluation.json"),
        sandbox_source=None,
    )

    command = build_bitsec_evaluation_command(context)

    script = command[-1]
    # The hostile project key must survive as a single quoted literal instead
    # of terminating the string and injecting statements.
    assert repr(context.project_key) in script
    import ast

    ast.parse(script)
