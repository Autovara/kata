from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from kata.evaluators.sn60_bitsec import (
    Sn60ReplicaContext,
    Sn60ReplicaResult,
    build_bitsec_execution_command,
    build_default_execution_hook,
    ensure_internal_agent_network,
    extract_evaluation_metrics,
    load_sn60_benchmark_project_keys,
    project_passes,
    resolve_sn60_early_stop,
    resolve_sn60_inference_api,
    resolve_sn60_proxy_network,
    resolve_sn60_sandbox_source,
    run_sn60_bitsec_duel,
    sn60_codebase_pass_count,
    sn60_synthetic_ids,
    split_projects_for_early_stop,
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
    benchmark_path.write_text(
        json.dumps(
            [
                {"project_id": "project-alpha", "vulnerabilities": []},
                {"project_id": "project-beta", "vulnerabilities": []},
            ]
        )
        + "\n",
        encoding="utf-8",
    )
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


def test_load_sn60_benchmark_project_keys_reads_real_snapshot_ids(tmp_path: Path) -> None:
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = write_sandbox_source(sandbox_root)
    payload = json.loads(benchmark_path.read_text(encoding="utf-8"))
    payload.extend(
        [
            {"project_id": "project-beta", "vulnerabilities": []},
            {"project_id": "project-alpha", "vulnerabilities": []},
        ]
    )
    benchmark_path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
    source = resolve_sn60_sandbox_source(
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit="commit-1",
        scorer_version="ScaBenchScorerV2",
    )

    assert load_sn60_benchmark_project_keys(source) == ["project-alpha", "project-beta"]


def test_run_sn60_bitsec_duel_rejects_project_keys_missing_from_benchmark(
    tmp_path: Path,
) -> None:
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = write_sandbox_source(sandbox_root)
    king_root = tmp_path / "king"
    candidate_root = tmp_path / "candidate"
    write_bundle(king_root, agent_source="def agent_main():\n    return {'vulnerabilities': []}\n")
    write_bundle(
        candidate_root,
        agent_source="def agent_main():\n    return {'vulnerabilities': []}\n",
    )

    with pytest.raises(ValueError, match="not present in the resolved benchmark"):
        run_sn60_bitsec_duel(
            king_artifact_path=str(king_root),
            candidate_artifact_path=str(candidate_root),
            project_keys=["project-missing"],
            output_root=str(tmp_path / "runs"),
            sandbox_root=str(sandbox_root),
            benchmark_file=str(benchmark_path),
            sandbox_commit="commit-1",
        )


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


def _run_default_execution_hook_with_report(tmp_path, monkeypatch, source, report_text):
    """Drive the default execution hook with the docker/subprocess edges mocked,
    after the (untrusted) agent wrote `report_text` to report.json."""
    from kata.evaluators import sn60_bitsec as sn60

    context = _make_context(tmp_path, source)
    Path(context.report_path).parent.mkdir(parents=True, exist_ok=True)
    Path(context.report_path).write_text(report_text, encoding="utf-8")

    monkeypatch.setenv("INFERENCE_API_KEY", "run-token")
    monkeypatch.setattr(sn60, "ensure_internal_agent_network", lambda *_a, **_k: None)
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda cmd, *a, **k: subprocess.CompletedProcess(cmd, 0, stdout="", stderr=""),
    )
    return sn60.build_default_execution_hook(source)(context)


def test_malformed_agent_report_is_recorded_failure_not_a_crash(
    tmp_path: Path, monkeypatch
) -> None:
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = write_sandbox_source(sandbox_root)
    source = resolve_sn60_sandbox_source(
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit="commit-1",
        scorer_version="ScaBenchScorerV2",
    )

    # report.json is agent-writable and untrusted. Malformed JSON and a non-dict
    # JSON must both degrade to a failed replica, never abort the whole duel.
    for report_text in ("{not valid json", "[1, 2, 3]", "null"):
        payload = _run_default_execution_hook_with_report(
            tmp_path, monkeypatch, source, report_text
        )
        assert isinstance(payload, dict)
        assert payload.get("success") is False
        assert "error" in payload

    # A well-formed object is still returned verbatim.
    good = _run_default_execution_hook_with_report(
        tmp_path, monkeypatch, source, '{"success": true, "report": {}}'
    )
    assert good == {"success": True, "report": {}}


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


def test_extract_evaluation_metrics_accepts_enum_repr_status() -> None:
    # The SN60 sandbox serializes its Status enum as "Status.SUCCESS" (via
    # json.dumps(default=str)); a valid run must not be counted as invalid.
    metrics = extract_evaluation_metrics(
        {
            "status": "Status.SUCCESS",
            "result": {
                "detection_rate": 0.5,
                "true_positives": 1,
                "total_expected": 2,
                "total_found": 1,
                "result": "PASS",
            },
        }
    )

    assert metrics["evaluation_status"] == "success"
    assert metrics["score"] == 0.5
    assert metrics["true_positives"] == 1

    # A non-success enum status is still treated as invalid.
    failed = extract_evaluation_metrics({"status": "Status.ERROR", "result": {}})
    assert failed["evaluation_status"] == "error"
    assert failed["score"] == 0.0


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


def _completed(cmd, returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(cmd, returncode, stdout=stdout, stderr=stderr)


def test_resolve_sn60_inference_api_defaults_and_overrides(monkeypatch) -> None:
    monkeypatch.delenv("KATA_SN60_INFERENCE_API", raising=False)
    assert resolve_sn60_inference_api() == "http://bitsec_proxy:8000"
    monkeypatch.setenv("KATA_SN60_INFERENCE_API", " http://secret-proxy:9000 ")
    assert resolve_sn60_inference_api() == "http://secret-proxy:9000"


def test_resolve_sn60_proxy_network_defaults_and_overrides(monkeypatch) -> None:
    monkeypatch.delenv("KATA_SN60_PROXY_NETWORK", raising=False)
    assert resolve_sn60_proxy_network() == "bitsec-net"
    monkeypatch.setenv("KATA_SN60_PROXY_NETWORK", "kata-secret-net")
    assert resolve_sn60_proxy_network() == "kata-secret-net"


def test_build_bitsec_execution_command_uses_configured_endpoint(tmp_path: Path) -> None:
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = write_sandbox_source(sandbox_root)
    source = resolve_sn60_sandbox_source(
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit="commit-1",
        scorer_version="ScaBenchScorerV2",
    )
    context = _make_context(tmp_path, source)

    command = build_bitsec_execution_command(
        context,
        proxy_network="kata-secret-net",
        inference_api="http://secret-proxy:9000",
    )

    assert "--network" in command
    assert "kata-secret-net" in command
    assert "INFERENCE_API=http://secret-proxy:9000" in command


def test_ensure_internal_agent_network_creates_when_absent() -> None:
    calls = []

    def fake_run(cmd, *args, **kwargs):
        calls.append(cmd)
        if cmd[:3] == ["docker", "network", "inspect"]:
            return _completed(cmd, returncode=1, stderr="Error: No such network: bitsec-net")
        return _completed(cmd, returncode=0)

    ensure_internal_agent_network("bitsec-net", run=fake_run)

    assert ["docker", "network", "create", "--internal", "bitsec-net"] in calls


def test_ensure_internal_agent_network_accepts_existing_internal() -> None:
    calls = []

    def fake_run(cmd, *args, **kwargs):
        calls.append(cmd)
        return _completed(cmd, returncode=0, stdout="true\n")

    ensure_internal_agent_network("bitsec-net", run=fake_run)

    # Existing internal network: assert only, never create.
    assert not any(cmd[:3] == ["docker", "network", "create"] for cmd in calls)


def test_ensure_internal_agent_network_rejects_non_internal() -> None:
    def fake_run(cmd, *args, **kwargs):
        return _completed(cmd, returncode=0, stdout="false\n")

    with pytest.raises(ValueError, match="permits external egress"):
        ensure_internal_agent_network("bitsec-net", run=fake_run)


def test_ensure_internal_agent_network_surfaces_inspect_errors() -> None:
    def fake_run(cmd, *args, **kwargs):
        return _completed(cmd, returncode=1, stderr="Cannot connect to the Docker daemon")

    with pytest.raises(RuntimeError, match="Failed to inspect docker network"):
        ensure_internal_agent_network("bitsec-net", run=fake_run)


def test_default_execution_hook_asserts_internal_network_and_uses_endpoint(
    tmp_path: Path, monkeypatch
) -> None:
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
    Path(context.report_path).write_text(
        json.dumps({"success": True, "report": {"vulnerabilities": []}}),
        encoding="utf-8",
    )
    monkeypatch.setenv("INFERENCE_API_KEY", "run-token")
    monkeypatch.setenv("KATA_SN60_INFERENCE_API", "http://secret-proxy:9000")
    monkeypatch.delenv("KATA_SN60_PROXY_NETWORK", raising=False)

    calls = []

    def fake_run(cmd, *args, **kwargs):
        calls.append(cmd)
        if cmd[:3] == ["docker", "network", "inspect"]:
            return _completed(cmd, returncode=0, stdout="true\n")
        return _completed(cmd, returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = build_default_execution_hook(source)(context)

    assert result == {"success": True, "report": {"vulnerabilities": []}}
    # The internal-network guarantee runs before the agent container starts.
    assert any(cmd[:3] == ["docker", "network", "inspect"] for cmd in calls)
    docker_run = next(cmd for cmd in calls if cmd[:2] == ["docker", "run"])
    assert "INFERENCE_API=http://secret-proxy:9000" in docker_run


def test_default_execution_hook_refuses_non_internal_network(
    tmp_path: Path, monkeypatch
) -> None:
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = write_sandbox_source(sandbox_root)
    source = resolve_sn60_sandbox_source(
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit="commit-1",
        scorer_version="ScaBenchScorerV2",
    )
    context = _make_context(tmp_path, source)
    monkeypatch.setenv("INFERENCE_API_KEY", "run-token")

    docker_ran = {"value": False}

    def fake_run(cmd, *args, **kwargs):
        if cmd[:3] == ["docker", "network", "inspect"]:
            return _completed(cmd, returncode=0, stdout="false\n")
        if cmd[:2] == ["docker", "run"]:
            docker_ran["value"] = True
        return _completed(cmd, returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(ValueError, match="permits external egress"):
        build_default_execution_hook(source)(context)

    # Untrusted agent must never start on an egress-capable network.
    assert docker_ran["value"] is False


# --- two-phase early-stop ---------------------------------------------------


def _replica(project_key: str, result: str | None, status: str = "success") -> Sn60ReplicaResult:
    return Sn60ReplicaResult(
        project_key=project_key,
        replica_index=1,
        report_path="",
        evaluation_path="",
        execution_success=True,
        evaluation_status=status,
        score=0.0,
        detection_rate=0.0,
        result=result,
        true_positives=0,
        total_expected=0,
        total_found=0,
    )


def _make_multi_project_benchmark(root: Path, project_keys: list[str]) -> Path:
    benchmark_path = root / "validator" / "curated-highs-only-2025-08-08.json"
    benchmark_path.parent.mkdir(parents=True, exist_ok=True)
    benchmark_path.write_text(
        json.dumps([{"project_id": key, "vulnerabilities": []} for key in project_keys]) + "\n",
        encoding="utf-8",
    )
    return benchmark_path


def _passfail_hooks(*, king_pass: bool, candidate_pass: bool, candidate_status: str = "success"):
    executed: list[tuple[str, str]] = []

    def execute(context: Sn60ReplicaContext) -> dict[str, object]:
        executed.append((context.variant_name, context.project_key))
        return {"success": True, "report": {"project": context.project_key, "vulnerabilities": []}}

    def evaluate(context: Sn60ReplicaContext, _report: dict[str, object]) -> dict[str, object]:
        is_candidate = context.variant_name == "candidate"
        status = candidate_status if is_candidate else "success"
        passes = candidate_pass if is_candidate else king_pass
        return {
            "status": status,
            "result": {
                "result": "PASS" if passes else "FAIL",
                "detection_rate": 1.0 if passes else 0.0,
                "true_positives": 1 if passes else 0,
                "total_expected": 1,
                "total_found": 1 if passes else 0,
            },
        }

    return executed, execute, evaluate


def _run_early_stop_duel(tmp_path, monkeypatch, *, project_keys, phase1, margin, hooks):
    executed, execute, evaluate = hooks
    monkeypatch.setenv("KATA_SN60_EARLY_STOP", "1")
    monkeypatch.setenv("KATA_SN60_EARLY_STOP_PHASE1", str(phase1))
    monkeypatch.setenv("KATA_SN60_EARLY_STOP_MARGIN", str(margin))
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = _make_multi_project_benchmark(sandbox_root, project_keys)
    king_root = tmp_path / "king"
    candidate_root = tmp_path / "candidate"
    write_bundle(king_root, agent_source="def agent_main():\n    return {}\n")
    write_bundle(candidate_root, agent_source="def agent_main():\n    return {}\n")
    summary = run_sn60_bitsec_duel(
        king_artifact_path=str(king_root),
        candidate_artifact_path=str(candidate_root),
        project_keys=project_keys,
        output_root=str(tmp_path / "runs"),
        replicas_per_project=1,
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit="commit-early-stop",
        execution_hook=execute,
        evaluation_hook=evaluate,
    )
    early_stop_path = Path(summary.output_root) / "early_stop.json"
    info = (
        json.loads(early_stop_path.read_text(encoding="utf-8"))
        if early_stop_path.exists()
        else None
    )
    return summary, executed, info


def test_resolve_early_stop_is_none_when_disabled(monkeypatch) -> None:
    monkeypatch.delenv("KATA_SN60_EARLY_STOP", raising=False)
    assert resolve_sn60_early_stop(32) is None


def test_resolve_early_stop_defaults_and_overrides(monkeypatch) -> None:
    monkeypatch.setenv("KATA_SN60_EARLY_STOP", "1")
    monkeypatch.delenv("KATA_SN60_EARLY_STOP_PHASE1", raising=False)
    monkeypatch.delenv("KATA_SN60_EARLY_STOP_MARGIN", raising=False)
    config = resolve_sn60_early_stop(32)
    assert config is not None
    assert config.phase1_size == 16  # half of 32
    assert config.loss_margin == 6

    monkeypatch.setenv("KATA_SN60_EARLY_STOP_PHASE1", "20")
    monkeypatch.setenv("KATA_SN60_EARLY_STOP_MARGIN", "4")
    config = resolve_sn60_early_stop(32)
    assert config.phase1_size == 20
    assert config.loss_margin == 4

    # phase1 is clamped to [1, total-1] so phase 2 is never empty.
    monkeypatch.setenv("KATA_SN60_EARLY_STOP_PHASE1", "99")
    assert resolve_sn60_early_stop(8).phase1_size == 7


def test_split_projects_is_stable_and_partitions_all_keys() -> None:
    keys = [f"project-{i:02d}" for i in range(10)]
    p1_a, p2_a = split_projects_for_early_stop(keys, seed="king-hash|cand-hash", phase1_size=4)
    p1_b, p2_b = split_projects_for_early_stop(keys, seed="king-hash|cand-hash", phase1_size=4)
    assert (p1_a, p2_a) == (p1_b, p2_b)  # deterministic for the same seed
    assert len(p1_a) == 4 and len(p2_a) == 6
    assert sorted(p1_a + p2_a) == sorted(keys)  # a true partition
    # A different seed generally yields a different phase-1 subset.
    p1_c, _ = split_projects_for_early_stop(keys, seed="other-seed", phase1_size=4)
    assert set(p1_c) != set(p1_a)


def test_codebase_pass_count_uses_two_thirds_rule() -> None:
    results = [
        _replica("a", "PASS"),
        _replica("b", "FAIL"),
        _replica("c", None, status="error"),
    ]
    assert sn60_codebase_pass_count(results) == 1  # only "a" passes


def test_early_stop_triggers_on_decisive_loss(tmp_path, monkeypatch) -> None:
    keys = [f"project-{i:02d}" for i in range(6)]
    summary, executed, info = _run_early_stop_duel(
        tmp_path,
        monkeypatch,
        project_keys=keys,
        phase1=3,
        margin=2,
        hooks=_passfail_hooks(king_pass=True, candidate_pass=False),
    )
    distinct_projects = {project for _, project in executed}
    assert len(distinct_projects) == 3  # phase 2 was skipped
    assert len(summary.project_keys) == 3
    assert info["early_stopped"] is True
    assert "decisive loss" in info["reason"]
    assert info["gap"] == -3


def test_early_stop_triggers_on_candidate_invalid_run(tmp_path, monkeypatch) -> None:
    keys = [f"project-{i:02d}" for i in range(6)]
    # Margin is high enough that only the invalid-run rule can fire.
    summary, executed, info = _run_early_stop_duel(
        tmp_path,
        monkeypatch,
        project_keys=keys,
        phase1=3,
        margin=10,
        hooks=_passfail_hooks(king_pass=True, candidate_pass=False, candidate_status="error"),
    )
    distinct_projects = {project for _, project in executed}
    assert len(distinct_projects) == 3
    assert info["early_stopped"] is True
    assert "invalid" in info["reason"]
    assert info["candidate_invalid_runs_phase1"] == 3


def test_early_stop_never_short_circuits_a_win(tmp_path, monkeypatch) -> None:
    keys = [f"project-{i:02d}" for i in range(6)]
    summary, executed, info = _run_early_stop_duel(
        tmp_path,
        monkeypatch,
        project_keys=keys,
        phase1=3,
        margin=2,
        hooks=_passfail_hooks(king_pass=False, candidate_pass=True),
    )
    distinct_projects = {project for _, project in executed}
    assert len(distinct_projects) == 6  # full benchmark ran
    assert len(summary.project_keys) == 6
    assert info["early_stopped"] is False


def test_early_stop_runs_full_grid_when_borderline(tmp_path, monkeypatch) -> None:
    keys = [f"project-{i:02d}" for i in range(6)]
    summary, executed, info = _run_early_stop_duel(
        tmp_path,
        monkeypatch,
        project_keys=keys,
        phase1=3,
        margin=2,
        hooks=_passfail_hooks(king_pass=True, candidate_pass=True),
    )
    distinct_projects = {project for _, project in executed}
    assert len(distinct_projects) == 6
    assert info["early_stopped"] is False
    assert info["gap"] == 0


def test_early_stop_disabled_writes_no_sidecar_and_runs_full(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("KATA_SN60_EARLY_STOP", raising=False)
    keys = [f"project-{i:02d}" for i in range(4)]
    executed, execute, evaluate = _passfail_hooks(king_pass=True, candidate_pass=False)
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = _make_multi_project_benchmark(sandbox_root, keys)
    king_root = tmp_path / "king"
    candidate_root = tmp_path / "candidate"
    write_bundle(king_root, agent_source="def agent_main():\n    return {}\n")
    write_bundle(candidate_root, agent_source="def agent_main():\n    return {}\n")
    summary = run_sn60_bitsec_duel(
        king_artifact_path=str(king_root),
        candidate_artifact_path=str(candidate_root),
        project_keys=keys,
        output_root=str(tmp_path / "runs"),
        replicas_per_project=1,
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit="commit-early-stop",
        execution_hook=execute,
        evaluation_hook=evaluate,
    )
    assert {project for _, project in executed} == set(keys)  # all projects ran
    assert summary.project_keys == keys  # original order preserved
    assert not (Path(summary.output_root) / "early_stop.json").exists()
