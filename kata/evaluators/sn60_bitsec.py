from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import subprocess
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from statistics import fmean
from typing import Callable, NamedTuple, TypedDict

from kata.agent_bundle import AGENT_ENTRY_FILENAME, load_bundle_files, write_bundle_files
from kata.provenance import sha256_directory
from kata.util import write_json

SN60_BITSEC_EVALUATOR_ID = "sn60_bitsec"
DEFAULT_SN60_DUEL_SCHEMA_VERSION = 2
DEFAULT_SANDBOX_PROXY_NETWORK = "bitsec-net"
DEFAULT_SANDBOX_PROXY_URL = "http://localhost:8087"
DEFAULT_SANDBOX_INFERENCE_API = "http://bitsec_proxy:8000"
DEFAULT_EVAL_MAX_VULNS = 100
DEFAULT_REPLICAS_PER_PROJECT = 3
DEFAULT_BENCHMARK_FILENAME = "curated-highs-only-2025-08-08.json"


@dataclass(frozen=True)
class Sn60SandboxSource:
    sandbox_root: str
    benchmark_file: str
    benchmark_sha256: str
    sandbox_commit: str
    scorer_version: str


@dataclass(frozen=True)
class Sn60ReplicaContext:
    run_id: str
    variant_name: str
    project_key: str
    replica_index: int
    bundle_root: str
    reports_root: str
    report_path: str
    evaluation_path: str
    sandbox_source: Sn60SandboxSource
    eval_max_vulns: int = DEFAULT_EVAL_MAX_VULNS


class Sn60SyntheticIds(NamedTuple):
    """Deterministic numeric identity for a single SN60 replica.

    SN60 normally gets these from the platform job payload. Locally we derive
    stable synthetic ids so (a) the pinned proxy meters/summaries each replica
    distinctly instead of colliding under a fixed id, and (b) king and
    candidate replicas are distinguishable in scorer/executor logs.
    """

    job_run_id: int
    job_id: int
    validator_id: int
    agent_id: int


def stable_synthetic_id(*parts: object) -> int:
    key = "\x1f".join(str(part) for part in parts).encode("utf-8")
    digest = hashlib.sha256(key).digest()
    # Positive value inside signed-32-bit range; avoids the 0 sentinel.
    return 1 + (int.from_bytes(digest[:4], "big") % (2**31 - 2))


def sn60_synthetic_ids(context: Sn60ReplicaContext) -> Sn60SyntheticIds:
    return Sn60SyntheticIds(
        # Distinct per scored replica so proxy metering and scorer headers do
        # not collide across replicas, variants, or duels.
        job_run_id=stable_synthetic_id(
            context.run_id,
            context.variant_name,
            context.project_key,
            context.replica_index,
        ),
        # Groups all replicas of one duel.
        job_id=stable_synthetic_id(context.run_id),
        # Stable local validator identity.
        validator_id=1,
        # Distinct per side (king vs candidate) within a duel.
        agent_id=stable_synthetic_id(context.run_id, context.variant_name),
    )


@dataclass(frozen=True)
class Sn60ReplicaResult:
    project_key: str
    replica_index: int
    report_path: str
    evaluation_path: str
    execution_success: bool
    evaluation_status: str
    score: float
    detection_rate: float
    result: str | None
    true_positives: int
    total_expected: int
    total_found: int


class Sn60EvaluationMetrics(TypedDict):
    evaluation_status: str
    score: float
    detection_rate: float
    result: str | None
    true_positives: int
    total_expected: int
    total_found: int


@dataclass(frozen=True)
class Sn60ProjectAggregate:
    project_key: str
    replica_count: int
    successful_runs: int
    invalid_runs: int
    pass_count: int
    passed: bool
    average_detection_rate: float
    true_positives: int
    total_expected: int
    total_found: int


@dataclass(frozen=True)
class Sn60VariantSummary:
    variant_name: str
    artifact_path: str
    artifact_hash: str
    successful_runs: int
    invalid_runs: int
    pass_count: int
    codebase_pass_count: int
    aggregated_score: float
    average_detection_rate: float
    true_positives: int
    total_expected: int
    total_found: int
    project_summaries: list[Sn60ProjectAggregate]
    replica_results: list[Sn60ReplicaResult]


@dataclass(frozen=True)
class Sn60DuelSummary:
    schema_version: int
    run_id: str
    created_at: str
    output_root: str
    project_keys: list[str]
    replicas_per_project: int
    sandbox_source: Sn60SandboxSource
    king: Sn60VariantSummary
    candidate: Sn60VariantSummary


Sn60ExecutionHook = Callable[[Sn60ReplicaContext], dict[str, object]]
Sn60EvaluationHook = Callable[[Sn60ReplicaContext, dict[str, object]], dict[str, object]]


def run_sn60_bitsec_duel(
    *,
    king_artifact_path: str,
    candidate_artifact_path: str,
    project_keys: list[str],
    output_root: str | None = None,
    replicas_per_project: int = DEFAULT_REPLICAS_PER_PROJECT,
    sandbox_root: str | None = None,
    benchmark_file: str | None = None,
    sandbox_commit: str | None = None,
    scorer_version: str = "ScaBenchScorerV2",
    eval_max_vulns: int = DEFAULT_EVAL_MAX_VULNS,
    execution_hook: Sn60ExecutionHook | None = None,
    evaluation_hook: Sn60EvaluationHook | None = None,
) -> Sn60DuelSummary:
    if not project_keys:
        raise ValueError("SN60 duel requires at least one project key.")
    if replicas_per_project <= 0:
        raise ValueError("SN60 duel replicas_per_project must be positive.")
    if eval_max_vulns <= 0:
        raise ValueError("SN60 duel eval_max_vulns must be positive.")

    source = resolve_sn60_sandbox_source(
        sandbox_root=sandbox_root,
        benchmark_file=benchmark_file,
        sandbox_commit=sandbox_commit,
        scorer_version=scorer_version,
    )
    king_root = Path(king_artifact_path).expanduser().resolve()
    candidate_root = Path(candidate_artifact_path).expanduser().resolve()
    output_base = (
        Path(output_root).expanduser().resolve()
        if output_root
        else Path("runs").resolve()
    )
    run_id = build_sn60_duel_id()
    run_root = output_base / run_id
    run_root.mkdir(parents=True, exist_ok=False)

    king_summary = evaluate_variant(
        run_id=run_id,
        run_root=run_root,
        variant_name="king",
        artifact_root=king_root,
        project_keys=project_keys,
        replicas_per_project=replicas_per_project,
        sandbox_source=source,
        eval_max_vulns=eval_max_vulns,
        execution_hook=execution_hook or build_default_execution_hook(source),
        evaluation_hook=evaluation_hook or build_default_evaluation_hook(source),
    )
    candidate_summary = evaluate_variant(
        run_id=run_id,
        run_root=run_root,
        variant_name="candidate",
        artifact_root=candidate_root,
        project_keys=project_keys,
        replicas_per_project=replicas_per_project,
        sandbox_source=source,
        eval_max_vulns=eval_max_vulns,
        execution_hook=execution_hook or build_default_execution_hook(source),
        evaluation_hook=evaluation_hook or build_default_evaluation_hook(source),
    )

    summary = Sn60DuelSummary(
        schema_version=DEFAULT_SN60_DUEL_SCHEMA_VERSION,
        run_id=run_id,
        created_at=datetime.now(UTC).isoformat(),
        output_root=str(run_root),
        project_keys=list(project_keys),
        replicas_per_project=replicas_per_project,
        sandbox_source=source,
        king=king_summary,
        candidate=candidate_summary,
    )
    write_sn60_duel_summary(run_root / "duel_summary.json", summary)
    return summary


def evaluate_variant(
    *,
    run_id: str,
    run_root: Path,
    variant_name: str,
    artifact_root: Path,
    project_keys: list[str],
    replicas_per_project: int,
    sandbox_source: Sn60SandboxSource,
    execution_hook: Sn60ExecutionHook,
    evaluation_hook: Sn60EvaluationHook,
    eval_max_vulns: int = DEFAULT_EVAL_MAX_VULNS,
) -> Sn60VariantSummary:
    variant_root = run_root / variant_name
    artifact_hash = hash_bundle_root(artifact_root)
    replica_results: list[Sn60ReplicaResult] = []

    for project_key in project_keys:
        for replica_index in range(1, replicas_per_project + 1):
            replica_root = variant_root / project_key / f"replica-{replica_index:02d}"
            bundle_root = replica_root / "bundle"
            project_reports_root = replica_root / "reports" / project_key
            project_reports_root.mkdir(parents=True, exist_ok=True)
            stage_bundle(artifact_root, bundle_root)

            context = Sn60ReplicaContext(
                run_id=run_id,
                variant_name=variant_name,
                project_key=project_key,
                replica_index=replica_index,
                bundle_root=str(bundle_root),
                reports_root=str(project_reports_root),
                report_path=str(project_reports_root / "report.json"),
                evaluation_path=str(project_reports_root / "evaluation.json"),
                sandbox_source=sandbox_source,
                eval_max_vulns=eval_max_vulns,
            )
            report_payload = execution_hook(context)
            write_json(Path(context.report_path), report_payload)
            evaluation_payload = evaluation_hook(context, report_payload)
            write_json(Path(context.evaluation_path), evaluation_payload)
            replica_results.append(
                build_replica_result(context, report_payload, evaluation_payload)
            )

    return summarize_variant(
        variant_name=variant_name,
        artifact_root=artifact_root,
        artifact_hash=artifact_hash,
        replica_results=replica_results,
    )


def resolve_sn60_sandbox_source(
    *,
    sandbox_root: str | None = None,
    benchmark_file: str | None = None,
    sandbox_commit: str | None = None,
    scorer_version: str,
) -> Sn60SandboxSource:
    resolved_sandbox_root = (
        Path(sandbox_root).expanduser().resolve()
        if sandbox_root
        else default_sandbox_root()
    )
    resolved_benchmark_file = (
        Path(benchmark_file).expanduser().resolve()
        if benchmark_file
        else resolved_sandbox_root / "validator" / DEFAULT_BENCHMARK_FILENAME
    )
    if not resolved_benchmark_file.exists():
        raise FileNotFoundError(
            f"SN60 benchmark snapshot does not exist: {resolved_benchmark_file}"
        )
    if resolved_benchmark_file.name != DEFAULT_BENCHMARK_FILENAME:
        # The pinned Bitsec scorer hardcodes this filename and reads it from
        # settings.validator_dir. Kata points VALIDATOR_DIR at this file's
        # parent, so a differently-named file would make the recorded
        # benchmark_sha256 describe a file the scorer never reads. Reject it
        # rather than record dishonest provenance.
        raise ValueError(
            "SN60 benchmark file must be named "
            f"'{DEFAULT_BENCHMARK_FILENAME}' because the pinned Bitsec scorer "
            f"reads that hardcoded filename; got '{resolved_benchmark_file.name}'. "
            "Rename the snapshot or update the sandbox mirror to match."
        )
    if sandbox_commit and (resolved_sandbox_root / ".git").exists():
        actual_commit = resolve_git_commit(resolved_sandbox_root)
        if actual_commit != sandbox_commit:
            raise ValueError(
                "Pinned SN60 sandbox commit does not match the checked-out sandbox: "
                f"pinned {sandbox_commit}, actual {actual_commit}."
            )
    resolved_commit = sandbox_commit or resolve_git_commit(resolved_sandbox_root)
    return Sn60SandboxSource(
        sandbox_root=str(resolved_sandbox_root),
        benchmark_file=str(resolved_benchmark_file),
        benchmark_sha256=sha256_directory(
            resolved_benchmark_file.parent,
            include=[resolved_benchmark_file.name],
        ),
        sandbox_commit=resolved_commit,
        scorer_version=scorer_version,
    )


def default_sandbox_root() -> Path:
    env_root = os.environ.get("KATA_SN60_SANDBOX_ROOT")
    if env_root and env_root.strip():
        return Path(env_root).expanduser().resolve()
    return workspace_root() / "sandbox"


def workspace_root() -> Path:
    return Path(__file__).resolve().parents[3]


def resolve_git_commit(repo_root: Path) -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=str(repo_root),
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def build_sn60_duel_id() -> str:
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return f"sn60-duel-{timestamp}-{secrets.token_hex(3)}"


def stage_bundle(source_root: Path, destination_root: Path) -> None:
    bundle_files = load_bundle_files(source_root)
    if not bundle_files:
        raise ValueError(f"SN60 artifact bundle is empty: {source_root}")
    if destination_root.exists():
        shutil.rmtree(destination_root)
    destination_root.mkdir(parents=True, exist_ok=True)
    write_bundle_files(destination_root, bundle_files)


def hash_bundle_root(bundle_root: Path) -> str:
    bundle_files = load_bundle_files(bundle_root)
    if not bundle_files:
        raise ValueError(f"SN60 artifact bundle is empty: {bundle_root}")
    return sha256_directory(bundle_root, include=sorted(bundle_files))


def write_sn60_duel_summary(path: Path, summary: Sn60DuelSummary) -> None:
    write_json(path, asdict(summary))




def summarize_variant(
    *,
    variant_name: str,
    artifact_root: Path,
    artifact_hash: str,
    replica_results: list[Sn60ReplicaResult],
) -> Sn60VariantSummary:
    project_keys = sorted({result.project_key for result in replica_results})
    project_summaries = [
        summarize_project(
            project_key=project_key,
            replica_results=[
                result for result in replica_results if result.project_key == project_key
            ],
        )
        for project_key in project_keys
    ]
    detection_rates = [result.detection_rate for result in replica_results]
    codebase_pass_count = sum(1 for project in project_summaries if project.passed)
    return Sn60VariantSummary(
        variant_name=variant_name,
        artifact_path=str(artifact_root),
        artifact_hash=artifact_hash,
        successful_runs=sum(
            1 for result in replica_results if result.evaluation_status == "success"
        ),
        invalid_runs=sum(1 for result in replica_results if result.evaluation_status != "success"),
        pass_count=sum(1 for result in replica_results if result.result == "PASS"),
        codebase_pass_count=codebase_pass_count,
        # `aggregated score` per the SN60 spec: passed codebases / total codebases.
        # V1 runs one local validator replica-set, so this equals its validator score.
        aggregated_score=(
            codebase_pass_count / len(project_summaries) if project_summaries else 0.0
        ),
        average_detection_rate=fmean(detection_rates) if detection_rates else 0.0,
        true_positives=sum(result.true_positives for result in replica_results),
        total_expected=sum(result.total_expected for result in replica_results),
        total_found=sum(result.total_found for result in replica_results),
        project_summaries=project_summaries,
        replica_results=replica_results,
    )


def summarize_project(
    *,
    project_key: str,
    replica_results: list[Sn60ReplicaResult],
) -> Sn60ProjectAggregate:
    detection_rates = [result.detection_rate for result in replica_results]
    pass_count = sum(1 for result in replica_results if result.result == "PASS")
    return Sn60ProjectAggregate(
        project_key=project_key,
        replica_count=len(replica_results),
        successful_runs=sum(
            1 for result in replica_results if result.evaluation_status == "success"
        ),
        invalid_runs=sum(1 for result in replica_results if result.evaluation_status != "success"),
        pass_count=pass_count,
        passed=project_passes(pass_count=pass_count, replica_count=len(replica_results)),
        average_detection_rate=fmean(detection_rates) if detection_rates else 0.0,
        true_positives=sum(result.true_positives for result in replica_results),
        total_expected=sum(result.total_expected for result in replica_results),
        total_found=sum(result.total_found for result in replica_results),
    )


def project_passes(*, pass_count: int, replica_count: int) -> bool:
    """Codebase-level binary pass per the SN60 rule: at least 2 of 3 runs must pass.

    Generalized to other replica counts as pass_count/replica_count >= 2/3.
    """
    if replica_count <= 0:
        return False
    return pass_count * 3 >= replica_count * 2


def build_replica_result(
    context: Sn60ReplicaContext,
    report_payload: dict[str, object],
    evaluation_payload: dict[str, object],
) -> Sn60ReplicaResult:
    metrics = extract_evaluation_metrics(evaluation_payload)
    return Sn60ReplicaResult(
        project_key=context.project_key,
        replica_index=context.replica_index,
        report_path=context.report_path,
        evaluation_path=context.evaluation_path,
        execution_success=bool(report_payload.get("success")),
        evaluation_status=metrics["evaluation_status"],
        score=metrics["score"],
        detection_rate=metrics["detection_rate"],
        result=metrics["result"],
        true_positives=metrics["true_positives"],
        total_expected=metrics["total_expected"],
        total_found=metrics["total_found"],
    )


def extract_evaluation_metrics(evaluation_payload: dict[str, object]) -> Sn60EvaluationMetrics:
    status_value = str(evaluation_payload.get("status", "error")).lower()
    result_payload = evaluation_payload.get("result")
    if not isinstance(result_payload, dict):
        result_payload = {}
    is_success = status_value == "success"
    detection_rate = float(result_payload.get("detection_rate", 0.0) or 0.0)
    # Every metric is gated on evaluation success: a non-success replica must
    # not contribute a PASS or inflate true-positive counts. The king variant
    # is never gated on invalid_runs, so ungated metrics would silently raise
    # the promotion bar with data from failed runs.
    return {
        "evaluation_status": status_value,
        "score": detection_rate if is_success else 0.0,
        "detection_rate": detection_rate if is_success else 0.0,
        "result": (
            str(result_payload["result"])
            if is_success and result_payload.get("result") is not None
            else None
        ),
        "true_positives": (
            int(result_payload.get("true_positives", 0) or 0) if is_success else 0
        ),
        "total_expected": (
            int(result_payload.get("total_expected", 0) or 0) if is_success else 0
        ),
        "total_found": (
            int(result_payload.get("total_found", 0) or 0) if is_success else 0
        ),
    }


def build_default_execution_hook(source: Sn60SandboxSource) -> Sn60ExecutionHook:
    def _execute(context: Sn60ReplicaContext) -> dict[str, object]:
        command = build_bitsec_execution_command(context)
        env = {
            "INFERENCE_API_KEY": required_env("INFERENCE_API_KEY"),
        }
        completed = subprocess.run(
            command,
            cwd=source.sandbox_root,
            capture_output=True,
            text=True,
            env={**execution_subprocess_env(), **env},
        )
        report_path = Path(context.report_path)
        if report_path.exists():
            return json.loads(report_path.read_text(encoding="utf-8"))
        return {
            "success": False,
            "error": (
                f"Bitsec execution command failed with exit code {completed.returncode}: "
                f"{completed.stderr.strip() or completed.stdout.strip()}"
            ),
        }

    return _execute


def build_default_evaluation_hook(source: Sn60SandboxSource) -> Sn60EvaluationHook:
    def _evaluate(
        context: Sn60ReplicaContext,
        report_payload: dict[str, object],
    ) -> dict[str, object]:
        if not Path(context.report_path).exists():
            write_json(Path(context.report_path), report_payload)
        completed = subprocess.run(
            build_bitsec_evaluation_command(context),
            cwd=source.sandbox_root,
            capture_output=True,
            text=True,
            env={
                **default_subprocess_env(),
                # Point the SN60 scorer at the exact benchmark file Kata
                # resolved and recorded in provenance. The scorer hardcodes the
                # filename and reads settings.validator_dir, so without this the
                # recorded benchmark_sha256 could describe a different file than
                # the one actually scored.
                "VALIDATOR_DIR": str(
                    Path(source.benchmark_file).expanduser().resolve().parent
                ),
                "CHUTES_API_KEY": required_env("CHUTES_API_KEY"),
                "PROXY_URL": DEFAULT_SANDBOX_PROXY_URL,
            },
        )
        if completed.returncode == 0:
            try:
                return json.loads(completed.stdout.strip())
            except json.JSONDecodeError:
                pass
        evaluation_path = Path(context.evaluation_path)
        if evaluation_path.exists():
            return json.loads(evaluation_path.read_text(encoding="utf-8"))
        return {
            "status": "error",
            "error": (
                f"Bitsec evaluation command failed with exit code {completed.returncode}: "
                f"{completed.stderr.strip() or completed.stdout.strip()}"
            ),
            "result": {},
        }

    return _evaluate


def build_bitsec_execution_command(
    context: Sn60ReplicaContext,
    *,
    proxy_network: str = DEFAULT_SANDBOX_PROXY_NETWORK,
    inference_api: str = DEFAULT_SANDBOX_INFERENCE_API,
) -> list[str]:
    bundle_root = Path(context.bundle_root).resolve()
    reports_root = Path(context.reports_root).resolve()
    ids = sn60_synthetic_ids(context)
    return [
        "docker",
        "run",
        "--rm",
        "--network",
        proxy_network,
        # Match the SN60 executor's container resource envelope so agents run
        # under the same limits the real validator grants (executor.run_project:
        # memory="512m", cpu_quota=25000 == 0.25 CPU, pids_limit=64).
        "--memory",
        "512m",
        "--cpus",
        "0.25",
        "--pids-limit",
        "64",
        "--volume",
        f"{bundle_root}:/kata_bundle:ro",
        "--volume",
        f"{reports_root}:/kata_output",
        "--env",
        f"AGENT_FILE=/kata_bundle/{AGENT_ENTRY_FILENAME}",
        "--env",
        "PYTHONPATH=/kata_bundle",
        "--env",
        "REPORT_FILE=/kata_output/report.json",
        "--env",
        f"AGENT_ID={ids.agent_id}",
        "--env",
        f"JOB_RUN_ID={ids.job_run_id}",
        "--env",
        f"PROJECT_KEY={context.project_key}",
        "--env",
        f"INFERENCE_API={inference_api}",
        "--env",
        "INFERENCE_API_KEY",
        bitsec_project_image(context.project_key),
    ]


def bitsec_project_image(project_key: str) -> str:
    return f"ghcr.io/bitsec-ai/{project_key}:latest"


def build_bitsec_evaluation_command(context: Sn60ReplicaContext) -> list[str]:
    # repr() quotes the interpolated strings so a project key or path
    # containing quote characters cannot break or alter the script. The ids
    # and eval_max_vulns are validated ints, safe to interpolate directly.
    ids = sn60_synthetic_ids(context)
    script = (
        "import json; "
        "from validator.executor import AgentExecutor; "
        "from validator.models.platform import MockJobRun; "
        "from validator.platform_client import MockPlatformClient; "
        "executor = AgentExecutor("
        "job_run=MockJobRun("
        f"id={ids.job_run_id}, job_id={ids.job_id}, "
        f"validator_id={ids.validator_id}, agent_id={ids.agent_id}), "
        "agent_filepath='', "
        "project_key="
        + repr(str(context.project_key))
        + ", "
        "job_run_reports_dir="
        + repr(str(Path(context.reports_root).parent.resolve()))
        + ", "
        "platform_client=MockPlatformClient(), "
        "eval_max_vulns="
        + str(int(context.eval_max_vulns))
        + "); "
        "print(json.dumps(executor.eval_job_run(), default=str))"
    )
    return ["uv", "run", "python", "-c", script]


# Validator-owned scoring secrets that the miner execution path must never
# see. Docker's `--env` allowlist is the primary boundary; keeping these out
# of the docker-CLI process env means a single allowlist mistake cannot
# expose them.
VALIDATOR_ONLY_SECRET_ENV_VARS = (
    "CHUTES_API_KEY",
    "KATA_VALIDATOR_API_KEY",
)


def default_subprocess_env() -> dict[str, str]:
    return dict(os.environ)


def execution_subprocess_env() -> dict[str, str]:
    return {
        name: value
        for name, value in os.environ.items()
        if name not in VALIDATOR_ONLY_SECRET_ENV_VARS
    }


def required_env(name: str) -> str:
    value = os.environ.get(name)
    if value is None or not value.strip():
        raise ValueError(f"Required environment variable is not set: {name}")
    return value
