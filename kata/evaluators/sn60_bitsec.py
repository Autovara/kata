from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from statistics import fmean
from typing import Callable, NamedTuple, TypedDict

from kata.agent_bundle import AGENT_ENTRY_FILENAME, load_bundle_files, write_bundle_files
from kata.evaluators.king_cache import (
    KingScoreboard,
    benchmark_version_key,
    load_king_scoreboard,
    save_king_scoreboard,
)
from kata.provenance import sha256_directory
from kata.util import write_json

SN60_BITSEC_EVALUATOR_ID = "sn60_bitsec"
DEFAULT_SN60_DUEL_SCHEMA_VERSION = 2
DEFAULT_SANDBOX_PROXY_NETWORK = "bitsec-net"
DEFAULT_SANDBOX_PROXY_URL = "http://localhost:8087"
DEFAULT_SANDBOX_INFERENCE_API = "http://bitsec_proxy:8000"
DEFAULT_EVAL_MAX_VULNS = 100
DEFAULT_REPLICAS_PER_PROJECT = 1
DEFAULT_BENCHMARK_FILENAME = "curated-highs-only-2025-08-08.json"
DEFAULT_EXECUTION_SUBPROCESS_TIMEOUT_SECONDS = 35 * 60
DEFAULT_EVALUATION_SUBPROCESS_TIMEOUT_SECONDS = 60 * 60


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
    precision: float
    f1_score: float


class Sn60EvaluationMetrics(TypedDict):
    evaluation_status: str
    score: float
    detection_rate: float
    result: str | None
    true_positives: int
    total_expected: int
    total_found: int
    precision: float
    f1_score: float


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
    precision: float
    f1_score: float


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
    precision: float
    f1_score: float
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


def _env_positive_float(name: str, default: float) -> float:
    value = os.environ.get(name)
    if value and value.strip():
        try:
            parsed = float(value.strip())
        except ValueError:
            return default
        if parsed > 0:
            return parsed
    return default


def sn60_codebase_pass_count(replica_results: list[Sn60ReplicaResult]) -> int:
    """Number of distinct projects that pass the configured replica threshold."""
    passes = 0
    for project_key in {result.project_key for result in replica_results}:
        project_replicas = [r for r in replica_results if r.project_key == project_key]
        pass_count = sum(1 for r in project_replicas if r.result == "PASS")
        if project_passes(pass_count=pass_count, replica_count=len(project_replicas)):
            passes += 1
    return passes


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
    king_scoreboard_path: str | None = None,
    progress_callback: Callable[[Sn60ReplicaContext], None] | None = None,
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
    validate_sn60_project_keys(project_keys, sandbox_source=source)
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

    resolved_execution_hook = execution_hook or build_default_execution_hook(source)
    resolved_evaluation_hook = evaluation_hook or build_default_evaluation_hook(source)
    king_hash = hash_bundle_root(king_root)
    candidate_hash = hash_bundle_root(candidate_root)

    # The king's score is stable for a fixed king + benchmark, so route it through
    # the per-project cache when a scoreboard is configured: an uncached project
    # runs the king once and stores it; a cached project reuses it without paying
    # for inference. The candidate always runs fresh.
    king_execution_hook = resolved_execution_hook
    king_evaluation_hook = resolved_evaluation_hook
    if king_scoreboard_path:
        king_execution_hook, king_evaluation_hook = build_cached_king_hooks(
            scoreboard_path=king_scoreboard_path,
            king_hash=king_hash,
            benchmark_version=benchmark_version_key(source.scorer_version, source.benchmark_sha256),
            base_execution_hook=resolved_execution_hook,
            base_evaluation_hook=resolved_evaluation_hook,
        )

    candidate_results = score_variant_on_projects(
        run_id=run_id,
        run_root=run_root,
        variant_name="candidate",
        artifact_root=candidate_root,
        project_keys=project_keys,
        replicas_per_project=replicas_per_project,
        sandbox_source=source,
        execution_hook=resolved_execution_hook,
        evaluation_hook=resolved_evaluation_hook,
        eval_max_vulns=eval_max_vulns,
        progress_callback=progress_callback,
    )
    king_results = score_variant_on_projects(
        run_id=run_id,
        run_root=run_root,
        variant_name="king",
        artifact_root=king_root,
        project_keys=project_keys,
        replicas_per_project=replicas_per_project,
        sandbox_source=source,
        execution_hook=king_execution_hook,
        evaluation_hook=king_evaluation_hook,
        eval_max_vulns=eval_max_vulns,
        progress_callback=progress_callback,
    )
    ordered_executed_keys = list(project_keys)

    king_summary = summarize_variant(
        variant_name="king",
        artifact_root=king_root,
        artifact_hash=king_hash,
        replica_results=king_results,
    )
    candidate_summary = summarize_variant(
        variant_name="candidate",
        artifact_root=candidate_root,
        artifact_hash=candidate_hash,
        replica_results=candidate_results,
    )

    summary = Sn60DuelSummary(
        schema_version=DEFAULT_SN60_DUEL_SCHEMA_VERSION,
        run_id=run_id,
        created_at=datetime.now(UTC).isoformat(),
        output_root=str(run_root),
        project_keys=ordered_executed_keys,
        replicas_per_project=replicas_per_project,
        sandbox_source=source,
        king=king_summary,
        candidate=candidate_summary,
    )
    write_sn60_duel_summary(run_root / "duel_summary.json", summary)
    return summary


def score_variant_on_projects(
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
    progress_callback: Callable[[Sn60ReplicaContext], None] | None = None,
) -> list[Sn60ReplicaResult]:
    """Run every replica for one variant over the given projects.

    Returns the flat replica results (unsummarized) so callers can score king and
    candidate independently and summarize each set once. ``progress_callback`` is
    invoked after each replica finishes so callers can publish live progress.
    """
    variant_root = run_root / variant_name
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
            replica_result = build_replica_result(context, report_payload, evaluation_payload)
            replica_results.append(replica_result)
            if progress_callback is not None:
                progress_callback(context)

    return replica_results


def build_cached_king_hooks(
    *,
    scoreboard_path: str | Path,
    king_hash: str,
    benchmark_version: str,
    base_execution_hook: Sn60ExecutionHook,
    base_evaluation_hook: Sn60EvaluationHook,
) -> tuple[Sn60ExecutionHook, Sn60EvaluationHook]:
    """Wrap the king's hooks so cached projects skip inference entirely.

    On a cache hit both hooks return the stored payloads (no Docker exec, no
    scorer call); the surrounding scoring path still materializes identical
    ``report.json`` / ``evaluation.json`` artifacts in the run. On a miss the
    base hooks run and the payloads are recorded for future rounds.
    """
    board: KingScoreboard = load_king_scoreboard(
        scoreboard_path,
        king_hash=king_hash,
        benchmark_version=benchmark_version,
    )

    def execution_hook(context: Sn60ReplicaContext) -> dict[str, object]:
        cached = board.cached_run(context.project_key, context.replica_index)
        if cached is not None:
            return dict(cached["report"])  # type: ignore[arg-type]
        return base_execution_hook(context)

    def evaluation_hook(
        context: Sn60ReplicaContext,
        report_payload: dict[str, object],
    ) -> dict[str, object]:
        cached = board.cached_run(context.project_key, context.replica_index)
        if cached is not None:
            return dict(cached["evaluation"])  # type: ignore[arg-type]
        evaluation_payload = base_evaluation_hook(context, report_payload)
        board.record_run(
            context.project_key,
            context.replica_index,
            report_payload,
            evaluation_payload,
        )
        save_king_scoreboard(scoreboard_path, board)
        return evaluation_payload

    return execution_hook, evaluation_hook


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


def load_sn60_benchmark_project_keys(sandbox_source: Sn60SandboxSource) -> list[str]:
    payload = json.loads(Path(sandbox_source.benchmark_file).read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("SN60 benchmark snapshot must be a JSON list.")
    project_keys: list[str] = []
    for index, entry in enumerate(payload):
        if not isinstance(entry, dict):
            raise ValueError(f"SN60 benchmark entry {index} must be a JSON object.")
        project_id = entry.get("project_id")
        if isinstance(project_id, str) and project_id.strip():
            project_keys.append(project_id.strip())
    if not project_keys:
        raise ValueError("SN60 benchmark snapshot does not contain any project_id entries.")
    return sorted(dict.fromkeys(project_keys))


def sn60_benchmark_expected_count(
    sandbox_source: Sn60SandboxSource,
    project_key: str,
) -> int:
    payload = json.loads(Path(sandbox_source.benchmark_file).read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("SN60 benchmark snapshot must be a JSON list.")
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        if entry.get("project_id") == project_key or entry.get("id") == project_key:
            vulnerabilities = entry.get("vulnerabilities")
            return len(vulnerabilities) if isinstance(vulnerabilities, list) else 0
    return 0


def validate_sn60_project_keys(
    project_keys: list[str],
    *,
    sandbox_source: Sn60SandboxSource,
) -> None:
    benchmark_project_keys = set(load_sn60_benchmark_project_keys(sandbox_source))
    missing = [key for key in project_keys if key not in benchmark_project_keys]
    if missing:
        raise ValueError(
            "SN60 project keys are not present in the resolved benchmark snapshot: "
            + ", ".join(missing)
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
    true_positives = sum(result.true_positives for result in replica_results)
    total_expected = sum(result.total_expected for result in replica_results)
    total_found = sum(result.total_found for result in replica_results)
    precision = true_positives / total_found if total_found else 0.0
    aggregated_score = true_positives / total_expected if total_expected else 0.0
    f1_score = (
        2 * precision * aggregated_score / (precision + aggregated_score)
        if precision + aggregated_score > 0
        else 0.0
    )
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
        # SN60 score signal: total expected vulnerabilities found across the
        # sampled projects. Project PASS remains a display metric only.
        aggregated_score=aggregated_score,
        average_detection_rate=fmean(detection_rates) if detection_rates else 0.0,
        true_positives=true_positives,
        total_expected=total_expected,
        total_found=total_found,
        precision=precision,
        f1_score=f1_score,
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
    true_positives = sum(result.true_positives for result in replica_results)
    total_expected = sum(result.total_expected for result in replica_results)
    total_found = sum(result.total_found for result in replica_results)
    detection_rate = true_positives / total_expected if total_expected else 0.0
    precision = true_positives / total_found if total_found else 0.0
    f1_score = (
        2 * precision * detection_rate / (precision + detection_rate)
        if precision + detection_rate > 0
        else 0.0
    )
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
        true_positives=true_positives,
        total_expected=total_expected,
        total_found=total_found,
        precision=precision,
        f1_score=f1_score,
    )


def project_passes(*, pass_count: int, replica_count: int) -> bool:
    """Codebase-level binary PASS using the configured replica count.

    The default production setting is one replica, so 1/1 passes. If operators
    raise replicas, this preserves the historical two-thirds majority threshold.
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
    total_expected = metrics["total_expected"]
    if metrics["evaluation_status"] != "success" and total_expected == 0:
        total_expected = sn60_benchmark_expected_count(
            context.sandbox_source,
            context.project_key,
        )
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
        total_expected=total_expected,
        total_found=metrics["total_found"],
        precision=metrics["precision"],
        f1_score=metrics["f1_score"],
    )


def extract_evaluation_metrics(evaluation_payload: dict[str, object]) -> Sn60EvaluationMetrics:
    # The SN60 sandbox serializes its Status enum via json.dumps(default=str),
    # yielding "Status.SUCCESS"; older builds emitted the bare value "success".
    # Normalize to the segment after the last "." so both forms compare equal
    # (otherwise a genuinely successful run is miscounted as an invalid run).
    raw_status = str(evaluation_payload.get("status", "error")).lower()
    status_value = raw_status.rsplit(".", 1)[-1]
    result_payload = evaluation_payload.get("result")
    if not isinstance(result_payload, dict):
        result_payload = {}
    is_success = status_value == "success"
    detection_rate = safe_float(result_payload.get("detection_rate"), 0.0)
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
            safe_int(result_payload.get("true_positives"), 0) if is_success else 0
        ),
        "total_expected": (
            safe_int(result_payload.get("total_expected"), 0) if is_success else 0
        ),
        "total_found": (
            safe_int(result_payload.get("total_found"), 0) if is_success else 0
        ),
        "precision": safe_float(result_payload.get("precision"), 0.0) if is_success else 0.0,
        "f1_score": safe_float(result_payload.get("f1_score"), 0.0) if is_success else 0.0,
    }


def safe_float(value: object, default: float) -> float:
    try:
        return float(value if value is not None else default)
    except (TypeError, ValueError):
        return default


def safe_int(value: object, default: int) -> int:
    try:
        return int(value if value is not None else default)
    except (TypeError, ValueError):
        return default


def resolve_sn60_inference_api() -> str:
    """Endpoint the sandboxed agent calls for inference.

    Defaults to the local Bitsec proxy; a secret-proxy deployment overrides it
    via KATA_SN60_INFERENCE_API so the agent is routed through a scoped proxy
    instead. The default keeps existing local runs unchanged.
    """
    value = os.environ.get("KATA_SN60_INFERENCE_API")
    if value and value.strip():
        return value.strip()
    return DEFAULT_SANDBOX_INFERENCE_API


def resolve_sn60_proxy_network() -> str:
    value = os.environ.get("KATA_SN60_PROXY_NETWORK")
    if value and value.strip():
        return value.strip()
    return DEFAULT_SANDBOX_PROXY_NETWORK


def docker_network_internal_state(
    network_name: str,
    *,
    run: Callable[..., subprocess.CompletedProcess] | None = None,
) -> bool | None:
    """Return the network's `Internal` flag, or None if it does not exist."""
    run = run or subprocess.run
    completed = run(
        ["docker", "network", "inspect", network_name, "--format", "{{.Internal}}"],
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        stderr = (completed.stderr or "").lower()
        if "not found" in stderr or "no such network" in stderr:
            return None
        raise RuntimeError(
            f"Failed to inspect docker network '{network_name}': "
            f"{completed.stderr.strip() or completed.stdout.strip()}"
        )
    return completed.stdout.strip().lower() == "true"


def ensure_internal_agent_network(
    network_name: str,
    *,
    run: Callable[..., subprocess.CompletedProcess] | None = None,
) -> None:
    """Guarantee the SN60 agent network exists and blocks external egress.

    Untrusted miner code runs on this network, so it must be `--internal`:
    agents can reach the proxy but not the public internet, which is what keeps
    injected credentials from being exfiltrated. Create the network if it is
    absent; refuse to run if it exists but permits egress rather than silently
    running untrusted code with internet access.
    """
    run = run or subprocess.run
    state = docker_network_internal_state(network_name, run=run)
    if state is None:
        created = run(
            ["docker", "network", "create", "--internal", network_name],
            capture_output=True,
            text=True,
        )
        if created.returncode != 0:
            raise RuntimeError(
                f"Failed to create internal docker network '{network_name}': "
                f"{created.stderr.strip() or created.stdout.strip()}"
            )
        return
    if state is False:
        raise ValueError(
            f"Refusing to run untrusted SN60 agents on docker network "
            f"'{network_name}': it permits external egress. Recreate it with "
            f"`docker network create --internal {network_name}` or set "
            "KATA_SN60_PROXY_NETWORK to an internal network."
        )


def build_default_execution_hook(
    source: Sn60SandboxSource,
    *,
    timeout_env_name: str = "KATA_SN60_EXECUTION_TIMEOUT_SECONDS",
    timeout_default: float = DEFAULT_EXECUTION_SUBPROCESS_TIMEOUT_SECONDS,
) -> Sn60ExecutionHook:
    def _execute(context: Sn60ReplicaContext) -> dict[str, object]:
        proxy_network = resolve_sn60_proxy_network()
        inference_api = resolve_sn60_inference_api()
        # Untrusted miner code runs in this container; guarantee it can only
        # reach the proxy (never the public internet) before starting it.
        ensure_internal_agent_network(proxy_network)
        command = build_bitsec_execution_command(
            context,
            proxy_network=proxy_network,
            inference_api=inference_api,
        )
        env = {
            "INFERENCE_API_KEY": required_env("INFERENCE_API_KEY"),
        }
        try:
            timeout_seconds = _env_positive_float(timeout_env_name, timeout_default)
            completed = subprocess.run(
                command,
                cwd=source.sandbox_root,
                capture_output=True,
                text=True,
                env={**execution_subprocess_env(), **env},
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            try:
                cleanup = force_remove_sn60_container(context)
                cleanup_suffix = (
                    ""
                    if cleanup.returncode == 0
                    else f" Cleanup failed: {cleanup.stderr.strip() or cleanup.stdout.strip()}"
                )
            except Exception as cleanup_exc:
                cleanup_suffix = f" Cleanup failed: {cleanup_exc}"
            return {
                "success": False,
                "error": (
                    f"Bitsec execution command timed out after {exc.timeout} seconds."
                    f"{cleanup_suffix}"
                ),
            }
        report_path = Path(context.report_path)
        if report_path.exists():
            # report.json is written inside the agent container, which mounts
            # the reports dir read-write — its contents are untrusted. A
            # malformed/non-object report is an agent fault (recorded as a
            # failed replica), never a reason to crash the whole duel.
            return _read_untrusted_report_json(
                report_path,
                failure={
                    "success": False,
                    "error": "SN60 execution report is not a valid JSON object.",
                },
            )
        if completed.returncode != 0:
            return {
                "success": False,
                "error": (
                    f"Bitsec execution command failed with exit code {completed.returncode}: "
                    f"{completed.stderr.strip() or completed.stdout.strip()}"
                ),
            }
        return {
            "success": False,
            "error": "Bitsec execution command completed without writing report.json.",
        }

    return _execute


def _read_untrusted_report_json(
    path: Path, *, failure: dict[str, object]
) -> dict[str, object]:
    """Read an agent-writable JSON report, returning `failure` (with the parse
    error appended) instead of raising on malformed or non-object content."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, UnicodeDecodeError) as exc:
        return {**failure, "error": f"{failure['error']} ({exc})"}
    if not isinstance(payload, dict):
        return failure
    return payload


def extract_sn60_evaluation_payload(stdout: str) -> dict[str, object] | None:
    """Pull the scorer's result JSON out of its (noisy) stdout.

    The pinned Bitsec scorer prints verbose progress -- Rich tables, per-finding
    match logs -- to stdout before the final ``json.dumps`` result, so the whole
    stream is not valid JSON. Parse the last stdout line that is a JSON object
    carrying a ``status`` field (the result), tolerating any preceding noise.
    """
    stripped = stdout.strip()
    if not stripped:
        return None
    try:
        payload = json.loads(stripped)
        if isinstance(payload, dict) and "status" in payload:
            return payload
    except json.JSONDecodeError:
        pass
    for line in reversed(stripped.splitlines()):
        candidate = line.strip()
        if not (candidate.startswith("{") and candidate.endswith("}")):
            continue
        try:
            payload = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict) and "status" in payload:
            return payload
    return None


def report_finding_count(report_payload: dict[str, object]) -> int:
    """Number of vulnerabilities in an agent report (`{report: {vulnerabilities}}`)."""
    report = report_payload.get("report")
    if isinstance(report, dict):
        vulnerabilities = report.get("vulnerabilities")
        return len(vulnerabilities) if isinstance(vulnerabilities, list) else 0
    return 0


def build_default_evaluation_hook(source: Sn60SandboxSource) -> Sn60EvaluationHook:
    def _evaluate(
        context: Sn60ReplicaContext,
        report_payload: dict[str, object],
    ) -> dict[str, object]:
        if not Path(context.report_path).exists():
            write_json(Path(context.report_path), report_payload)
        # Cost/latency saver: a successful report with zero findings has zero true
        # positives by definition, so there is nothing for the LLM judge to score.
        # Skip the scorer call entirely and synthesize the deterministic empty
        # result -- but keep the benchmark's expected count so a missed project
        # still counts against the detection score (no accuracy change).
        if bool(report_payload.get("success")) and report_finding_count(report_payload) == 0:
            return {
                "status": "success",
                "result": {
                    "project": context.project_key,
                    "detection_rate": 0.0,
                    "true_positives": 0,
                    "total_expected": sn60_benchmark_expected_count(source, context.project_key),
                    "total_found": 0,
                    "precision": 0.0,
                    "f1_score": 0.0,
                    "result": "no findings reported; LLM scoring skipped",
                },
            }
        try:
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
                timeout=_env_positive_float(
                    "KATA_SN60_EVALUATION_TIMEOUT_SECONDS",
                    DEFAULT_EVALUATION_SUBPROCESS_TIMEOUT_SECONDS,
                ),
            )
        except subprocess.TimeoutExpired as exc:
            return {
                "status": "error",
                "error": f"Bitsec evaluation command timed out after {exc.timeout} seconds.",
                "result": {},
            }
        if completed.returncode == 0:
            payload = extract_sn60_evaluation_payload(completed.stdout)
            if payload is None:
                return {
                    "status": "error",
                    "error": "SN60 evaluation stdout did not contain a result JSON object.",
                    "result": {},
                }
            return payload
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
        "--name",
        sn60_container_name(context),
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


def sn60_container_name(context: Sn60ReplicaContext) -> str:
    digest = hashlib.sha256(
        "|".join(
            [
                context.run_id,
                context.variant_name,
                context.project_key,
                str(context.replica_index),
            ]
        ).encode("utf-8")
    ).hexdigest()[:12]
    project = re.sub(r"[^a-z0-9_.-]+", "-", context.project_key.lower()).strip(".-")
    project = project[:42] or "project"
    variant = re.sub(r"[^a-z0-9_.-]+", "-", context.variant_name.lower()).strip(".-")
    variant = variant[:16] or "variant"
    return f"kata-sn60-{variant}-{project}-r{context.replica_index}-{digest}"


def force_remove_sn60_container(context: Sn60ReplicaContext) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "rm", "-f", sn60_container_name(context)],
        capture_output=True,
        text=True,
    )


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
    "KATA_SN60_PROJECT_SAMPLE_SECRET",
    "KATA_VALIDATOR_API_KEY",
)


def default_subprocess_env() -> dict[str, str]:
    return {
        name: value
        for name, value in os.environ.items()
        if name != "KATA_SN60_PROJECT_SAMPLE_SECRET"
    }


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
