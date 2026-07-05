from __future__ import annotations

import ast
import json
import os
import re
import secrets
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Callable

from kata.agent_bundle import AGENT_ENTRY_FILENAME, load_bundle_files
from kata.ast_utils import (
    find_module_async_function_def,
    find_module_function_def,
    function_supports_no_arg_invocation,
)
from kata.evaluators.sn60_bitsec import (
    Sn60ReplicaContext,
    Sn60SandboxSource,
    build_default_execution_hook,
    hash_bundle_root,
    stage_bundle,
)
from kata.util import dedupe, write_json

SN60_SCREENING_SCHEMA_VERSION = 1
SN60_SCREENING_STATUS_PASSED = "passed"
SN60_SCREENING_STATUS_FAILED = "failed"
SN60_SCREENING_STAGE_STATIC = "static"
SN60_SCREENING_STAGE_EXECUTION = "execution"
SN60_SCREENING_MAX_FINDINGS = 100
SN60_SCREENING_MIN_DESCRIPTION_CHARS = 80
SN60_SCREENING_TIMEOUT_ENV = "KATA_SN60_SCREENING_EXECUTION_TIMEOUT_SECONDS"
DEFAULT_SN60_SCREENING_EXECUTION_TIMEOUT_SECONDS = 5 * 60
VALID_SCREENING_SEVERITIES = {"critical", "high"}
SOURCE_LOCATION_PATTERN = re.compile(
    r"\b[\w./-]+\.(?:sol|vy|rs|move|cairo|fe)\b",
    re.IGNORECASE,
)

BENCHMARK_LEAK_TOKENS = (
    "curated-highs-only",
    "known_solution",
    "known solution",
    "expected_findings",
    "expected findings",
    "expected_vulnerabilities",
    "expected vulnerabilities",
    "ground_truth",
    "ground truth",
    "answer_key",
    "answer key",
    "scabench",
    "hardsteer",
)

# Screener security checks: submitted agents must never reference validator
# scoring secrets or ship hardcoded provider keys.
VALIDATOR_SECRET_ENV_TOKENS = (
    "CHUTES_API_KEY",
    "KATA_VALIDATOR_API_KEY",
)
HARDCODED_SECRET_PATTERN = re.compile(
    r"(sk-[A-Za-z0-9]{10,}|ghp_[A-Za-z0-9]{10,}|hf_[A-Za-z0-9]{10,}|cpk_[A-Za-z0-9]{10,})"
)


@dataclass(frozen=True)
class Sn60ScreeningResult:
    schema_version: int
    run_id: str
    status: str
    stage: str
    artifact_path: str
    artifact_hash: str
    project_key: str
    report_path: str | None
    result_path: str
    reasons: list[str]
    details: dict[str, object]
    sandbox_source: Sn60SandboxSource
    created_at: str

    @property
    def passed(self) -> bool:
        return self.status == SN60_SCREENING_STATUS_PASSED


Sn60ScreeningHook = Callable[[Sn60ReplicaContext], dict[str, object]]


def run_sn60_screening(
    *,
    candidate_artifact_path: str,
    project_key: str,
    output_root: str,
    sandbox_source: Sn60SandboxSource,
    execution_hook: Sn60ScreeningHook | None = None,
    precomputed_reports: list[dict[str, object]] | None = None,
) -> Sn60ScreeningResult:
    """Static + execution screening for an SN60 candidate.

    When ``precomputed_reports`` is provided (the candidate's report.json from each
    duel project), the execution stage reuses those runs instead of executing the
    agent a second time — the candidate already ran on these projects in the duel.
    The agent passes execution screening if it produced a well-formed findings
    report on at least one sampled project, so a transient failure on any single
    project cannot fail the whole gate.
    """
    artifact_root = Path(candidate_artifact_path).expanduser().resolve()
    output_base = Path(output_root).expanduser().resolve()
    run_id = build_sn60_screening_id()
    run_root = output_base / run_id
    run_root.mkdir(parents=True, exist_ok=False)

    artifact_hash = hash_bundle_root(artifact_root)
    static_reasons = validate_sn60_static_screening(artifact_root)
    if static_reasons:
        result = build_screening_result(
            run_id=run_id,
            status=SN60_SCREENING_STATUS_FAILED,
            stage=SN60_SCREENING_STAGE_STATIC,
            artifact_root=artifact_root,
            artifact_hash=artifact_hash,
            project_key=project_key,
            report_path=None,
            result_path=run_root / "screening_result.json",
            reasons=static_reasons,
            details={"static_checks": "failed"},
            sandbox_source=sandbox_source,
        )
        write_screening_result(Path(result.result_path), result)
        return result

    if precomputed_reports is not None:
        if precomputed_reports:
            per_report_reasons = [
                validate_sn60_screening_report(report) for report in precomputed_reports
            ]
        else:
            per_report_reasons = [
                ["SN60 screening: candidate produced no evaluated reports."]
            ]
        passed = any(not reasons for reasons in per_report_reasons)
        execution_reasons = [] if passed else per_report_reasons[0]
        result = build_screening_result(
            run_id=run_id,
            status=(
                SN60_SCREENING_STATUS_PASSED
                if passed
                else SN60_SCREENING_STATUS_FAILED
            ),
            stage=SN60_SCREENING_STAGE_EXECUTION,
            artifact_root=artifact_root,
            artifact_hash=artifact_hash,
            project_key=project_key,
            report_path=None,
            result_path=run_root / "screening_result.json",
            reasons=execution_reasons,
            details={
                "execution_report_success": passed,
                "reused_duel_reports": len(precomputed_reports),
            },
            sandbox_source=sandbox_source,
        )
        write_screening_result(Path(result.result_path), result)
        return result

    bundle_root = run_root / "bundle"
    reports_root = run_root / "reports" / project_key
    reports_root.mkdir(parents=True, exist_ok=True)
    stage_bundle(artifact_root, bundle_root)
    context = Sn60ReplicaContext(
        run_id=run_id,
        variant_name="screening",
        project_key=project_key,
        replica_index=1,
        bundle_root=str(bundle_root),
        reports_root=str(reports_root),
        report_path=str(reports_root / "report.json"),
        evaluation_path=str(reports_root / "evaluation.json"),
        sandbox_source=sandbox_source,
    )
    timeout_seconds = resolve_sn60_screening_execution_timeout_seconds()
    execute = execution_hook or build_default_screening_execution_hook(sandbox_source)
    try:
        report_payload = execute(context)
    except Exception as exc:
        report_payload = {
            "success": False,
            "error": f"SN60 screening execution failed before report creation: {exc}",
        }
    write_json(Path(context.report_path), report_payload)
    execution_reasons = validate_sn60_screening_report(report_payload)
    result = build_screening_result(
        run_id=run_id,
        status=(
            SN60_SCREENING_STATUS_FAILED
            if execution_reasons
            else SN60_SCREENING_STATUS_PASSED
        ),
        stage=SN60_SCREENING_STAGE_EXECUTION,
        artifact_root=artifact_root,
        artifact_hash=artifact_hash,
        project_key=project_key,
        report_path=Path(context.report_path),
        result_path=run_root / "screening_result.json",
        reasons=execution_reasons,
        details={
            "execution_report_success": bool(report_payload.get("success")),
            "execution_timeout_seconds": timeout_seconds,
        },
        sandbox_source=sandbox_source,
    )
    write_screening_result(Path(result.result_path), result)
    return result


def build_default_screening_execution_hook(source: Sn60SandboxSource) -> Sn60ScreeningHook:
    return build_default_execution_hook(
        source,
        timeout_env_name=SN60_SCREENING_TIMEOUT_ENV,
        timeout_default=DEFAULT_SN60_SCREENING_EXECUTION_TIMEOUT_SECONDS,
    )


def resolve_sn60_screening_execution_timeout_seconds() -> float:
    value = os.environ.get(SN60_SCREENING_TIMEOUT_ENV)
    if value and value.strip():
        try:
            parsed = float(value.strip())
        except ValueError:
            return DEFAULT_SN60_SCREENING_EXECUTION_TIMEOUT_SECONDS
        if parsed > 0:
            return parsed
    return DEFAULT_SN60_SCREENING_EXECUTION_TIMEOUT_SECONDS


def validate_sn60_static_screening(candidate_root: str | Path) -> list[str]:
    root = Path(candidate_root).expanduser().resolve()
    reasons: list[str] = []
    bundle_files = load_bundle_files(root)
    helper_paths = [
        relative_path
        for relative_path in sorted(bundle_files)
        if Path(relative_path).parts and Path(relative_path).parts[0] == "helpers"
    ]
    if helper_paths:
        reasons.append(
            "SN60 miner submissions do not support helper files in V1: "
            + ", ".join(helper_paths)
        )

    for relative_path, content in sorted(bundle_files.items()):
        if not relative_path.endswith(".py"):
            continue
        for token in VALIDATOR_SECRET_ENV_TOKENS:
            if token in content:
                reasons.append(
                    "SN60 screening rejected a validator secret reference: "
                    f"{relative_path} references `{token}`."
                )
        if HARDCODED_SECRET_PATTERN.search(content):
            reasons.append(
                f"SN60 screening rejected a hardcoded secret token in {relative_path}."
            )

    agent_source = bundle_files.get(AGENT_ENTRY_FILENAME)
    if agent_source is None:
        reasons.append("Submission agent must define agent_main(...).")
        return reasons

    try:
        tree = ast.parse(agent_source, filename=AGENT_ENTRY_FILENAME)
    except SyntaxError as exc:
        line_number = exc.lineno or 1
        reasons.append(
            f"Submission bundle contains invalid Python syntax in agent.py:{line_number}."
        )
        return reasons

    agent_main = find_module_function_def(tree, "agent_main")
    if agent_main is None:
        if find_module_async_function_def(tree, "agent_main") is not None:
            reasons.append(
                "Submission agent_main must be a synchronous function; the SN60 "
                "sandbox runner calls agent_main() directly and does not await "
                "coroutines."
            )
        else:
            reasons.append("Submission agent must define agent_main(...).")
    elif not function_supports_no_arg_invocation(agent_main):
        reasons.append("Submission agent must support no-argument invocation: agent_main().")
    elif agent_main_returns_direct_empty_report(agent_main):
        reasons.append(
            "SN60 screening rejected a no-op agent: agent_main returns an empty "
            "`vulnerabilities` list without doing any analysis."
        )

    lowered_source = agent_source.lower()
    for token in BENCHMARK_LEAK_TOKENS:
        if token in lowered_source:
            reasons.append(
                "SN60 screening rejected benchmark-answer leakage token: "
                f"`{token}`."
            )
    return dedupe(reasons)


def validate_sn60_screening_report(report_payload: dict[str, object]) -> list[str]:
    reasons: list[str] = []
    if not report_payload.get("success"):
        reasons.append(
            "SN60 screening execution did not complete successfully: "
            + str(report_payload.get("error", "unknown error"))
        )
    report = report_payload.get("report")
    if not isinstance(report, dict):
        reasons.append("SN60 screening report must be a JSON object.")
        return dedupe(reasons)
    vulnerabilities = report.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        reasons.append("SN60 screening report must contain a top-level `vulnerabilities` list.")
        return dedupe(reasons)
    if not vulnerabilities:
        reasons.append(
            "SN60 screening report must include at least one candidate vulnerability. "
            "Empty reports are treated as no-op submissions."
        )
        return dedupe(reasons)
    if len(vulnerabilities) > SN60_SCREENING_MAX_FINDINGS:
        reasons.append(
            "SN60 screening report includes too many findings "
            f"({len(vulnerabilities)}; limit is {SN60_SCREENING_MAX_FINDINGS})."
        )
    for index, finding in enumerate(vulnerabilities, start=1):
        if not isinstance(finding, dict):
            reasons.append(f"SN60 screening finding #{index} must be a JSON object.")
            continue
        title = str(finding.get("title") or "").strip()
        description = str(finding.get("description") or "").strip()
        if not title:
            reasons.append(f"SN60 screening finding #{index} must include a non-empty title.")
        if len(description) < SN60_SCREENING_MIN_DESCRIPTION_CHARS:
            reasons.append(
                f"SN60 screening finding #{index} must include a useful description "
                f"(at least {SN60_SCREENING_MIN_DESCRIPTION_CHARS} characters)."
            )
        severity = str(finding.get("severity") or "").strip().lower()
        if not severity:
            reasons.append(
                f"SN60 screening finding #{index} must include severity `high` or `critical`."
            )
        elif severity not in VALID_SCREENING_SEVERITIES:
            reasons.append(
                f"SN60 screening finding #{index} has unsupported severity `{severity}`."
            )
        if not has_source_location_hint(finding):
            reasons.append(
                f"SN60 screening finding #{index} must include a source location hint "
                "such as `Vault.sol`, `program.rs`, or a non-empty `file` field."
            )
    return dedupe(reasons)


def has_source_location_hint(finding: dict[str, object]) -> bool:
    explicit_location = str(
        finding.get("file") or finding.get("path") or finding.get("location") or ""
    ).strip()
    if explicit_location:
        return True
    searchable = " ".join(
        str(finding.get(key) or "")
        for key in ("title", "description", "function", "contract")
    )
    return bool(SOURCE_LOCATION_PATTERN.search(searchable))


def agent_main_returns_direct_empty_report(agent_main: ast.FunctionDef) -> bool:
    """Catch the common scaffold/no-op pattern without rejecting real analysis code."""
    for return_node in iter_direct_function_returns(agent_main):
        value = return_node.value
        if not isinstance(value, ast.Dict):
            continue
        for key, item in zip(value.keys, value.values, strict=False):
            if not (isinstance(key, ast.Constant) and key.value == "vulnerabilities"):
                continue
            if isinstance(item, ast.List) and not item.elts:
                return True
    return False


def iter_direct_function_returns(function_node: ast.FunctionDef):
    stack: list[ast.AST] = list(reversed(function_node.body))
    while stack:
        node = stack.pop()
        if isinstance(node, ast.Return):
            yield node
            continue
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        stack.extend(reversed(list(ast.iter_child_nodes(node))))


def build_screening_result(
    *,
    run_id: str,
    status: str,
    stage: str,
    artifact_root: Path,
    artifact_hash: str,
    project_key: str,
    report_path: Path | None,
    result_path: Path,
    reasons: list[str],
    details: dict[str, object],
    sandbox_source: Sn60SandboxSource,
) -> Sn60ScreeningResult:
    return Sn60ScreeningResult(
        schema_version=SN60_SCREENING_SCHEMA_VERSION,
        run_id=run_id,
        status=status,
        stage=stage,
        artifact_path=str(artifact_root),
        artifact_hash=artifact_hash,
        project_key=project_key,
        report_path=str(report_path) if report_path is not None else None,
        result_path=str(result_path),
        reasons=reasons,
        details=details,
        sandbox_source=sandbox_source,
        created_at=datetime.now(UTC).isoformat(),
    )


def write_screening_result(path: Path, result: Sn60ScreeningResult) -> Path:
    write_json(path, asdict(result))
    return path




def screening_result_payload(result: Sn60ScreeningResult) -> dict[str, object]:
    return asdict(result)


def sn60_screening_freshness_fingerprint(
    *,
    king_artifact_hash: str,
    screening_result: Sn60ScreeningResult,
) -> str:
    payload = {
        "king_artifact_hash": king_artifact_hash,
        "candidate_artifact_hash": screening_result.artifact_hash,
        "project_key": screening_result.project_key,
        "screening_status": screening_result.status,
        "screening_stage": screening_result.stage,
        "sandbox_commit": screening_result.sandbox_source.sandbox_commit,
        "benchmark_sha256": screening_result.sandbox_source.benchmark_sha256,
        "scorer_version": screening_result.sandbox_source.scorer_version,
    }
    return sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


def build_sn60_screening_id() -> str:
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return f"sn60-screening-{timestamp}-{secrets.token_hex(3)}"
