from __future__ import annotations

import fnmatch
import subprocess
from dataclasses import dataclass
from pathlib import Path

TASK_WEIGHT_FILENAME = "task_weight.txt"


@dataclass(frozen=True)
class PathPolicyResult:
    passed: bool
    allowed_rules: list[str]
    forbidden_rules: list[str]
    violating_paths: list[str]


@dataclass(frozen=True)
class VariantBenchmarkScore:
    agent_ok: bool
    checks_passed: bool
    task_solved: bool
    validity_passed: bool
    verifier_score: float
    quality_score: float
    task_weight: float
    weighted_task_score: float
    score_source: str
    changed_paths: list[str]
    path_policy_passed: bool
    path_policy_violations: list[str]


def score_variant_run(
    *,
    repo_snapshot: Path,
    eval_pack_root: Path,
    workspace: Path,
    agent_exit_code: int,
    checks_exit_code: int,
    score_file: Path,
) -> VariantBenchmarkScore:
    changed_paths = diff_paths(repo_snapshot, workspace)
    path_policy = evaluate_path_policy(
        changed_paths,
        allowed_rules=read_path_rules(eval_pack_root / "allowed_paths.txt"),
        forbidden_rules=read_path_rules(eval_pack_root / "forbidden_paths.txt"),
    )
    agent_ok = agent_exit_code == 0
    checks_passed = checks_exit_code == 0
    verifier_score, score_source = resolve_verifier_score(score_file, checks_passed=checks_passed)
    validity_passed = agent_ok and path_policy.passed
    quality_score = verifier_score if validity_passed else 0.0
    task_weight = read_task_weight(eval_pack_root)
    return VariantBenchmarkScore(
        agent_ok=agent_ok,
        checks_passed=checks_passed,
        task_solved=checks_passed,
        validity_passed=validity_passed,
        verifier_score=verifier_score,
        quality_score=quality_score,
        task_weight=task_weight,
        weighted_task_score=quality_score * task_weight,
        score_source=score_source,
        changed_paths=changed_paths,
        path_policy_passed=path_policy.passed,
        path_policy_violations=path_policy.violating_paths,
    )


def resolve_verifier_score(score_file: Path, *, checks_passed: bool) -> tuple[float, str]:
    if not score_file.exists():
        return (1.0 if checks_passed else 0.0), "checks-exit-code"
    raw = score_file.read_text(encoding="utf-8").strip()
    if not raw:
        return (1.0 if checks_passed else 0.0), "checks-exit-code"
    try:
        value = float(raw)
    except ValueError as exc:
        raise ValueError(
            f"Invalid Kata score file at {score_file}: expected a float in [0, 1]."
        ) from exc
    if not 0.0 <= value <= 1.0:
        raise ValueError(
            f"Invalid Kata score file at {score_file}: score must be in [0, 1], got {value}."
        )
    return value, "score-file"


def read_task_weight(eval_pack_root: Path) -> float:
    weight_path = eval_pack_root / TASK_WEIGHT_FILENAME
    if not weight_path.exists():
        return 1.0
    raw = weight_path.read_text(encoding="utf-8").strip()
    if not raw:
        return 1.0
    try:
        value = float(raw)
    except ValueError as exc:
        raise ValueError(
            f"Invalid task weight in {weight_path}: expected a positive float."
        ) from exc
    if value <= 0:
        raise ValueError(f"Invalid task weight in {weight_path}: expected > 0, got {value}.")
    return value


def diff_paths(source: Path, target: Path) -> list[str]:
    completed = subprocess.run(
        ["git", "diff", "--no-index", "--name-status", str(source), str(target)],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode not in {0, 1}:
        raise RuntimeError(completed.stderr.strip() or "Unable to diff eval workspaces.")

    source_prefixes = path_prefixes(source)
    target_prefixes = path_prefixes(target)
    paths: list[str] = []
    for line in completed.stdout.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        status, _, raw_path = stripped.partition("\t")
        if not raw_path:
            continue
        prefixes = source_prefixes if status.startswith(("D", "M", "R", "C")) else target_prefixes
        normalized = normalize_diff_path(raw_path, prefixes)
        paths.append(normalized)
    return sorted(set(paths))


def path_prefixes(root: Path) -> list[str]:
    return [
        root.as_posix().rstrip("/") + "/",
        root.resolve().as_posix().rstrip("/") + "/",
    ]


def normalize_diff_path(path: str, prefixes: list[str]) -> str:
    normalized = path.replace("\\", "/")
    for prefix in prefixes:
        if normalized.startswith(prefix):
            return normalized.removeprefix(prefix)
    return normalized


def read_path_rules(path: Path) -> list[str]:
    rules: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        rules.append(stripped.replace("\\", "/").strip("/"))
    return rules


def evaluate_path_policy(
    changed_paths: list[str],
    *,
    allowed_rules: list[str],
    forbidden_rules: list[str],
) -> PathPolicyResult:
    violations: list[str] = []
    for changed_path in changed_paths:
        if matches_any_rule(changed_path, forbidden_rules):
            violations.append(changed_path)
            continue
        if allowed_rules and not matches_any_rule(changed_path, allowed_rules):
            violations.append(changed_path)
    return PathPolicyResult(
        passed=not violations,
        allowed_rules=allowed_rules,
        forbidden_rules=forbidden_rules,
        violating_paths=violations,
    )


def matches_any_rule(path: str, rules: list[str]) -> bool:
    if not rules:
        return False
    normalized = path.replace("\\", "/").strip("/")
    for rule in rules:
        if fnmatch.fnmatch(normalized, rule):
            return True
        if normalized == rule or normalized.startswith(f"{rule}/"):
            return True
    return False
