from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from kata.scoring import (
    diff_paths,
    evaluate_path_policy,
    read_path_rules,
    resolve_verifier_score,
)


def render_report(run_ref: str) -> str:
    run_root = resolve_run_root(run_ref)
    summary = load_summary(run_root / "run_summary.json")
    task_reports = [build_task_report(run_root, task) for task in summary["tasks"]]
    variant_names = task_reports[0]["variant_order"] if task_reports else []
    variant_scores = {
        variant_name: aggregate_variant_score(task_reports, variant_name)
        for variant_name in variant_names
    }

    lines: list[str] = []
    lines.append(f"# Kata Eval Report: {summary['run_id']}")
    lines.append("")
    lines.append(f"- Created: {summary['created_at']}")
    lines.append(f"- Run kind: {summary.get('run_kind', 'eval')}")
    lines.append(f"- Mode: {summary['mode']}")
    lines.append(f"- Requested repo: `{summary['requested_repo_ref']}`")
    lines.append(f"- Eval pack: `{summary['eval_pack']}`")
    lines.append(f"- Agent command: `{summary['agent_command']}`")
    metadata = summary.get("metadata") or {}
    if metadata.get("evaluator_version"):
        lines.append(f"- Evaluator version: `{metadata['evaluator_version']}`")
    if metadata.get("task_pool_fingerprint"):
        lines.append(f"- Task pool fingerprint: `{metadata['task_pool_fingerprint']}`")
    lines.append("")
    lines.append("## Measurement Basis")
    lines.append(
        "- Benchmark quality is measured per task as verifier score in `[0, 1]`, then "
        "collapsed to zero when the run is invalid."
    )
    lines.append(
        "- Protected or forbidden path compliance is measured from the actual changed files "
        "against `allowed_paths.txt` and `forbidden_paths.txt`."
    )
    lines.append(
        "- Kata score is the task-weighted average quality scaled to `0-100`."
    )
    lines.append("")
    lines.append("## Aggregate Results")
    lines.append(f"- Tasks: {len(task_reports)}")
    for variant_name in variant_names:
        lines.append(f"- {variant_name} score: {variant_scores[variant_name]:.2f}")
    if len(variant_names) == 2:
        pairwise = summarize_pairwise(task_reports, variant_names[0], variant_names[1])
        lines.append(f"- {variant_names[1]} wins: {pairwise['right_wins']}")
        lines.append(f"- {variant_names[0]} wins: {pairwise['left_wins']}")
        lines.append(f"- Ties: {pairwise['ties']}")
        lines.append(f"- Invalid runs: {pairwise['invalid']}")
        comparable = pairwise["left_wins"] + pairwise["right_wins"] + pairwise["ties"]
        if comparable:
            lines.append(
                f"- {variant_names[1]} win rate: {pairwise['right_wins']}/{comparable}"
            )
        else:
            lines.append(
                f"- {variant_names[1]} win rate: not available because no task produced "
                "a comparable result."
            )

    for task_report in task_reports:
        lines.append("")
        lines.append(f"## Task: {task_report['task_id']}")
        lines.append(f"- Repo ref: `{task_report['task_repo_ref']}`")
        lines.append(f"- Outcome: {task_report['outcome']}")
        lines.append(f"- Task weight: {task_report['task_weight']:g}")
        lines.append("")
        lines.extend(render_variant_table(task_report))
        lines.append("")
        for variant_name in task_report["variant_order"]:
            variant = task_report["variants"][variant_name]
            lines.append(
                f"- {variant_name} changed paths: {render_paths(variant['changed_paths'])}"
            )
            lines.append(
                f"- {variant_name} path issues: {render_paths(variant['path_policy_violations'])}"
            )

    return "\n".join(lines)


def render_variant_table(task_report: dict[str, Any]) -> list[str]:
    variant_order = task_report["variant_order"]
    lines = [
        "| Metric | " + " | ".join(variant_order) + " |",
        "| " + " | ".join(["---"] * (len(variant_order) + 1)) + " |",
    ]
    rows = [
        ("Agent command", lambda variant: render_status(variant["agent_ok"])),
        ("Task solved", lambda variant: render_status(variant["task_solved"])),
        ("Checks passed", lambda variant: render_status(variant["checks_passed"])),
        (
            "Protected/forbidden paths avoided",
            lambda variant: render_status(variant["path_policy_passed"]),
        ),
        ("Valid benchmark run", lambda variant: render_status(variant["validity_passed"])),
        ("Verifier score", lambda variant: f"{variant['verifier_score']:.2f}"),
        ("Final task quality", lambda variant: f"{variant['quality_score']:.2f}"),
        ("Repo rules followed", lambda variant: variant["repo_rules_followed"]),
        (
            "Scoring/review misunderstanding detected",
            lambda variant: variant["scoring_review_misunderstanding"],
        ),
    ]
    for label, formatter in rows:
        rendered_values = [
            formatter(task_report["variants"][variant_name]) for variant_name in variant_order
        ]
        lines.append("| " + " | ".join([label, *rendered_values]) + " |")
    return lines


def resolve_run_root(run_ref: str) -> Path:
    candidate = Path(run_ref).expanduser()
    if candidate.is_file() and candidate.name == "run_summary.json":
        return candidate.parent.resolve()
    if candidate.is_dir():
        return candidate.resolve()

    default_root = Path("runs") / run_ref
    if default_root.is_dir():
        return default_root.resolve()
    raise FileNotFoundError(f"Run artifacts not found: {run_ref}")


def load_summary(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def build_task_report(run_root: Path, task: dict[str, Any]) -> dict[str, Any]:
    task_root = run_root / "tasks" / task["task_id"]
    repo_snapshot = task_root / "repo_snapshot"
    eval_pack_root = task_root / "eval_pack"
    variants = {
        variant["name"]: build_variant_report(repo_snapshot, eval_pack_root, variant)
        for variant in task["variants"]
    }
    variant_order = [variant["name"] for variant in task["variants"]]
    return {
        "task_id": task["task_id"],
        "task_repo_ref": task["task_repo_ref"],
        "task_weight": float(task.get("task_weight", 1.0)),
        "variants": variants,
        "variant_order": variant_order,
        "outcome": summarize_task_outcome(variants, variant_order),
    }


def build_variant_report(
    repo_snapshot: Path,
    eval_pack_root: Path,
    variant: dict[str, Any],
) -> dict[str, Any]:
    changed_paths = variant.get("changed_paths")
    path_policy_violations = variant.get("path_policy_violations")
    path_policy_passed = variant.get("path_policy_passed")
    if changed_paths is None or path_policy_violations is None or path_policy_passed is None:
        changed_paths = diff_paths(repo_snapshot, Path(variant["workspace"]))
        path_policy = evaluate_path_policy(
            changed_paths,
            allowed_rules=read_path_rules(eval_pack_root / "allowed_paths.txt"),
            forbidden_rules=read_path_rules(eval_pack_root / "forbidden_paths.txt"),
        )
        path_policy_passed = path_policy.passed
        path_policy_violations = path_policy.violating_paths

    checks_passed = variant["checks_exit_code"] == 0
    verifier_score = variant.get("verifier_score")
    score_source = variant.get("score_source")
    if verifier_score is None or score_source is None:
        verifier_score, score_source = resolve_verifier_score(
            Path(variant["workspace"]).parent / "score.txt",
            checks_passed=checks_passed,
        )

    task_weight = float(variant.get("task_weight", read_task_weight_fallback(eval_pack_root)))
    validity_passed = bool(
        variant.get("validity_passed", variant["agent_exit_code"] == 0 and path_policy_passed)
    )
    quality_score = float(variant.get("quality_score", verifier_score if validity_passed else 0.0))
    return {
        "agent_ok": variant["agent_exit_code"] == 0,
        "task_solved": bool(variant.get("task_solved", checks_passed)),
        "checks_passed": checks_passed,
        "validity_passed": validity_passed,
        "verifier_score": float(verifier_score),
        "quality_score": quality_score,
        "score_source": score_source,
        "path_policy_passed": bool(path_policy_passed),
        "path_policy_violations": list(path_policy_violations),
        "changed_paths": list(changed_paths),
        "task_weight": task_weight,
        "weighted_task_score": float(
            variant.get("weighted_task_score", quality_score * task_weight)
        ),
        "repo_rules_followed": "not separately measured",
        "scoring_review_misunderstanding": "not separately measured",
        "success_score": score_variant(
            agent_ok=variant["agent_exit_code"] == 0,
            checks_passed=checks_passed,
            path_policy_passed=bool(path_policy_passed),
        ),
    }


def compare_variants(left: dict[str, Any], right: dict[str, Any]) -> str:
    left_quality = float(left.get("quality_score", left.get("success_score", 0.0)))
    right_quality = float(right.get("quality_score", right.get("success_score", 0.0)))
    if right_quality > left_quality:
        return "Kata win"
    if left_quality > right_quality:
        return "Baseline win"
    if not left.get("validity_passed", left["agent_ok"]) and not right.get(
        "validity_passed", right["agent_ok"]
    ):
        return "Invalid run"
    return "Tie"


def summarize_pairwise(
    task_reports: list[dict[str, Any]], left_variant: str, right_variant: str
) -> dict[str, int]:
    left_wins = 0
    right_wins = 0
    ties = 0
    invalid = 0
    for task_report in task_reports:
        outcome = compare_variants(
            task_report["variants"][left_variant],
            task_report["variants"][right_variant],
        )
        if outcome == "Kata win":
            right_wins += 1
        elif outcome == "Baseline win":
            left_wins += 1
        elif outcome == "Invalid run":
            invalid += 1
        else:
            ties += 1
    return {
        "left_wins": left_wins,
        "right_wins": right_wins,
        "ties": ties,
        "invalid": invalid,
    }


def summarize_task_outcome(
    variants: dict[str, dict[str, Any]], variant_order: list[str]
) -> str:
    if len(variant_order) == 2:
        left = variants[variant_order[0]]
        right = variants[variant_order[1]]
        outcome = compare_variants(left, right)
        if outcome == "Kata win":
            return f"{variant_order[1]} win"
        if outcome == "Baseline win":
            return f"{variant_order[0]} win"
        return outcome

    scores = {name: variants[name]["quality_score"] for name in variant_order}
    best_score = max(scores.values(), default=0.0)
    winners = [name for name, score in scores.items() if score == best_score]
    if len(winners) == 1:
        return f"best variant: {winners[0]}"
    return "tie: " + ", ".join(winners)


def score_variant(*, agent_ok: bool, checks_passed: bool, path_policy_passed: bool) -> int:
    return int(agent_ok and checks_passed and path_policy_passed)


def variant_completed_task(variant: dict[str, Any]) -> bool:
    return bool(variant["agent_ok"] and variant["task_solved"] and variant["path_policy_passed"])


def aggregate_variant_score(task_reports: list[dict[str, Any]], variant_name: str) -> float:
    total_weight = sum(report["task_weight"] for report in task_reports)
    if total_weight <= 0:
        return 0.0
    weighted = sum(
        report["variants"][variant_name]["quality_score"] * report["task_weight"]
        for report in task_reports
    )
    return round((weighted / total_weight) * 100, 2)


def read_task_weight_fallback(eval_pack_root: Path) -> float:
    task_weight_path = eval_pack_root / "task_weight.txt"
    if not task_weight_path.exists():
        return 1.0
    raw = task_weight_path.read_text(encoding="utf-8").strip()
    return float(raw) if raw else 1.0


def render_paths(paths: list[str]) -> str:
    return ", ".join(f"`{path}`" for path in paths) if paths else "none"


def render_status(value: bool) -> str:
    return "pass" if value else "fail"
