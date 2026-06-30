from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path

from kata.baseline import generate_baseline_prompt
from kata.benchmarks import render_benchmark_registry, resolve_benchmark_registry
from kata.challenge import (
    load_challenge_summary,
    render_challenge_summary,
    run_frontier_challenge,
)
from kata.eval_pack import (
    discover_eval_pack_tasks,
    init_eval_pack,
    render_validation_result,
)
from kata.eval_runner import run_eval
from kata.frontier import (
    DEFAULT_PROMOTION_MARGIN_POINTS,
    init_frontier,
    load_frontier_manifest,
    render_frontier_json,
    render_frontier_manifest,
    update_frontier_prompt,
)
from kata.generator import generate_prompt
from kata.reporting import render_report
from kata.submissions import (
    decide_submission_action,
    evaluate_submission,
    init_submission,
    inspect_pull_request,
    read_changed_paths_file,
    render_pull_request_inspection,
    render_submission_decision,
    render_submission_json,
    render_submission_validation,
    render_submission_verification,
    validate_submission,
    verify_submission_result,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kata",
        description="Initialize and evaluate repo-specific coding-agent competition lanes.",
    )
    parser.add_argument("--version", action="version", version="kata 0.1.0")

    subparsers = parser.add_subparsers(dest="command", required=True)

    generate = subparsers.add_parser(
        "generate",
        help="Generate an initial repo-specific prompt from repo sources.",
    )
    generate.add_argument("--repo", required=True, help="Path or URL of the target repo.")
    generate.add_argument(
        "--mode",
        choices=["contributor", "reviewer"],
        default="contributor",
        help="Prompt mode to initialize.",
    )
    generate.add_argument(
        "--registry-url",
        default=None,
        help="Optional SN74 registry JSON URL. Defaults to env or built-in live test-branch URL.",
    )
    generate.set_defaults(handler=handle_generate)

    baseline = subparsers.add_parser(
        "baseline",
        help="Create or print the fixed generic baseline prompt.",
    )
    baseline.add_argument("--repo", required=True, help="Path or URL of the target repo.")
    baseline.add_argument(
        "--mode",
        choices=["contributor", "reviewer"],
        default="contributor",
        help="Baseline prompt mode to generate.",
    )
    baseline.set_defaults(handler=handle_baseline)

    eval_cmd = subparsers.add_parser(
        "eval",
        help="Run the baseline-vs-generated reference eval workflow.",
    )
    eval_cmd.add_argument("--repo", required=True, help="Path or URL of the target repo.")
    eval_cmd.add_argument(
        "--eval-pack",
        required=True,
        help="Path to the repo eval pack or a pack id under the benchmark registry.",
    )
    eval_cmd.add_argument(
        "--mode",
        choices=["contributor", "reviewer"],
        default="contributor",
        help="Prompt mode to compare.",
    )
    eval_cmd.add_argument(
        "--agent-command",
        required=True,
        help=(
            "Shell command used to run the agent in each workspace. It runs with "
            "KATA_WORKSPACE, KATA_PROMPT_FILE, KATA_TASK_FILE, and "
            "other eval-pack file paths set."
        ),
    )
    eval_cmd.add_argument(
        "--registry-url",
        default=None,
        help="Optional SN74 registry JSON URL for generated prompts.",
    )
    eval_cmd.add_argument(
        "--output-root",
        default=None,
        help="Optional base directory for eval run artifacts. Defaults to ./runs.",
    )
    eval_cmd.add_argument(
        "--agent-timeout-seconds",
        type=int,
        default=None,
        help="Optional timeout for each agent-command run.",
    )
    eval_cmd.add_argument(
        "--checks-timeout-seconds",
        type=int,
        default=None,
        help="Optional timeout for each checks.sh run.",
    )
    eval_cmd.set_defaults(handler=handle_eval)

    frontier = subparsers.add_parser(
        "frontier",
        help="Manage baseline/frontier prompt state for competition.",
    )
    frontier_subparsers = frontier.add_subparsers(dest="frontier_command", required=True)

    frontier_init = frontier_subparsers.add_parser(
        "init", help="Create baseline/frontier prompts and a frontier manifest."
    )
    frontier_init.add_argument("--repo", required=True, help="Path or URL of the target repo.")
    frontier_init.add_argument(
        "--eval-pack",
        required=True,
        help="Path to the repo eval pack or a pack id under the benchmark registry.",
    )
    frontier_init.add_argument(
        "--mode",
        choices=["contributor", "reviewer"],
        default="contributor",
        help="Prompt mode to initialize.",
    )
    frontier_init.add_argument(
        "--registry-url",
        default=None,
        help="Optional SN74 registry JSON URL for initializing frontier prompts.",
    )
    frontier_init.add_argument(
        "--primary-task",
        action="append",
        default=None,
        help="Task id to include in the primary pool. Repeat to select multiple tasks.",
    )
    frontier_init.add_argument(
        "--holdout-task",
        action="append",
        default=None,
        help="Task id to include in the holdout pool. Repeat to select multiple tasks.",
    )
    frontier_init.add_argument(
        "--promotion-margin-points",
        type=float,
        default=None,
        help="Optional score margin the challenger must clear to replace the frontier.",
    )
    frontier_init.set_defaults(handler=handle_frontier_init)

    frontier_show = frontier_subparsers.add_parser("show", help="Show frontier manifest details.")
    frontier_show.add_argument(
        "--eval-pack",
        required=True,
        help="Path to the repo eval pack or a pack id under the benchmark registry.",
    )
    frontier_show.add_argument(
        "--mode",
        choices=["contributor", "reviewer"],
        default=None,
        help="Optional mode to render.",
    )
    frontier_show.add_argument("--json", action="store_true")
    frontier_show.set_defaults(handler=handle_frontier_show)

    frontier_promote = frontier_subparsers.add_parser(
        "promote", help="Promote a successful challenger prompt into the frontier."
    )
    frontier_promote.add_argument(
        "--challenge-run",
        required=True,
        help="Path to a challenge_summary.json file produced by `kata challenge`.",
    )
    frontier_promote.add_argument("--json", action="store_true")
    frontier_promote.set_defaults(handler=handle_frontier_promote)

    challenge = subparsers.add_parser(
        "challenge",
        help="Run baseline/frontier/challenger competition for one repo and mode.",
    )
    challenge.add_argument(
        "--eval-pack",
        required=True,
        help="Path to the repo eval pack or a pack id under the benchmark registry.",
    )
    challenge.add_argument(
        "--mode",
        choices=["contributor", "reviewer"],
        default="contributor",
        help="Prompt mode to challenge.",
    )
    challenge.add_argument(
        "--candidate-prompt",
        required=True,
        help="Path to the challenger prompt file to evaluate against the current frontier.",
    )
    challenge.add_argument(
        "--agent-command",
        required=True,
        help="Shell command used to run the agent in each workspace.",
    )
    challenge.add_argument(
        "--output-root",
        default=None,
        help="Optional base directory for challenge artifacts. Defaults to ./runs.",
    )
    challenge.add_argument(
        "--agent-timeout-seconds",
        type=int,
        default=None,
        help="Optional timeout for each agent-command run.",
    )
    challenge.add_argument(
        "--checks-timeout-seconds",
        type=int,
        default=None,
        help="Optional timeout for each checks.sh run.",
    )
    challenge.set_defaults(handler=handle_challenge)

    eval_pack = subparsers.add_parser("eval-pack", help="Scaffold or validate repo eval packs.")
    eval_pack_subparsers = eval_pack.add_subparsers(dest="eval_pack_command", required=True)

    eval_pack_init = eval_pack_subparsers.add_parser("init", help="Create a new eval-pack task.")
    eval_pack_init.add_argument("--repo", required=True, help="Path or URL of the target repo.")
    eval_pack_init.add_argument("--task-id", required=True, help="Task id for the eval case.")
    eval_pack_init.add_argument(
        "--output-root",
        default=None,
        help=(
            "Optional benchmark registry root or benchmarks directory. "
            "Defaults to the registry discovered via "
            "`kata-benchmark-registry.json`."
        ),
    )
    eval_pack_init.set_defaults(handler=handle_eval_pack_init)

    eval_pack_validate = eval_pack_subparsers.add_parser(
        "validate", help="Validate an eval-pack task directory."
    )
    eval_pack_validate.add_argument(
        "--path",
        required=True,
        help="Path to the eval-pack task/pack or a pack id under the benchmark registry.",
    )
    eval_pack_validate.set_defaults(handler=handle_eval_pack_validate)

    registry = subparsers.add_parser(
        "registry",
        help="Inspect the configured benchmark registry and active repo packs.",
    )
    registry_subparsers = registry.add_subparsers(dest="registry_command", required=True)

    registry_show = registry_subparsers.add_parser(
        "show",
        help="Show benchmark registry metadata and active repo packs.",
    )
    registry_show.add_argument(
        "--root",
        default=None,
        help="Optional benchmark registry root or benchmarks directory.",
    )
    registry_show.add_argument("--json", action="store_true")
    registry_show.set_defaults(handler=handle_registry_show)

    report = subparsers.add_parser("report", help="Render an eval report.")
    report.add_argument("--run", required=True, help="Run id or path to run artifacts.")
    report.set_defaults(handler=handle_report)

    submission = subparsers.add_parser(
        "submission",
        help="Manage miner agent submissions for PR-based competition.",
    )
    submission_subparsers = submission.add_subparsers(
        dest="submission_command", required=True
    )

    submission_init = submission_subparsers.add_parser(
        "init",
        help="Scaffold a challenger agent submission.",
    )
    submission_init.add_argument("--repo-pack", required=True, help="Target repo pack id.")
    submission_init.add_argument(
        "--mode",
        choices=["contributor", "reviewer"],
        required=True,
        help="Competition mode for the challenger submission.",
    )
    submission_init.add_argument(
        "--submission-id",
        required=True,
        help=(
            "Stable submission id. Recommended format: "
            "`<github-username>-YYYYMMDD-NN`."
        ),
    )
    submission_init.add_argument(
        "--output-root",
        default=None,
        help="Optional submissions root. Defaults to ./submissions.",
    )
    submission_init.add_argument(
        "--author",
        default=None,
        help="Optional GitHub username for leaderboard identity and avatar lookup.",
    )
    submission_init.add_argument("--title", default=None, help="Optional submission title.")
    submission_init.add_argument("--notes", default=None, help="Optional short notes.")
    submission_init.set_defaults(handler=handle_submission_init)

    submission_validate = submission_subparsers.add_parser(
        "validate",
        help="Validate a PR submission directory and optional changed-file scope.",
    )
    submission_validate.add_argument(
        "--path",
        required=True,
        help="Path to submissions/<repo-pack>/<mode>/<submission-id>.",
    )
    submission_validate.add_argument(
        "--changed-path",
        action="append",
        default=None,
        help="Changed path from the PR diff. Repeat for each changed file.",
    )
    submission_validate.add_argument(
        "--changed-path-file",
        default=None,
        help="Optional newline-delimited file of changed paths from the PR diff.",
    )
    submission_validate.add_argument(
        "--repo-root",
        default=None,
        help="Optional Kata repo root used to resolve changed paths.",
    )
    submission_validate.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of text.",
    )
    submission_validate.set_defaults(handler=handle_submission_validate)

    submission_inspect = submission_subparsers.add_parser(
        "inspect-pr",
        help="Inspect PR changed paths and decide whether the PR should be closed or evaluated.",
    )
    submission_inspect.add_argument(
        "--repo-root",
        required=True,
        help="Kata repo root used to resolve the inferred submission path.",
    )
    submission_inspect.add_argument(
        "--changed-path",
        action="append",
        default=None,
        help="Changed path from the PR diff. Repeat for each changed file.",
    )
    submission_inspect.add_argument(
        "--changed-path-file",
        default=None,
        help="Optional newline-delimited file of changed paths from the PR diff.",
    )
    submission_inspect.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of text.",
    )
    submission_inspect.set_defaults(handler=handle_submission_inspect)

    submission_evaluate = submission_subparsers.add_parser(
        "evaluate",
        help="Run a validated submission against the current frontier.",
    )
    submission_evaluate.add_argument(
        "--path",
        required=True,
        help="Path to submissions/<repo-pack>/<mode>/<submission-id>.",
    )
    submission_evaluate.add_argument(
        "--agent-command",
        required=True,
        help="Shell command used to run the agent in each workspace.",
    )
    submission_evaluate.add_argument(
        "--output-root",
        default=None,
        help="Optional base directory for run artifacts. Defaults to ./runs.",
    )
    submission_evaluate.add_argument(
        "--agent-timeout-seconds",
        type=int,
        default=None,
        help="Optional timeout for each agent-command run.",
    )
    submission_evaluate.add_argument(
        "--checks-timeout-seconds",
        type=int,
        default=None,
        help="Optional timeout for each checks.sh run.",
    )
    submission_evaluate.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON with the challenge summary path.",
    )
    submission_evaluate.set_defaults(handler=handle_submission_evaluate)

    submission_verify = submission_subparsers.add_parser(
        "verify",
        help="Check whether a submission result is still current and auto-mergeable.",
    )
    submission_verify.add_argument(
        "--path",
        required=True,
        help="Path to submissions/<repo-pack>/<mode>/<submission-id>.",
    )
    submission_verify.add_argument(
        "--challenge-run",
        required=True,
        help="Path to the challenge_summary.json generated for this submission.",
    )
    submission_verify.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of text.",
    )
    submission_verify.set_defaults(handler=handle_submission_verify)

    submission_decide = submission_subparsers.add_parser(
        "decide",
        help="Decide whether a submission PR should be closed, rerun, or auto-merged.",
    )
    submission_decide.add_argument(
        "--path",
        required=True,
        help="Path to submissions/<repo-pack>/<mode>/<submission-id>.",
    )
    submission_decide.add_argument(
        "--challenge-run",
        required=True,
        help="Path to the challenge_summary.json generated for this submission.",
    )
    submission_decide.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of text.",
    )
    submission_decide.set_defaults(handler=handle_submission_decide)

    return parser


def handle_generate(args: argparse.Namespace) -> int:
    print(generate_prompt(args.repo, args.mode, args.registry_url))
    return 0


def handle_baseline(args: argparse.Namespace) -> int:
    print(generate_baseline_prompt(args.repo, args.mode))
    return 0


def handle_eval(args: argparse.Namespace) -> int:
    summary = run_eval(
        repo_ref=args.repo,
        eval_pack_path=args.eval_pack,
        mode=args.mode,
        agent_command=args.agent_command,
        registry_url=args.registry_url,
        output_root=args.output_root,
        agent_timeout_seconds=args.agent_timeout_seconds,
        checks_timeout_seconds=args.checks_timeout_seconds,
    )
    print(
        f"Created eval run: {summary.run_id}\n"
        f"Run kind: {summary.run_kind}\n"
        f"Mode: {summary.mode}\n"
        f"Requested repo: {summary.requested_repo_ref}\n"
        f"Eval pack: {summary.eval_pack}\n"
        f"Evaluator version: {summary.metadata.get('evaluator_version', 'unknown')}\n"
        f"Task pool fingerprint: {summary.metadata.get('task_pool_fingerprint', 'unknown')}"
    )
    for task in summary.tasks:
        print(f"Task: {task.task_id}")
        print(f"Repo ref: {task.task_repo_ref}")
        for variant in task.variants:
            print(
                f"- {variant.name}: agent_exit={variant.agent_exit_code}, "
                f"checks_exit={variant.checks_exit_code}, success={variant.success}"
            )
    return 0


def handle_frontier_init(args: argparse.Namespace) -> int:
    manifest = init_frontier(
        repo_ref=args.repo,
        eval_pack_path=args.eval_pack,
        mode=args.mode,
        registry_url=args.registry_url,
        primary_tasks=args.primary_task,
        holdout_tasks=args.holdout_task,
        promotion_margin_points=(
            args.promotion_margin_points
            if args.promotion_margin_points is not None
            else DEFAULT_PROMOTION_MARGIN_POINTS
        ),
    )
    print(render_frontier_manifest(manifest, args.mode))
    return 0


def handle_frontier_show(args: argparse.Namespace) -> int:
    manifest = load_frontier_manifest(args.eval_pack)
    print(
        render_frontier_json(manifest)
        if args.json
        else render_frontier_manifest(manifest, args.mode)
    )
    return 0


def handle_frontier_promote(args: argparse.Namespace) -> int:
    summary = load_challenge_summary(args.challenge_run)
    if not summary.promotion_ready:
        raise ValueError(
            "Challenge is not promotion-ready. "
            f"Reason: {summary.promotion_reason}"
        )
    candidate_text = Path(summary.candidate_prompt).read_text(encoding="utf-8")
    manifest = update_frontier_prompt(
        eval_pack_path=Path(summary.manifest_path).parent.as_posix(),
        mode=summary.mode,
        new_prompt_text=candidate_text,
        source=summary.run_id,
        evaluator_version=summary.evaluator_version,
    )
    print(
        render_frontier_json(manifest)
        if args.json
        else render_frontier_manifest(manifest, summary.mode)
    )
    return 0


def handle_challenge(args: argparse.Namespace) -> int:
    summary = run_frontier_challenge(
        eval_pack_path=args.eval_pack,
        mode=args.mode,
        candidate_prompt_path=args.candidate_prompt,
        agent_command=args.agent_command,
        output_root=args.output_root,
        agent_timeout_seconds=args.agent_timeout_seconds,
        checks_timeout_seconds=args.checks_timeout_seconds,
    )
    print(render_challenge_summary(summary))
    return 0


def handle_eval_pack_init(args: argparse.Namespace) -> int:
    pack_dir = init_eval_pack(args.repo, args.task_id, args.output_root)
    print(f"Created eval pack: {pack_dir}")
    return 0


def handle_eval_pack_validate(args: argparse.Namespace) -> int:
    results = discover_eval_pack_tasks(args.path)
    print("\n\n".join(render_validation_result(result) for result in results))
    return 0 if all(result.is_valid for result in results) else 2


def handle_registry_show(args: argparse.Namespace) -> int:
    registry = resolve_benchmark_registry(args.root)
    if args.json:
        print_json(
            {
                "root": str(registry.root),
                "benchmarks_dir": str(registry.benchmarks_dir),
                "marker_path": str(registry.marker_path),
                "schema_version": registry.schema_version,
                "registry_name": registry.registry_name,
                "active_repo_packs": list(registry.active_repo_packs),
                "default_repo_pack": registry.default_repo_pack,
            }
        )
    else:
        print(render_benchmark_registry(registry))
    return 0


def handle_report(args: argparse.Namespace) -> int:
    print(render_report(args.run))
    return 0


def handle_submission_init(args: argparse.Namespace) -> int:
    submission_dir = init_submission(
        repo_pack=args.repo_pack,
        mode=args.mode,
        submission_id=args.submission_id,
        output_root=args.output_root,
        author=args.author,
        title=args.title,
        notes=args.notes,
    )
    print(f"Created submission: {submission_dir}")
    return 0


def handle_submission_validate(args: argparse.Namespace) -> int:
    changed_paths = collect_changed_paths(args.changed_path, args.changed_path_file)
    result = validate_submission(
        args.path,
        changed_paths=changed_paths,
        repo_root=args.repo_root,
    )
    print(
        render_submission_json(result)
        if args.json
        else render_submission_validation(result)
    )
    return 0 if result.is_valid else 2


def handle_submission_inspect(args: argparse.Namespace) -> int:
    result = inspect_pull_request(
        repo_root=args.repo_root,
        changed_paths=collect_changed_paths(args.changed_path, args.changed_path_file),
    )
    print(
        render_submission_json(result)
        if args.json
        else render_pull_request_inspection(result)
    )
    return 0 if result.action == "evaluate" else 2


def handle_submission_evaluate(args: argparse.Namespace) -> int:
    summary = evaluate_submission(
        args.path,
        agent_command=args.agent_command,
        output_root=args.output_root,
        agent_timeout_seconds=args.agent_timeout_seconds,
        checks_timeout_seconds=args.checks_timeout_seconds,
    )
    if args.json:
        output_base = Path(args.output_root) if args.output_root else Path("runs")
        payload = {
            "run_id": summary.run_id,
            "challenge_summary_path": str(
                (output_base / summary.run_id / "challenge_summary.json").resolve()
            ),
            "promotion_ready": summary.promotion_ready,
            "promotion_reason": summary.promotion_reason,
        }
        print_json(payload)
    else:
        print(render_challenge_summary(summary))
    return 0


def handle_submission_verify(args: argparse.Namespace) -> int:
    result = verify_submission_result(args.path, args.challenge_run)
    print(
        render_submission_json(result)
        if args.json
        else render_submission_verification(result)
    )
    return 0 if result.auto_merge_ready else 2


def handle_submission_decide(args: argparse.Namespace) -> int:
    result = decide_submission_action(args.path, args.challenge_run)
    print(
        render_submission_json(result)
        if args.json
        else render_submission_decision(result)
    )
    return 0 if result.action == "merge" else 2


def collect_changed_paths(
    inline_paths: list[str] | None,
    file_path: str | None,
) -> list[str]:
    changed_paths = list(inline_paths or [])
    if file_path:
        changed_paths.extend(read_changed_paths_file(file_path))
    return changed_paths


def print_json(payload: dict[str, object]) -> None:
    import json

    print(json.dumps(payload, indent=2))


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.handler(args)
