"""Command-line interface for Kata maintainers and local validation."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

from kata.promotion_system import bootstrap_lane_king, find_evaluator_pack_entry
from kata.state_system.lane import (
    LANE_METADATA_SCHEMA_VERSION,
    EvaluatorLaneMetadata,
    lane_metadata_path,
    load_lane_metadata,
    load_pack_registry,
    sync_pack_registry,
    write_lane_metadata,
)
from kata.submission_system import (
    SUPPORTED_SUBMISSION_MODES,
    decide_submission_action,
    init_submission,
    inspect_pull_request,
    promote_submission_result,
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
        description="Initialize and evaluate subnet-pack coding-agent competition lanes.",
    )
    parser.add_argument("--version", action="version", version="kata 0.1.0")

    subparsers = parser.add_subparsers(dest="command", required=True)
    _add_king_parser(subparsers)
    _add_lane_parsers(subparsers)
    _add_submission_parsers(subparsers)
    _add_round_parser(subparsers)
    # Subnet plugins contribute their own subcommands (e.g. SN60's `sn60-baseline`).
    from kata.packages.dispatch import load_builtin_plugins
    from kata.packages.registry import all_plugins

    load_builtin_plugins()
    for plugin in all_plugins():
        plugin.register_cli(subparsers)
    return parser


def _add_king_parser(subparsers) -> None:
    king = subparsers.add_parser(
        "king",
        help="Manage the current king agent for a lane.",
    )
    king_subparsers = king.add_subparsers(dest="king_command", required=True)

    king_promote = king_subparsers.add_parser(
        "promote", help="Promote a verified winning candidate into the lane king."
    )
    king_promote.add_argument(
        "--challenge-run",
        required=True,
        help="Path to a challenge_summary.json file produced by `kata challenge`.",
    )
    king_promote.add_argument(
        "--submission-path",
        default=None,
        help=(
            "Optional path to submissions/<subnet-pack>/<mode>/<submission-id>. "
            "Defaults to the candidate artifact recorded in the challenge summary."
        ),
    )
    king_promote.add_argument(
        "--public-root",
        default=None,
        help=(
            "Optional public Kata repo root used to publish the visible king mirror "
            "under `kings/<subnet-pack>/<mode>/`. Defaults to the current working directory."
        ),
    )
    king_promote.add_argument("--json", action="store_true")
    king_promote.set_defaults(handler=handle_king_promote)

    king_bootstrap = king_subparsers.add_parser(
        "bootstrap",
        help="Screen and seed an empty lane with a maintained baseline king.",
    )
    king_bootstrap.add_argument("--subnet-pack", required=True)
    king_bootstrap.add_argument("--mode", default="miner")
    king_bootstrap.add_argument("--baseline-path", required=True)
    king_bootstrap.add_argument("--baseline-id", required=True)
    king_bootstrap.add_argument("--public-root", default=None)
    king_bootstrap.add_argument(
        "--replace",
        action="store_true",
        help="Replace an existing king after screening. Intended only for controlled resets.",
    )
    king_bootstrap.add_argument("--json", action="store_true")
    king_bootstrap.set_defaults(handler=handle_king_bootstrap)


def _add_lane_parsers(subparsers) -> None:
    lane = subparsers.add_parser(
        "lane",
        help="Manage evaluator-backed subnet packs and the central pack registry.",
    )
    lane_subparsers = lane.add_subparsers(dest="lane_command", required=True)

    lane_init = lane_subparsers.add_parser(
        "init",
        help="Create or update an evaluator-backed lane and register it in the pack registry.",
    )
    lane_init.add_argument("--lane-id", required=True, help="Lane id, e.g. sn60__bitsec.")
    lane_init.add_argument(
        "--subnet-pack",
        dest="repo_pack",
        default=None,
        help="Subnet pack id. Defaults to lane id.",
    )
    lane_init.add_argument(
        "--repo-pack",
        dest="repo_pack",
        default=None,
        help="Deprecated alias for --subnet-pack.",
    )
    lane_init.add_argument("--mode", default="miner", help="Submission mode for the lane.")
    lane_init.add_argument(
        "--evaluator-id",
        required=True,
        help="Evaluator adapter id for the lane, e.g. sn60_bitsec.",
    )
    lane_init.add_argument(
        "--policy-version",
        default="v1",
        help="Evaluator policy version recorded in lane metadata.",
    )
    lane_init.add_argument(
        "--inactive",
        action="store_true",
        help="Register the lane without activating it.",
    )
    lane_init.add_argument(
        "--public-root",
        default=None,
        help="Optional Kata root that owns the lanes directory.",
    )
    lane_init.add_argument("--json", action="store_true")
    lane_init.set_defaults(handler=handle_lane_init)

    lane_list = lane_subparsers.add_parser(
        "list",
        help="List subnet packs from the central pack registry.",
    )
    lane_list.add_argument(
        "--active-only",
        action="store_true",
        help="Only list packs marked active in the registry.",
    )
    lane_list.add_argument(
        "--public-root",
        default=None,
        help="Optional Kata root that owns the lanes directory.",
    )
    lane_list.add_argument("--json", action="store_true")
    lane_list.set_defaults(handler=handle_lane_list)

    lane_sync = lane_subparsers.add_parser(
        "sync-registry",
        help="Rebuild the central pack registry from lane.json files on disk.",
    )
    lane_sync.add_argument(
        "--public-root",
        default=None,
        help="Optional Kata root that owns the lanes directory.",
    )
    lane_sync.add_argument("--json", action="store_true")
    lane_sync.set_defaults(handler=handle_lane_sync_registry)


def _add_submission_parsers(subparsers) -> None:
    submission = subparsers.add_parser(
        "submission",
        help="Manage miner agent submissions for PR-based competition.",
    )
    submission_subparsers = submission.add_subparsers(dest="submission_command", required=True)

    submission_init = submission_subparsers.add_parser(
        "init",
        help="Scaffold a challenger agent submission.",
    )
    submission_pack = submission_init.add_mutually_exclusive_group(required=True)
    submission_pack.add_argument(
        "--subnet-pack",
        dest="repo_pack",
        help="Target subnet pack id.",
    )
    submission_pack.add_argument(
        "--repo-pack",
        dest="repo_pack",
        help="Deprecated alias for --subnet-pack.",
    )
    submission_init.add_argument(
        "--mode",
        choices=sorted(SUPPORTED_SUBMISSION_MODES),
        required=True,
        help="Competition mode for the challenger submission.",
    )
    submission_init.add_argument(
        "--submission-id",
        required=True,
        help=("Stable submission id. Recommended format: `<github-username>-YYYYMMDD-NN`."),
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
        help="Path to submissions/<subnet-pack>/<mode>/<submission-id>.",
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
        help="Run a validated submission against the current lane king.",
    )
    submission_evaluate.add_argument(
        "--path",
        required=True,
        help="Path to submissions/<subnet-pack>/<mode>/<submission-id>.",
    )
    submission_evaluate.add_argument(
        "--output-root",
        default=None,
        help="Optional base directory for run artifacts. Defaults to ./runs.",
    )
    # Each subnet plugin contributes its own evaluate arguments (e.g. SN60's --sn60-* flags).
    from kata.packages.dispatch import load_builtin_plugins
    from kata.packages.registry import all_plugins

    load_builtin_plugins()
    for plugin in all_plugins():
        plugin.add_evaluate_arguments(submission_evaluate)
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
        help="Path to submissions/<subnet-pack>/<mode>/<submission-id>.",
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
        help="Path to submissions/<subnet-pack>/<mode>/<submission-id>.",
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


def _add_round_parser(subparsers) -> None:
    round_cmd = subparsers.add_parser(
        "round",
        help="Score the king against several candidates on the same projects and rank them.",
    )
    round_cmd.add_argument(
        "--evaluator",
        required=True,
        help="Subnet evaluator id whose plugin runs the round.",
    )
    round_cmd.add_argument(
        "--king-path",
        required=True,
        help="Path to the current lane king artifact.",
    )
    round_cmd.add_argument(
        "--candidate",
        action="append",
        required=True,
        metavar="ID=PATH",
        help="A competing candidate as '<submission-id>=<artifact-path>'. Repeat per entrant.",
    )
    round_cmd.add_argument(
        "--round-cache-path",
        default=None,
        help="Optional evaluator-owned cache path for this round.",
    )
    round_cmd.add_argument(
        "--candidate-only",
        action="store_true",
        help=(
            "Recovery mode: score candidates against each other only and skip "
            "evaluating the current king."
        ),
    )
    round_cmd.add_argument(
        "--output-root",
        default=None,
        help="Optional base directory for round artifacts. Defaults to ./runs.",
    )
    round_cmd.add_argument(
        "--round-progress-path",
        default=None,
        help="Optional path to publish a live per-candidate progress snapshot for the dashboard.",
    )
    round_cmd.add_argument(
        "--round-config-json",
        default=None,
        help=(
            "Optional JSON object merged into the selected evaluator's round configuration. "
            "Used by multi-lane operators to keep plugin settings lane-scoped."
        ),
    )
    round_cmd.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of text.",
    )
    # Each registered subnet plugin contributes its own namespaced round arguments
    # (e.g. SN60's --sn60-* flags); the core round handler stays subnet-blind.
    from kata.packages.dispatch import load_builtin_plugins
    from kata.packages.registry import all_plugins

    load_builtin_plugins()
    for plugin in all_plugins():
        plugin.add_round_arguments(round_cmd)
    round_cmd.set_defaults(handler=handle_round)


def handle_king_promote(args: argparse.Namespace) -> int:
    if not args.submission_path:
        raise SystemExit(
            "--submission-path is required: pass the candidate submission directory to promote."
        )
    # Default to None (not cwd) so promotion resolves the public root the same way
    # `verify`/`decide` do — honoring KATA_ROOT — instead of silently writing kings/ +
    # lane state into whatever directory it's run in.
    public_root = str(Path(args.public_root).expanduser().resolve()) if args.public_root else None
    result = promote_submission_result(
        args.submission_path,
        args.challenge_run,
        public_root=public_root,
    )
    if args.json:
        print_json(
            {
                "lane_id": result.lane_id,
                "king_root": result.king_root,
                "current_king_submission_id": result.king.current_king_submission_id,
                "current_king_artifact_hash": result.king.current_king_artifact_hash,
                "promotion_timestamp": result.king.promotion_timestamp,
            }
        )
    else:
        print(
            f"Promoted `{result.king.current_king_submission_id}` "
            f"as king of lane `{result.lane_id}`."
        )
    return 0


def handle_king_bootstrap(args: argparse.Namespace) -> int:
    public_root = str(Path(args.public_root).expanduser().resolve()) if args.public_root else None
    entry = find_evaluator_pack_entry(
        args.subnet_pack,
        args.mode,
        public_root=public_root,
    )
    if entry is None:
        raise SystemExit(
            f"No evaluator-backed lane is registered for `{args.subnet_pack}/{args.mode}`."
        )
    result = bootstrap_lane_king(
        entry=entry,
        baseline_path=args.baseline_path,
        baseline_id=args.baseline_id,
        public_root=public_root,
        replace_existing=args.replace,
    )
    if args.json:
        print_json(
            {
                "lane_id": result.lane_id,
                "baseline_id": result.baseline_id,
                "king_root": result.king_root,
                "current_king_artifact_hash": result.king.current_king_artifact_hash,
            }
        )
    else:
        print(
            f"Seeded `{result.baseline_id}` as the baseline king of lane `{result.lane_id}`."
        )
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
    print(render_submission_json(result) if args.json else render_submission_validation(result))
    return 0 if result.is_valid else 2


def handle_submission_inspect(args: argparse.Namespace) -> int:
    result = inspect_pull_request(
        repo_root=args.repo_root,
        changed_paths=collect_changed_paths(args.changed_path, args.changed_path_file),
    )
    print(render_submission_json(result) if args.json else render_pull_request_inspection(result))
    return 0 if result.action == "evaluate" else 2


def handle_submission_evaluate(args: argparse.Namespace) -> int:
    from kata.submission_system.workflow import plugin_for_submission

    validation = validate_submission(args.path)
    if not validation.is_valid or validation.metadata is None:
        raise SystemExit(
            "Submission is invalid. Run `kata submission validate` first. "
            + "; ".join(validation.reasons or ["unknown validation failure"])
        )
    plugin = plugin_for_submission(validation.metadata)
    if plugin is None:
        raise SystemExit(
            "No subnet plugin is registered for lane "
            f"`{validation.metadata.repo_pack}/{validation.metadata.mode}`."
        )
    return plugin.evaluate_from_cli(args)


def handle_submission_verify(args: argparse.Namespace) -> int:
    result = verify_submission_result(args.path, args.challenge_run)
    print(render_submission_json(result) if args.json else render_submission_verification(result))
    return 0 if result.auto_merge_ready else 2


def handle_submission_decide(args: argparse.Namespace) -> int:
    result = decide_submission_action(args.path, args.challenge_run)
    print(render_submission_json(result) if args.json else render_submission_decision(result))
    return 0 if result.action == "merge" else 2


def parse_round_candidate(spec: str) -> tuple[str, str]:
    submission_id, separator, artifact_path = spec.partition("=")
    if not separator or not submission_id.strip() or not artifact_path.strip():
        raise SystemExit(f"--candidate must be '<submission-id>=<path>', got: {spec!r}")
    return submission_id.strip(), artifact_path.strip()


def handle_round(args: argparse.Namespace) -> int:
    from kata.packages.dispatch import plugin_for_evaluator

    candidates = [parse_round_candidate(spec) for spec in args.candidate]
    plugin = plugin_for_evaluator(args.evaluator)
    if plugin is None:
        raise SystemExit(
            f"No subnet plugin is registered for evaluator '{args.evaluator}'."
        )
    config = plugin.build_round_config(args)
    if args.round_cache_path:
        config["round_cache_path"] = str(Path(args.round_cache_path).expanduser().resolve())
    if args.round_config_json:
        try:
            overrides = json.loads(args.round_config_json)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"--round-config-json must be valid JSON: {exc}") from exc
        if not isinstance(overrides, dict):
            raise SystemExit("--round-config-json must be a JSON object")
        config.update(overrides)
    result = plugin.run_round(
        king_agent_path=args.king_path,
        candidates=candidates,
        config=config,
        output_root=args.output_root or "runs",
        score_king=not args.candidate_only,
        progress_path=args.round_progress_path,
    )
    if args.json:
        print_json(plugin.round_result_json(result))
    else:
        print(plugin.render_round_text(result))
    return 0


def handle_lane_init(args: argparse.Namespace) -> int:
    from datetime import UTC, datetime

    now = datetime.now(UTC).isoformat()
    created_at = now
    if lane_metadata_path(args.lane_id, public_root=args.public_root).exists():
        created_at = load_lane_metadata(args.lane_id, public_root=args.public_root).created_at
    metadata = EvaluatorLaneMetadata(
        schema_version=LANE_METADATA_SCHEMA_VERSION,
        lane_id=args.lane_id,
        repo_pack=args.repo_pack or args.lane_id,
        mode=args.mode,
        evaluator_id=args.evaluator_id,
        evaluator_policy_version=args.policy_version,
        active=not args.inactive,
        created_at=created_at,
        updated_at=now,
    )
    path = write_lane_metadata(metadata, public_root=args.public_root)
    if args.json:
        print_json({"lane_metadata_path": str(path), "lane_id": metadata.lane_id})
    else:
        print(f"Registered lane `{metadata.lane_id}` at {path}")
    return 0


def handle_lane_list(args: argparse.Namespace) -> int:
    registry = load_pack_registry(public_root=args.public_root)
    packs = [pack for pack in registry.packs if pack.active or not args.active_only]
    if args.json:
        print_json(
            {
                "schema_version": registry.schema_version,
                "updated_at": registry.updated_at,
                "packs": [
                    {
                        "lane_id": pack.lane_id,
                        "subnet_pack": pack.repo_pack,
                        "repo_pack": pack.repo_pack,
                        "mode": pack.mode,
                        "evaluator_id": pack.evaluator_id,
                        "active": pack.active,
                    }
                    for pack in packs
                ],
            }
        )
        return 0
    if not packs:
        print("No subnet packs registered.")
        return 0
    for pack in packs:
        status = "active" if pack.active else "inactive"
        print(f"{pack.lane_id}  mode={pack.mode}  evaluator={pack.evaluator_id}  {status}")
    return 0


def handle_lane_sync_registry(args: argparse.Namespace) -> int:
    registry = sync_pack_registry(public_root=args.public_root)
    if args.json:
        print_json(
            {
                "packs": [pack.lane_id for pack in registry.packs],
                "updated_at": registry.updated_at,
            }
        )
    else:
        print(f"Synced pack registry with {len(registry.packs)} lane(s).")
    return 0


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
