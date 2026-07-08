"""Command-line interface for Kata maintainers and local validation."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path

from kata.evaluators.sn60_bitsec import (
    DEFAULT_REPLICAS_PER_PROJECT,
    hash_bundle_root,
)
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
    evaluate_submission,
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
from kata.validator_system import (
    load_challenge_summary,
    render_challenge_summary,
    resolve_sn60_project_keys,
    run_sn60_round,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kata",
        description="Initialize and evaluate subnet-pack coding-agent competition lanes.",
    )
    parser.add_argument("--version", action="version", version="kata 0.1.0")

    subparsers = parser.add_subparsers(dest="command", required=True)

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
    submission_evaluate.add_argument(
        "--sn60-project-key",
        action="append",
        default=None,
        help=(
            "Optional SN60 Bitsec project key to evaluate. Repeat for multiple "
            "projects. Defaults to every project_id in the resolved benchmark snapshot."
        ),
    )
    submission_evaluate.add_argument(
        "--sn60-replicas-per-project",
        type=int,
        default=None,
        help="Optional SN60 replica count per project.",
    )
    submission_evaluate.add_argument(
        "--sn60-sandbox-root",
        default=None,
        help="Optional local SN60 sandbox root.",
    )
    submission_evaluate.add_argument(
        "--sn60-benchmark-file",
        default=None,
        help="Optional SN60 benchmark JSON file path.",
    )
    submission_evaluate.add_argument(
        "--sn60-sandbox-commit",
        default=None,
        help="Optional SN60 sandbox commit identifier.",
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

    round_cmd = subparsers.add_parser(
        "round",
        help="Score the king against several candidates on the same projects and rank them.",
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
        "--sn60-project-key",
        action="append",
        default=None,
        help=(
            "SN60 project key to score every entrant on. Repeat per project. When "
            "omitted, the round secretly samples this round's problems from the "
            "benchmark (KATA_SN60_PROJECT_SAMPLE_SIZE / _SECRET)."
        ),
    )
    round_cmd.add_argument(
        "--king-scoreboard",
        default=None,
        help="Optional path to the persistent per-project king score cache.",
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
    round_cmd.add_argument("--sn60-replicas-per-project", type=int, default=None)
    round_cmd.add_argument("--sn60-sandbox-root", default=None)
    round_cmd.add_argument("--sn60-benchmark-file", default=None)
    round_cmd.add_argument("--sn60-sandbox-commit", default=None)
    round_cmd.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of text.",
    )
    round_cmd.set_defaults(handler=handle_round)

    return parser






def handle_king_promote(args: argparse.Namespace) -> int:
    summary = load_challenge_summary(args.challenge_run)
    # Default to None (not cwd) so promotion resolves the public root the same
    # way `verify`/`decide`/`evaluate` do — honoring KATA_ROOT — instead of
    # silently writing kings/ + lane state into whatever directory it's run in.
    public_root = (
        str(Path(args.public_root).expanduser().resolve())
        if args.public_root
        else None
    )
    result = promote_submission_result(
        args.submission_path or summary.candidate_artifact,
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
        output_root=args.output_root,
        sn60_project_keys=args.sn60_project_key,
        sn60_replicas_per_project=args.sn60_replicas_per_project,
        sn60_sandbox_root=args.sn60_sandbox_root,
        sn60_benchmark_file=args.sn60_benchmark_file,
        sn60_sandbox_commit=args.sn60_sandbox_commit,
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


def parse_round_candidate(spec: str) -> tuple[str, str]:
    submission_id, separator, artifact_path = spec.partition("=")
    if not separator or not submission_id.strip() or not artifact_path.strip():
        raise SystemExit(f"--candidate must be '<submission-id>=<path>', got: {spec!r}")
    return submission_id.strip(), artifact_path.strip()


def handle_round(args: argparse.Namespace) -> int:
    candidates = [parse_round_candidate(spec) for spec in args.candidate]
    project_keys = args.sn60_project_key or resolve_sn60_project_keys(
        configured_keys=None,
        sandbox_root=args.sn60_sandbox_root,
        benchmark_file=args.sn60_benchmark_file,
        sandbox_commit=args.sn60_sandbox_commit,
        king_artifact_hash=hash_bundle_root(Path(args.king_path).expanduser().resolve()),
    )
    result = run_sn60_round(
        king_artifact_path=args.king_path,
        candidates=candidates,
        project_keys=project_keys,
        output_root=args.output_root,
        replicas_per_project=args.sn60_replicas_per_project or DEFAULT_REPLICAS_PER_PROJECT,
        sandbox_root=args.sn60_sandbox_root,
        benchmark_file=args.sn60_benchmark_file,
        sandbox_commit=args.sn60_sandbox_commit,
        king_scoreboard_path=args.king_scoreboard,
        progress_path=args.round_progress_path,
    )
    if args.json:
        print_json(
            {
                "run_id": result.run_id,
                "round_summary_path": str(
                    (Path(result.output_root) / "round_summary.json").resolve()
                ),
                "winner_submission_id": result.winner_submission_id,
                "winner_challenge_summary_path": result.winner_challenge_summary_path,
                "promotion_ready": result.promotion_ready,
                "promotion_reason": result.promotion_reason,
                "king": _sn60_variant_detail(result.king),
                "entries": [
                    {
                        "submission_id": entry.submission_id,
                        "beats_king": entry.beats_king,
                        "duel_run_id": entry.duel_run_id,
                        **_sn60_variant_detail(entry.candidate),
                    }
                    for entry in result.entries
                ],
            }
        )
    else:
        print(render_round_result(result))
    return 0


def _sn60_variant_detail(variant) -> dict:  # type: ignore[no-untyped-def]
    """Serialize a variant summary (king or candidate) with its per-project
    breakdown so the dashboard can render a detailed per-PR duel view."""
    return {
        "aggregated_score": variant.aggregated_score,
        "average_detection_rate": variant.average_detection_rate,
        "true_positives": variant.true_positives,
        "total_expected": variant.total_expected,
        "total_found": variant.total_found,
        "precision": variant.precision,
        "f1_score": variant.f1_score,
        "invalid_runs": variant.invalid_runs,
        "codebase_pass_count": variant.codebase_pass_count,
        "projects": [
            {
                "project_key": project.project_key,
                "passed": project.passed,
                "detection_rate": project.average_detection_rate,
                "true_positives": project.true_positives,
                "total_expected": project.total_expected,
                "total_found": project.total_found,
                "precision": project.precision,
                "f1_score": project.f1_score,
            }
            for project in variant.project_summaries
        ],
    }


def render_round_result(result) -> str:  # type: ignore[no-untyped-def]
    lines = [
        f"SN60 round {result.run_id}",
        f"king detection {result.king.aggregated_score:.3f} "
        f"(tp {result.king.true_positives}/{result.king.total_expected})",
        "ranking (best first):",
    ]
    for position, entry in enumerate(result.entries, start=1):
        marker = "WINNER" if entry.submission_id == result.winner_submission_id else (
            "beats-king" if entry.beats_king else "-"
        )
        lines.append(
            f"  {position}. {entry.submission_id} "
            f"detection {entry.candidate.aggregated_score:.3f} "
            f"(tp {entry.candidate.true_positives}) {marker}"
        )
    lines.append(result.promotion_reason)
    return "\n".join(lines)


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
