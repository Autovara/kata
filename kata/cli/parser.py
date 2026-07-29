"""Parser construction for the `kata` CLI.

Deliberately separate from the handlers. The parser IS a cross-project contract -- kata-bot invokes
this program as a subprocess and kata-sn60 imports from it -- so it is worth being able to read the
whole surface in one file without the command bodies interleaved.

Handlers are bound here via ``set_defaults(handler=...)``; nothing else couples the two halves.
"""

from __future__ import annotations

import argparse
from importlib.metadata import PackageNotFoundError, version

from kata.cli.commands.challenge import handle_challenge
from kata.cli.commands.king import handle_king_bootstrap, handle_king_promote
from kata.cli.commands.lane import (
    handle_lane_init,
    handle_lane_list,
    handle_lane_sync_registry,
)
from kata.cli.commands.plugin import (
    handle_plugin_capacity_estimate,
    handle_plugin_preflight,
)
from kata.cli.commands.submission import (
    handle_submission_init,
    handle_submission_inspect,
    handle_submission_validate,
)
from kata.submissions.constants import SUPPORTED_SUBMISSION_MODES

try:
    _KATA_VERSION = version("kata")
except PackageNotFoundError:  # not installed (e.g. running from a source checkout)
    _KATA_VERSION = "0+unknown"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kata",
        description="Initialize and evaluate subnet-pack coding-agent competition lanes.",
    )
    parser.add_argument("--version", action="version", version=f"kata {_KATA_VERSION}")

    subparsers = parser.add_subparsers(dest="command", required=True)
    _add_king_parser(subparsers)
    _add_lane_parsers(subparsers)
    _add_submission_parsers(subparsers)
    _add_challenge_parser(subparsers)
    _add_plugin_parser(subparsers)
    # Subnet plugins contribute their own subcommands (e.g. SN60's `sn60-baseline`).
    from kata.plugins.discovery import load_builtin_plugins
    from kata.plugins.registry import all_plugins

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
        dest="subnet_pack",
        default=None,
        help="Subnet pack id. Defaults to lane id.",
    )
    lane_init.add_argument(
        "--repo-pack",
        dest="subnet_pack",
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
        dest="subnet_pack",
        help="Target subnet pack id.",
    )
    submission_pack.add_argument(
        "--repo-pack",
        dest="subnet_pack",
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


def _add_plugin_parser(subparsers) -> None:
    """Machine-facing queries about an installed subnet plugin.

    These exist because the caller that needs the answer (kata-bot) deliberately does NOT import
    plugin code: it drives the engine as a subprocess. So anything only a plugin knows has to be
    reachable over the same seam as a challenge.
    """
    plugin_cmd = subparsers.add_parser(
        "plugin",
        help="Query an installed subnet plugin.",
    )
    plugin_subparsers = plugin_cmd.add_subparsers(dest="plugin_command", required=True)

    capacity = plugin_subparsers.add_parser(
        "capacity-estimate",
        help="Print the plugin's worst-case per-challenge cost bounds as JSON.",
    )
    capacity.add_argument(
        "--evaluator",
        required=True,
        help="Subnet evaluator id whose plugin is asked for its bounds.",
    )
    capacity.add_argument(
        "--config-json",
        default=None,
        help=(
            "The evaluator-owned challenge config, as a JSON object -- the SAME config the "
            "challenge will run with, so the bound cannot diverge from the real execution."
        ),
    )
    capacity.set_defaults(handler=handle_plugin_capacity_estimate)

    preflight = plugin_subparsers.add_parser(
        "preflight",
        help="Print the plugin's deployment-configuration problems as JSON.",
    )
    preflight.add_argument(
        "--evaluator",
        required=True,
        help="Subnet evaluator id whose plugin checks its own deployment.",
    )
    preflight.set_defaults(handler=handle_plugin_preflight)


def _add_challenge_parser(subparsers) -> None:
    challenge_cmd = subparsers.add_parser(
        "challenge",
        help="Score the king against several candidates on the same projects and rank them.",
    )
    challenge_cmd.add_argument(
        "--evaluator",
        required=True,
        help="Subnet evaluator id whose plugin runs the challenge.",
    )
    challenge_cmd.add_argument(
        "--king-path",
        required=True,
        help="Path to the current lane king artifact.",
    )
    challenge_cmd.add_argument(
        "--candidate",
        action="append",
        required=True,
        metavar="ID=PATH",
        help="A competing candidate as '<submission-id>=<artifact-path>'. Repeat per entrant.",
    )
    challenge_cmd.add_argument(
        "--challenge-cache-path",
        default=None,
        help="Optional evaluator-owned cache path for this challenge.",
    )
    challenge_cmd.add_argument(
        "--output-root",
        default=None,
        help="Optional base directory for challenge artifacts. Defaults to ./runs.",
    )
    challenge_cmd.add_argument(
        "--challenge-progress-path",
        default=None,
        help="Optional path to publish a live per-candidate progress snapshot for the dashboard.",
    )
    challenge_cmd.add_argument(
        "--challenge-config-json",
        default=None,
        help=(
            "Optional JSON object merged into the selected evaluator's challenge configuration. "
            "Used by multi-lane operators to keep plugin settings lane-scoped."
        ),
    )
    challenge_cmd.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of text.",
    )
    # Each registered subnet plugin contributes its own namespaced challenge arguments
    # (e.g. SN60's --sn60-* flags); the core challenge handler stays subnet-blind.
    from kata.plugins.discovery import load_builtin_plugins
    from kata.plugins.registry import all_plugins

    load_builtin_plugins()
    for plugin in all_plugins():
        plugin.add_challenge_arguments(challenge_cmd)
    challenge_cmd.set_defaults(handler=handle_challenge)
