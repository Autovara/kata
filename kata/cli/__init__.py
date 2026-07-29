"""Command-line interface for Kata maintainers and local validation.

This package replaced a single ``cli.py``. It stays a NARROW FACADE on purpose: ``kata.cli:main`` is
the console-script entry point, and kata-sn60 -- packaged and deployed on its own schedule --
imports
``build_parser``, ``main``, ``parse_challenge_candidate`` and ``print_json`` from here. Re-exporting
them is not tidiness; it is the compatibility window for a consumer that cannot be updated in
lockstep with this repository.
"""

from __future__ import annotations

from collections.abc import Sequence

from kata.cli.commands.challenge import handle_challenge, parse_challenge_candidate
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
from kata.cli.output import collect_changed_paths, print_json
from kata.cli.parser import build_parser

__all__ = [
    "build_parser",
    "collect_changed_paths",
    "handle_challenge",
    "handle_king_bootstrap",
    "handle_king_promote",
    "handle_lane_init",
    "handle_lane_list",
    "handle_lane_sync_registry",
    "handle_plugin_capacity_estimate",
    "handle_plugin_preflight",
    "handle_submission_init",
    "handle_submission_inspect",
    "handle_submission_validate",
    "main",
    "parse_challenge_candidate",
    "print_json",
]


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.handler(args)
