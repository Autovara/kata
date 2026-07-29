"""`kata challenge` — run one challenge.

Its stdout JSON is parsed by kata-bot as a subprocess contract.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from kata.cli.output import print_json


def parse_challenge_candidate(spec: str) -> tuple[str, str]:
    submission_id, separator, artifact_path = spec.partition("=")
    if not separator or not submission_id.strip() or not artifact_path.strip():
        raise SystemExit(f"--candidate must be '<submission-id>=<path>', got: {spec!r}")
    return submission_id.strip(), artifact_path.strip()


def handle_challenge(args: argparse.Namespace) -> int:
    from kata.plugins.discovery import plugin_for_evaluator

    candidates = [parse_challenge_candidate(spec) for spec in args.candidate]
    plugin = plugin_for_evaluator(args.evaluator)
    if plugin is None:
        raise SystemExit(f"No subnet plugin is registered for evaluator '{args.evaluator}'.")
    config = plugin.build_challenge_config(args)
    if args.challenge_cache_path:
        config["challenge_cache_path"] = str(Path(args.challenge_cache_path).expanduser().resolve())
    if args.challenge_config_json:
        try:
            overrides = json.loads(args.challenge_config_json)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"--challenge-config-json must be valid JSON: {exc}") from exc
        if not isinstance(overrides, dict):
            raise SystemExit("--challenge-config-json must be a JSON object")
        config.update(overrides)
    result = plugin.run_challenge(
        king_agent_path=args.king_path,
        candidates=candidates,
        config=config,
        output_root=args.output_root or "runs",
        progress_path=args.challenge_progress_path,
    )
    if args.json:
        print_json(plugin.challenge_result_json(result))
    else:
        print(plugin.render_challenge_text(result))
    return 0
