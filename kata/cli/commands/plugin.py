"""`kata plugin` — per-subnet preflight and capacity estimation."""

from __future__ import annotations

import argparse
import json


def handle_plugin_preflight(args: argparse.Namespace) -> int:
    from kata.plugins.discovery import plugin_for_evaluator

    plugin = plugin_for_evaluator(args.evaluator)
    if plugin is None:
        raise SystemExit(f"No subnet plugin is registered for evaluator '{args.evaluator}'.")
    issues: list[dict[str, str]] = []
    for issue in plugin.preflight() or []:
        if not isinstance(issue, dict):
            raise SystemExit(f"plugin returned a non-usable preflight issue: {issue!r}")
        level = str(issue.get("level") or "error")
        if level not in {"error", "warning"}:
            # An unknown level must not be silently downgraded to a warning: that would let a
            # blocking problem through preflight and into a round.
            raise SystemExit(f"plugin returned an unknown preflight level: {level!r}")
        issues.append({"level": level, "message": str(issue.get("message") or "")})
    print(json.dumps({"evaluator": args.evaluator, "issues": issues}))
    return 0


def handle_plugin_capacity_estimate(args: argparse.Namespace) -> int:
    from kata.plugins.discovery import plugin_for_evaluator

    plugin = plugin_for_evaluator(args.evaluator)
    if plugin is None:
        raise SystemExit(f"No subnet plugin is registered for evaluator '{args.evaluator}'.")
    try:
        config = json.loads(args.config_json) if args.config_json else {}
    except ValueError as exc:
        raise SystemExit(f"--config-json is not valid JSON: {exc}") from exc
    if not isinstance(config, dict):
        raise SystemExit("--config-json must be a JSON object.")
    bounds = plugin.capacity_estimate(config=config)
    # Emit only finite, non-negative numbers: a caller reserves against these, so a NaN/inf or a
    # negative "bound" must fail here rather than silently weaken a hard cap downstream.
    cleaned: dict[str, float] = {}
    for dimension, value in (bounds or {}).items():
        number = float(value)
        if number != number or number in (float("inf"), float("-inf")) or number < 0:
            raise SystemExit(f"plugin returned a non-usable bound for {dimension!r}: {value!r}")
        cleaned[str(dimension)] = number
    print(json.dumps({"evaluator": args.evaluator, "bounds": cleaned}))
    return 0
