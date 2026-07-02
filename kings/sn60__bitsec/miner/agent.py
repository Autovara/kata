from __future__ import annotations

"""Seed king for the sn60__bitsec/miner lane.

This is the intentionally weak baseline agent. It satisfies the SN60
contract (synchronous, no-argument-callable `agent_main` returning a
Bitsec-compatible report) and reports no findings, so any candidate that
finds real vulnerabilities will beat it in the duel.
"""


def agent_main(
    project_dir: str | None = None,
    inference_api: str | None = None,
) -> dict:
    return {
        "vulnerabilities": [],
    }
