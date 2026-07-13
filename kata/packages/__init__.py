"""Subnet plugins for Kata.

Each subnet is an independent, self-contained plugin (task + environment + scorer +
config) implementing :class:`SubnetPlugin`. The core runs its King-of-the-Hill
competition against whatever plugin a lane names, without importing subnet code.

This package holds the plugin contract and registry; concrete plugins (e.g. ``sn60``)
live in subpackages and register themselves.
"""

from __future__ import annotations

from .plugin import (
    EnvSpec,
    NetworkPolicy,
    ProblemSet,
    ProgressUpdate,
    RawRun,
    RunContext,
    ScoreCard,
    ScoringProfile,
    SubnetPlugin,
)
from .registry import (
    all_plugins,
    clear_registry,
    get_plugin,
    get_plugin_or_none,
    register_plugin,
)

__all__ = [
    "EnvSpec",
    "NetworkPolicy",
    "ProblemSet",
    "ProgressUpdate",
    "RawRun",
    "RunContext",
    "ScoreCard",
    "ScoringProfile",
    "SubnetPlugin",
    "all_plugins",
    "clear_registry",
    "get_plugin",
    "get_plugin_or_none",
    "register_plugin",
]
