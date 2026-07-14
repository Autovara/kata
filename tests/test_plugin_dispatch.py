"""Tests: resolving the subnet plugin for a submission/lane, with no subnet installed.

kata itself declares no subnet -- each real subnet lives in its own repo and is discovered via a
``kata.subnets`` entry point. These check the negative paths that hold regardless of what is
installed; discovery-with-a-real-subnet is tested in the subnet repos (e.g. kata-sn22).
"""

from __future__ import annotations

from kata.packages.dispatch import load_builtin_plugins, plugin_for_evaluator


def test_load_builtin_plugins_no_subnet_installed_is_noop() -> None:
    # With no subnet package installed, discovery finds nothing and must not raise.
    load_builtin_plugins()


def test_plugin_for_evaluator_unknown_or_blank() -> None:
    assert plugin_for_evaluator("does-not-exist") is None
    assert plugin_for_evaluator(None) is None
    assert plugin_for_evaluator("") is None
