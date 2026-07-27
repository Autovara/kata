"""Tests: resolving the subnet plugin for a submission/lane, with no subnet installed.

kata itself declares no subnet -- each real subnet lives in its own repo and is discovered via a
``kata.subnets`` entry point. These check the negative paths that hold regardless of what is
installed; discovery-with-a-real-subnet is tested in the subnet repos (e.g. kata-sn22).
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from kata.plugins.discovery import load_builtin_plugins, plugin_for_evaluator


def test_load_builtin_plugins_no_subnet_installed_is_noop() -> None:
    # With no subnet package installed, discovery finds nothing and must not raise.
    load_builtin_plugins()


def test_plugin_for_evaluator_unknown_or_blank() -> None:
    assert plugin_for_evaluator("does-not-exist") is None
    assert plugin_for_evaluator(None) is None
    assert plugin_for_evaluator("") is None


# ---- `kata plugin capacity-estimate` (S3) --------------------------------------------------------
# kata-bot cannot import a plugin to ask for its worst-case cost -- it drives the engine as a
# subprocess and its deployed runtime has no `kata` installed. This command is that seam.
def _stub_plugin(bounds):
    return SimpleNamespace(capacity_estimate=lambda *, config: dict(bounds))


def _run_capacity_cli(monkeypatch, capsys, plugin, args):
    import kata.cli as cli
    import kata.plugins.discovery as discovery

    monkeypatch.setattr(discovery, "plugin_for_evaluator", lambda _e: plugin)
    code = cli.handle_plugin_capacity_estimate(args)
    return code, json.loads(capsys.readouterr().out)


def test_capacity_estimate_emits_the_plugin_bounds_as_json(monkeypatch, capsys):
    args = SimpleNamespace(evaluator="probe", config_json=json.dumps({"replicas_per_project": 3}))
    code, payload = _run_capacity_cli(monkeypatch, capsys, _stub_plugin({"tee_runs": 192}), args)
    assert code == 0
    assert payload == {"evaluator": "probe", "bounds": {"tee_runs": 192.0}}


def test_capacity_estimate_passes_the_config_through_untouched(monkeypatch, capsys):
    seen: dict[str, object] = {}
    plugin = SimpleNamespace(
        capacity_estimate=lambda *, config: seen.update(config) or {"tee_runs": 1}
    )
    args = SimpleNamespace(evaluator="probe", config_json=json.dumps({"replicas_per_project": 3}))
    _run_capacity_cli(monkeypatch, capsys, plugin, args)
    # The plugin must bound the SAME config the challenge runs with, or the reservation can diverge.
    assert seen == {"replicas_per_project": 3}


def test_capacity_estimate_refuses_an_unregistered_evaluator(monkeypatch, capsys):
    args = SimpleNamespace(evaluator="nope", config_json=None)
    with pytest.raises(SystemExit):
        _run_capacity_cli(monkeypatch, capsys, None, args)


@pytest.mark.parametrize("bad", ["{not json", "[]", '"a string"'])
def test_capacity_estimate_refuses_a_config_that_is_not_a_json_object(monkeypatch, capsys, bad):
    args = SimpleNamespace(evaluator="probe", config_json=bad)
    with pytest.raises(SystemExit):
        _run_capacity_cli(monkeypatch, capsys, _stub_plugin({}), args)


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), -1.0])
def test_capacity_estimate_refuses_an_unusable_bound(monkeypatch, capsys, bad):
    # A caller RESERVES against this number, so a NaN/inf/negative "bound" would silently weaken the
    # very hard cap it exists to enforce. Fail here instead.
    args = SimpleNamespace(evaluator="probe", config_json=None)
    with pytest.raises(SystemExit):
        _run_capacity_cli(monkeypatch, capsys, _stub_plugin({"tee_runs": bad}), args)


def test_capacity_estimate_reports_no_bounds_for_a_plugin_that_declares_none(monkeypatch, capsys):
    args = SimpleNamespace(evaluator="probe", config_json=None)
    code, payload = _run_capacity_cli(monkeypatch, capsys, _stub_plugin({}), args)
    assert code == 0 and payload["bounds"] == {}


def test_the_contract_default_bounds_nothing():
    """An existing plugin that never heard of capacity_estimate stays conformant and simply bounds
    nothing -- the core then defers rather than running against a cap it cannot enforce."""
    from kata.plugins.contract import SubnetPlugin

    assert SubnetPlugin.capacity_estimate(object(), config={}) == {}
