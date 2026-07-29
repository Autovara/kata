"""The contract every subnet plugin must satisfy, asserted against the real installed plugins.

The engine dispatches to plugins through a broad ABC with optional methods, which grew by accretion:
a plugin that forgot one gets a default, and the default is usually "do nothing". That fails silently
-- a lane scoring zero for a reason unrelated to its answers looks exactly like bad submissions.

This is the groundwork the capability-protocol work rests on: before methods can be regrouped into
explicit capabilities, there has to be a test saying which ones the installed plugins actually
implement. Run against whatever subnets are installed, so it covers the real ABI rather than a
fixture's idea of it.
"""

from __future__ import annotations

import inspect
from importlib.metadata import entry_points

import pytest

#: Every plugin must implement these itself. A default here would be the engine inventing an answer
#: about a subnet's competition on that subnet's behalf.
REQUIRED = (
    "evaluator_id",
    "sample_problems",
    "run_challenge",
    "beats_king",
    "environment_spec",
)

#: Optional today. Named explicitly so that regrouping them into capability protocols is a change to
#: this list, reviewed, rather than something discovered when a lane silently stops preflighting.
OPTIONAL_METHODS = (
    "preflight",
    "capacity_estimate",
    "static_screen",
    "challenge_result_json",
    "register_cli",
)

#: Optional surface that is a PROPERTY, not a method. The distinction is not cosmetic: the engine
#: reads these, and calling one -- or dispatching to a method as though it were an attribute -- is a
#: TypeError on a paid round. Both installed plugins expose `scoring_profile` as a property, which a
#: first version of this test asserted was callable and failed on.
OPTIONAL_PROPERTIES = (
    "scoring_profile",
)


def _installed_plugins():
    found = []
    for entry in entry_points(group="kata.subnets"):
        try:
            found.append((entry.name, entry.load()))
        except Exception as exc:  # noqa: BLE001 - a plugin that cannot load IS the finding
            pytest.fail(f"installed plugin {entry.name!r} failed to load: {exc}")
    return found


def test_at_least_the_entry_point_group_is_intact():
    """The group name is the ABI. Renaming it breaks every separately deployed subnet at once."""
    names = [entry.name for entry in entry_points(group="kata.subnets")]
    assert names == sorted(set(names)), f"duplicate subnet entry points: {names}"


@pytest.mark.parametrize("attribute", REQUIRED)
def test_every_installed_plugin_implements_the_required_surface(attribute):
    plugins = _installed_plugins()
    if not plugins:
        pytest.skip("no subnet plugin is installed in this environment")
    for name, plugin in plugins:
        assert getattr(plugin, attribute, None) is not None, f"{name} lacks {attribute}"


def test_every_installed_plugin_declares_a_unique_evaluator_id():
    """Two plugins claiming one id is refused by the registry, but only once both are loaded. A
    duplicate shipped in a release would surface as an install-time crash on the host."""
    plugins = _installed_plugins()
    if len(plugins) < 2:
        pytest.skip("fewer than two subnet plugins installed")
    ids = [plugin.evaluator_id for _, plugin in plugins]
    assert len(set(ids)) == len(ids), f"duplicate evaluator ids: {ids}"


@pytest.mark.parametrize("attribute", OPTIONAL_METHODS)
def test_an_optional_method_is_either_absent_or_callable(attribute):
    """Never a non-callable attribute. `plugin.preflight` being a dict would be dispatched to and
    fail deep inside a round rather than at load."""
    for name, plugin in _installed_plugins():
        value = getattr(plugin, attribute, None)
        if value is None:
            continue
        assert callable(value), f"{name}.{attribute} exists but is not callable"


@pytest.mark.parametrize("attribute", OPTIONAL_PROPERTIES)
def test_an_optional_property_is_read_not_called(attribute):
    """Absent, or a value. Never a bound method: the engine reads it as an attribute."""
    for name, plugin in _installed_plugins():
        if not hasattr(plugin, attribute):
            continue
        value = getattr(plugin, attribute)
        assert not inspect.ismethod(value) and not inspect.isfunction(value), (
            f"{name}.{attribute} is a method; the engine reads it as a property"
        )


def test_run_challenge_keeps_the_signature_the_engine_calls():
    """The engine passes these by keyword. A renamed parameter is a TypeError on a paid round."""
    for name, plugin in _installed_plugins():
        params = inspect.signature(plugin.run_challenge).parameters
        for required in ("king_agent_path", "candidates", "config", "output_root"):
            assert required in params, f"{name}.run_challenge lost {required!r}"
