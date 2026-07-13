"""In-process registry of subnet plugins (Phase 1 of the multi-subnet refactor).

The core resolves a subnet's plugin by its ``evaluator_id`` (the same id the lane
registry records). Plugins register themselves at import time; the core looks them up
here and never imports subnet packages directly. Nothing calls this yet.
"""

from __future__ import annotations

from .plugin import SubnetPlugin

_REGISTRY: dict[str, SubnetPlugin] = {}

_REQUIRED_ATTRS = ("evaluator_id", "pack", "mode", "scoring_profile", "validator_identity")


def register_plugin(plugin: SubnetPlugin) -> None:
    """Register a subnet plugin under its ``evaluator_id``.

    Idempotent for the same instance; raises if a *different* plugin claims an id that
    is already taken, or if the plugin is missing a required attribute.
    """
    for attr in _REQUIRED_ATTRS:
        if not getattr(plugin, attr, None):
            raise ValueError(
                f"Subnet plugin {plugin!r} is missing required attribute '{attr}'."
            )
    existing = _REGISTRY.get(plugin.evaluator_id)
    if existing is not None and existing is not plugin:
        raise ValueError(
            f"A different subnet plugin is already registered for evaluator id "
            f"'{plugin.evaluator_id}'."
        )
    _REGISTRY[plugin.evaluator_id] = plugin


def get_plugin(evaluator_id: str) -> SubnetPlugin:
    """Return the plugin for ``evaluator_id`` or raise ``KeyError`` if none is registered."""
    try:
        return _REGISTRY[evaluator_id]
    except KeyError:
        raise KeyError(
            f"No subnet plugin registered for evaluator id '{evaluator_id}'."
        ) from None


def get_plugin_or_none(evaluator_id: str) -> SubnetPlugin | None:
    """Return the plugin for ``evaluator_id``, or ``None`` if none is registered."""
    return _REGISTRY.get(evaluator_id)


def all_plugins() -> tuple[SubnetPlugin, ...]:
    """All registered plugins, in registration order."""
    return tuple(_REGISTRY.values())


def clear_registry() -> None:
    """Reset the registry. Intended for tests only."""
    _REGISTRY.clear()
