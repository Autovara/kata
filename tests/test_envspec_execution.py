"""T3: the execution backend is a platform-level EnvSpec field, so any lane can declare miner-paid
TEE execution generically (not via a subnet-specific env var)."""

from __future__ import annotations

from kata.packages import EnvSpec


def test_execution_defaults_to_sandbox() -> None:
    assert EnvSpec().execution == "sandbox"


def test_execution_can_be_tee() -> None:
    spec = EnvSpec(network="relay_only", execution="tee")
    assert spec.execution == "tee"
    assert spec.network == "relay_only"
