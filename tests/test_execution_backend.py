"""The subnet-neutral backend resolver.

Its whole job is to fail closed. A resolver that silently defaulted on a typo would run an untrusted
agent outside the attested room while the deployment believed otherwise -- the failure mode that
looks exactly like success.
"""

from __future__ import annotations

import pytest

from kata.core.execution_backend import ExecutionBackendPolicy

SN22 = ExecutionBackendPolicy("KATA_SN22_EXECUTION_BACKEND", frozenset({"tee", "sandbox"}), "tee")


def test_an_unset_variable_resolves_to_the_safe_default():
    assert SN22.resolve({}) == "tee"


def test_an_explicit_selection_is_honoured():
    assert SN22.resolve({"KATA_SN22_EXECUTION_BACKEND": "sandbox"}) == "sandbox"


@pytest.mark.parametrize("value", ["sandbx", "TEE ", "docker", "local", "0", "true"])
def test_an_unrecognised_value_raises_rather_than_defaulting(value):
    """`TEE ` with trailing space is normalised and accepted; the rest must refuse. A default here
    would be a deployment running somewhere other than it thinks."""
    if value.strip().lower() in {"tee", "sandbox"}:
        assert SN22.resolve({"KATA_SN22_EXECUTION_BACKEND": value}) == value.strip().lower()
        return
    with pytest.raises(ValueError, match="must be one of"):
        SN22.resolve({"KATA_SN22_EXECUTION_BACKEND": value})


def test_case_and_surrounding_whitespace_are_normalised():
    assert SN22.resolve({"KATA_SN22_EXECUTION_BACKEND": "  TEE  "}) == "tee"


def test_the_error_names_the_variable_and_the_permitted_values():
    """An operator reading this message must be able to fix it without reading the source."""
    with pytest.raises(ValueError) as excinfo:
        SN22.resolve({"KATA_SN22_EXECUTION_BACKEND": "nonsense"})
    assert "KATA_SN22_EXECUTION_BACKEND" in str(excinfo.value)
    assert "sandbox" in str(excinfo.value) and "tee" in str(excinfo.value)


def test_a_policy_whose_default_is_not_permitted_is_refused_at_declaration():
    """Caught when the policy is written, not on the first deployment that omits the variable."""
    with pytest.raises(ValueError, match="not one of"):
        ExecutionBackendPolicy("X", frozenset({"tee"}), "sandbox")


def test_a_policy_permitting_nothing_is_refused():
    with pytest.raises(ValueError, match="at least one"):
        ExecutionBackendPolicy("X", frozenset(), "tee")


def test_is_selected_answers_without_a_second_resolve_path():
    assert SN22.is_selected("tee", {}) is True
    assert SN22.is_selected("sandbox", {}) is False
    assert SN22.is_selected("sandbox", {"KATA_SN22_EXECUTION_BACKEND": "sandbox"}) is True


def test_two_subnets_get_independent_variables():
    """The duplication this replaced differed ONLY in the variable name, so that is the thing that
    must genuinely stay per-subnet."""
    sn60 = ExecutionBackendPolicy(
        "KATA_SN60_EXECUTION_BACKEND", frozenset({"tee", "sandbox"}), "tee")
    env = {"KATA_SN22_EXECUTION_BACKEND": "sandbox"}
    assert SN22.resolve(env) == "sandbox"
    assert sn60.resolve(env) == "tee", "SN22's setting must not select SN60's backend"
