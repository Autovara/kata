"""Make a skipped cross-repository contract test impossible to miss.

`tests/test_submission_preflight.py` verifies that this repository's PR gate bans exactly what
kata-sn22's own static screen bans. It has to, because the gate is dependency-free by design --
`validate-submission.yml` runs it on a bare Python with no `pip install`, so it cannot import the
plugin and must restate the list.

`.github/workflows/ci.yml` checks out only this repository, so that test SKIPS in CI and pytest
reports the run as green. That is how a restated contract drifts for weeks while every badge stays
passing: the one test that would have noticed never ran.

So a skip is counted and reported, and with `KATA_REQUIRE_CONTRACTS=1` it fails the run. A developer
with one repository checked out still gets a green suite plus a loud line naming what was not
verified; release CI sets the variable and gets a failure.
"""

from __future__ import annotations

import os

import pytest

REQUIRE_ENV = "KATA_REQUIRE_CONTRACTS"

_skipped_contracts: list[str] = []


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo) -> object:
    outcome = yield
    report = outcome.get_result()
    # BOTH phases. A `skipif` marker skips at setup; a `pytest.skip()` inside the test body skips at
    # call. Watching only setup counted a body-level skip as a pass -- and that is the skip a
    # contract test is most likely to use, because the condition is "is the sibling repository
    # checked out?", which is answered while the test runs.
    if report.when in ("setup", "call") and report.skipped:
        if item.get_closest_marker("contract") and item.nodeid not in _skipped_contracts:
            _skipped_contracts.append(item.nodeid)


def _required() -> bool:
    return os.environ.get(REQUIRE_ENV, "").strip().lower() in {"1", "true", "yes"}


def pytest_terminal_summary(terminalreporter, exitstatus, config) -> None:  # noqa: ANN001
    if not _skipped_contracts:
        return
    required = _required()
    terminalreporter.write_sep("=", "CROSS-REPOSITORY CONTRACTS NOT VERIFIED", red=required)
    for node in _skipped_contracts:
        terminalreporter.write_line(f"  skipped: {node}")
    terminalreporter.write_line(
        f"  {len(_skipped_contracts)} contract test(s) did not run. This suite passing does NOT "
        f"mean the contracts hold."
    )
    terminalreporter.write_line(
        f"  {REQUIRE_ENV} is set, so this is a failure. Check out the sibling repositories."
        if required else
        f"  Set {REQUIRE_ENV}=1 in release CI to make this a failure."
    )


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    """Fail as TESTS_FAILED, not as a usage error.

    Raising from `pytest_terminal_summary` also exits non-zero, but pytest reports it as exit code
    4 -- "usage error" -- which sends whoever reads the CI log looking for a bad command line
    instead of a missing checkout.
    """
    if _skipped_contracts and _required() and exitstatus == 0:
        session.exitstatus = 1
