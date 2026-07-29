"""Per-subnet static screening dispatches through the lane's plugin.

Generic anti-cheat checks stay in the core screener; a lane's plugin adds its own
subnet-specific static findings via ``static_screen``. The plugin is resolved in-process
by ``(pack, mode)`` -- no pack-registry file required. (Phase 2a moved SN60's static rules
out of the unconditional core path and into the SN60 plugin.)
"""

from __future__ import annotations

from pathlib import Path

import pytest

from kata.plugins import (
    EnvSpec,
    ScoreCard,
    ScoringProfile,
    SubnetPlugin,
    clear_registry,
    register_plugin,
)
from kata.plugins.discovery import load_builtin_plugins
from kata.screening.engine import _plugin_static_screen_findings


class _ScreeningPlugin(SubnetPlugin):
    evaluator_id = "t_eval"
    pack = "t__pack"
    mode = "miner"
    scoring_profile = ScoringProfile.DETERMINISTIC
    validator_identity = "t-v"

    def environment_spec(self) -> EnvSpec:
        return EnvSpec()

    def sample_problems(self, *, seed, config):
        return []

    def benchmark_identity(self, problems) -> str:
        return "b"

    def run_candidate(self, *, agent_path, problems, context):
        return None

    def score(self, raw, problems) -> ScoreCard:
        return ScoreCard(comparable=0.0, passed=True)

    def compare(self, a, b) -> int:
        return 0

    def beats_king(self, candidate, king) -> bool:
        return False

    def static_screen(self, submission_path):
        return ["custom subnet finding"]


@pytest.fixture(autouse=True)
def _restore_registry():
    yield
    clear_registry()
    load_builtin_plugins()


def test_static_screen_dispatches_to_lane_plugin(tmp_path: Path) -> None:
    register_plugin(_ScreeningPlugin())
    findings = _plugin_static_screen_findings(
        submission_root=tmp_path, subnet_pack="t__pack", mode="miner"
    )
    assert findings == ["custom subnet finding"]


def test_static_screen_noop_for_unknown_or_missing_lane(tmp_path: Path) -> None:
    # An unregistered pack resolves to no plugin -> no subnet-specific findings.
    assert (
        _plugin_static_screen_findings(
            submission_root=tmp_path, subnet_pack="nope__pack", mode="miner"
        )
        == []
    )
    # No subnet_pack -> no dispatch at all.
    assert (
        _plugin_static_screen_findings(
            submission_root=tmp_path, subnet_pack=None, mode="miner"
        )
        == []
    )


# --- the gate must not silently not-run ----------------------------------------------------------
#
# `_plugin_static_screen_findings` returning [] for an unresolvable pack is correct AT THAT LEVEL --
# it is a dispatch helper. The bug was that `screen_submission` treated that empty result as "no
# subnet findings" and reported `pass`, so a lane whose plugin was missing got the generic
# anti-cheat only and its submission was labelled `kata:pending`.
#
# A submission a subnet's own rules would reject came back clean. "I could not check" has to be a
# different outcome from "I checked and it is fine".


def _bundle(root: Path, pack: str) -> Path:
    import json

    root.mkdir(parents=True, exist_ok=True)
    (root / "agent.py").write_text(
        "def agent_main(project_dir=None, inference_api=None):\n"
        "    return {'vulnerabilities': [{'severity': 'high', 'title': 'canned'}]}\n",
        encoding="utf-8",
    )
    (root / "agent_manifest.json").write_text(
        json.dumps({"schema_version": 1, "runtime": "python", "entrypoint": "agent.py"}),
        encoding="utf-8",
    )
    (root / "submission.json").write_text(
        json.dumps(
            {
                "schema_version": 2,
                "subnet_pack": pack,
                "mode": "miner",
                "submission_id": "alice-20260729-01",
                "created_at": "2026-07-29T00:00:00Z",
                "author": "alice",
                "title": "t",
                "notes": "n",
            }
        ),
        encoding="utf-8",
    )
    return root


def test_an_unresolvable_subnet_plugin_is_not_a_pass(tmp_path: Path) -> None:
    """THE regression. This returned `pass` with zero findings and zero notes."""
    from kata.screening.engine import UNRESOLVED_PLUGIN_RULE, screen_submission

    decision = screen_submission(
        submission_root=_bundle(tmp_path / "sub", "nope__pack"),
        subnet_pack="nope__pack",
        mode="miner",
        check_current_king=False,
    )
    assert decision.status == "review", decision.status
    assert not decision.passed
    assert [f.rule_id for f in decision.review_reasons] == [UNRESOLVED_PLUGIN_RULE]


def test_the_unavailable_gate_blames_the_deployment_not_the_miner(tmp_path: Path) -> None:
    """Held for a human, not closed as invalid: the fault is a missing plugin, and closing a
    contributor's PR for a deployment fault would be wrong."""
    from kata.screening.engine import screen_submission

    decision = screen_submission(
        submission_root=_bundle(tmp_path / "sub", "nope__pack"),
        subnet_pack="nope__pack",
        mode="miner",
        check_current_king=False,
    )
    assert decision.status != "reject"
    assert not decision.reject_reasons
    reason = decision.review_reasons[0].reason
    assert "deployment fault" in reason
    assert "nope__pack" in reason


class _CleanPlugin(_ScreeningPlugin):
    """Same lane, no static findings.

    ``_ScreeningPlugin.static_screen`` returns a plain string. That is fine for the dispatch-level
    test above, which only checks what the helper passes through -- but production extends those
    findings into ``dedupe_findings``, which reads ``.rule_id``. The fixture has never matched the
    real contract; going end-to-end here is what surfaced it.
    """

    def static_screen(self, submission_path):
        return []


def test_a_resolvable_plugin_still_screens_normally(tmp_path: Path) -> None:
    """The guard must not fire for a lane whose plugin IS present, or everything would hold."""
    from kata.screening.engine import UNRESOLVED_PLUGIN_RULE, screen_submission

    register_plugin(_CleanPlugin())
    decision = screen_submission(
        submission_root=_bundle(tmp_path / "sub", "t__pack"),
        subnet_pack="t__pack",
        mode="miner",
        check_current_king=False,
    )
    assert UNRESOLVED_PLUGIN_RULE not in [
        f.rule_id for f in (decision.review_reasons + decision.reject_reasons)
    ]


def test_a_submission_with_no_pack_is_unaffected(tmp_path: Path) -> None:
    """No pack means nothing to dispatch to; the generic screen stands on its own."""
    from kata.screening.engine import UNRESOLVED_PLUGIN_RULE, screen_submission

    register_plugin(_CleanPlugin())
    decision = screen_submission(
        submission_root=_bundle(tmp_path / "sub", "t__pack"),
        subnet_pack=None,
        mode="miner",
        check_current_king=False,
    )
    assert UNRESOLVED_PLUGIN_RULE not in [f.rule_id for f in decision.review_reasons]
