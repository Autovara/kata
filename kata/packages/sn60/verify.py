"""SN60-specific challenge verification: benchmark currency + candidate-only checks.

Called by the generic verifier via the plugin's ``benchmark_is_current`` /
``extra_verification_reasons`` seams so ``submission_system`` stays subnet-blind.
Relocates to ``kata-sn60`` in Phase 3.
"""

from __future__ import annotations

from kata.packages.sn60.promotion import load_sn60_duel_summary
from kata.provenance import short_hash
from kata.state_system.lane import benchmark_snapshot_path, load_benchmark_snapshot


def sn60_benchmark_is_current(*, lane_id, summary, public_root=None) -> bool:
    """Freshness against the lane's recorded benchmark snapshot version.

    Gated on the benchmark snapshot version (scorer + sandbox commit) only -- NOT the
    per-run ``freshness_fingerprint`` (which bundles the randomly sampled project keys and
    is never committed, so comparing it would flag every winner as stale). King and
    submission identity are verified separately by the generic verifier.
    """
    if not benchmark_snapshot_path(lane_id, public_root=public_root).exists():
        return False
    snapshot = load_benchmark_snapshot(lane_id, public_root=public_root)
    expected_version = f"{snapshot.scorer_version}@{short_hash(snapshot.sandbox_commit_hash)}"
    return summary.evaluator_version == expected_version


def sn60_extra_verification_reasons(*, lane_id, summary, public_root=None) -> list[str]:
    """SN60-specific reject reasons: candidate-only recovery needs a true positive."""
    reasons: list[str] = []
    if summary.primary.competition_mode == "candidate_only":
        duel_summary = load_sn60_duel_summary(summary.primary.run_summary_path)
        if duel_summary.candidate.true_positives <= 0:
            reasons.append(
                "Candidate-only recovery promotion requires at least one true-positive "
                "vulnerability."
            )
    return reasons
