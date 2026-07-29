from __future__ import annotations

import os
from pathlib import Path

from kata.screening.models import (
    ScreeningDecision,
    ScreeningFinding,
    dedupe_findings,
)
from kata.screening.rules import (
    screen_bundle_python_sources,
    screen_bundle_static_policy,
    screen_submission_bundle_files,
)
from kata.screening.similarity import screen_current_king_copycat
from kata.submissions.bundle import load_bundle_files

STRICT_REPLAY_ENV = "KATA_SCREENING_STRICT_REPLAY"
REVIEW_MODE_ENV = "KATA_SCREENING_REVIEW_MODE"


#: Rule id for "the lane's own gate could not run". Not a miner-facing defect: it means this
#: deployment could not resolve the subnet's plugin, so only the generic anti-cheat ran.
UNRESOLVED_PLUGIN_RULE = "screening.subnet_plugin_unresolved"


def subnet_gate_unavailable_finding(subnet_pack: str) -> ScreeningFinding:
    return ScreeningFinding(
        rule_id=UNRESOLVED_PLUGIN_RULE,
        severity="review",
        path=None,
        line=None,
        reason=(
            f"the {subnet_pack} plugin could not be resolved, so that subnet's own screening did "
            f"not run. Only the generic anti-cheat checks were applied, which is not enough to "
            f"admit a submission to this lane. This is a deployment fault, not a defect in the "
            f"submission: install the lane's plugin and re-screen"
        ),
        evidence=f"plugin_for_pack({subnet_pack!r}) returned None",
    )


def _plugin_static_screen_findings(
    *,
    submission_root: Path,
    subnet_pack: str | None,
    mode: str,
) -> list:
    """Per-subnet static screening findings from the lane's plugin, if any.

    Resolves the lane's plugin in-process by ``(pack, mode)`` and runs its
    ``static_screen``. Lazily imported to avoid an import cycle. Returns an empty
    list when the lane has no plugin or the plugin adds no static findings.
    """
    from kata.plugins.discovery import plugin_for_pack

    plugin = plugin_for_pack(subnet_pack, mode)
    if plugin is None:
        return []
    findings = plugin.static_screen(str(submission_root))
    return list(findings) if findings else []


def _plugin_benchmark_review(
    *,
    bundle_files: dict[str, str],
    subnet_pack: str | None,
    mode: str,
    strict: bool,
) -> tuple[list, list, float]:
    """Subnet anti-memorization (benchmark-replay) review from the lane's plugin.

    Returns ``(reject_findings, review_findings, score)`` -- all empty for lanes with no
    plugin or no benchmark review.
    """
    from kata.plugins.discovery import plugin_for_pack

    plugin = plugin_for_pack(subnet_pack, mode)
    if plugin is None:
        return [], [], 0.0
    rejects, reviews, score = plugin.benchmark_review(bundle_files, strict=strict)
    return list(rejects), list(reviews), score


def _plugin_llm_review(
    *,
    submission_root: Path,
    bundle_files: dict[str, str],
    decision,
    subnet_pack: str | None,
    mode: str,
) -> tuple[list, list]:
    """Optional subnet LLM review of a suspicious submission from the lane's plugin.

    Returns ``(findings, notes)`` -- both empty for lanes with no plugin or no LLM review.
    """
    from kata.plugins.discovery import plugin_for_pack

    plugin = plugin_for_pack(subnet_pack, mode)
    if plugin is None:
        return [], []
    findings, notes = plugin.llm_review(
        submission_root=submission_root, bundle_files=bundle_files, decision=decision
    )
    return list(findings), list(notes)


def screen_submission(
    *,
    submission_root: Path,
    public_root: Path | None = None,
    mode: str = "miner",
    subnet_pack: str | None = None,
    enable_review: bool | None = None,
    strict_replay: bool | None = None,
    check_current_king: bool = True,
) -> ScreeningDecision:
    """Run the screening subsystem for a candidate submission.

    Generic anti-cheat runs for every lane; subnet-specific static and benchmark-replay
    checks are dispatched through the lane's plugin.
    """
    if mode != "miner":
        return ScreeningDecision(status="pass")

    # FAIL CLOSED on a pack whose plugin this process cannot resolve.
    #
    # The three helpers below each return empty when `plugin_for_pack` yields None, so a lane whose
    # plugin is missing used to be screened by the GENERIC anti-cheat alone and then reported
    # `pass` -- with no finding and no note. A submission that a subnet's own rules would reject
    # (SN60's canned-report rule, say) came back clean and was labelled `kata:pending`.
    #
    # "I could not check" must not be spelled the same way as "I checked and it is fine". It is
    # raised as REVIEW rather than REJECT deliberately: the fault is in the deployment, not in the
    # submission, so a human is asked rather than a contributor's PR closed.
    from kata.plugins.discovery import plugin_for_pack

    if subnet_pack and plugin_for_pack(subnet_pack, mode) is None:
        return ScreeningDecision(
            status="review",
            review_reasons=[subnet_gate_unavailable_finding(subnet_pack)],
        )

    bundle_files = load_bundle_files(submission_root)
    reject_findings = []
    reject_findings.extend(screen_submission_bundle_files(submission_root))
    reject_findings.extend(screen_bundle_python_sources(bundle_files))
    reject_findings.extend(screen_bundle_static_policy(bundle_files))
    # Subnet-specific static checks (a subnet's own rules) run only for the
    # lane's own plugin; the generic anti-cheat checks above run for every subnet.
    reject_findings.extend(
        _plugin_static_screen_findings(
            submission_root=submission_root,
            subnet_pack=subnet_pack,
            mode=mode,
        )
    )
    bench_rejects, review_findings, review_score = _plugin_benchmark_review(
        bundle_files=bundle_files,
        subnet_pack=subnet_pack,
        mode=mode,
        strict=resolve_strict_replay(strict_replay),
    )
    reject_findings.extend(bench_rejects)
    # An explicit first-king bootstrap is screened for all static and subnet policy gates, but
    # it cannot meaningfully be compared with the destination it is about to seed.
    if check_current_king:
        copycat_rejects, copycat_reviews, copycat_score = screen_current_king_copycat(
            submission_root=submission_root,
            bundle_files=bundle_files,
            subnet_pack=subnet_pack,
            mode=mode,
            public_root=str(public_root) if public_root is not None else None,
        )
        reject_findings.extend(copycat_rejects)
        review_findings.extend(copycat_reviews)
        review_score += copycat_score
    notes: list[ScreeningFinding] = []
    reject_findings = dedupe_findings(reject_findings)
    review_findings = dedupe_findings(review_findings)
    if reject_findings:
        return ScreeningDecision(
            status="reject",
            reject_reasons=reject_findings,
            review_reasons=review_findings,
            notes=notes,
            score=review_score,
        )
    llm_findings, llm_notes = _plugin_llm_review(
        submission_root=submission_root,
        bundle_files=bundle_files,
        decision=ScreeningDecision(
            status="review" if review_findings else "pass",
            review_reasons=review_findings,
            score=review_score,
        ),
        subnet_pack=subnet_pack,
        mode=mode,
    )
    review_findings.extend(llm_findings)
    review_findings = dedupe_findings(review_findings)
    notes.extend(llm_notes)
    if review_findings and resolve_review_mode(enable_review):
        return ScreeningDecision(
            status="review",
            review_reasons=review_findings,
            notes=notes,
            score=review_score,
        )
    return ScreeningDecision(
        status="pass",
        review_reasons=review_findings,
        notes=notes,
        score=review_score,
    )


def resolve_strict_replay(value: bool | None) -> bool:
    if value is not None:
        return value
    raw = os.environ.get(STRICT_REPLAY_ENV, "")
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def resolve_review_mode(value: bool | None) -> bool:
    if value is not None:
        return value
    raw = os.environ.get(REVIEW_MODE_ENV, "")
    return raw.strip().lower() in {"1", "true", "yes", "on"}
