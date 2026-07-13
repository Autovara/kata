"""Subnet-agnostic round orchestrator (Phase 3 of the multi-subnet refactor).

This is the core King-of-the-Hill round, driven entirely through the
:class:`SubnetPlugin` interface: sample the problems, score the king once, score each
candidate, rank them with the plugin's comparator, and pick the top challenger that
beats the king. It knows nothing about any specific subnet.

Phase 3a introduces it as an additive, independently tested module; Phase 3b routes
SN60's ``run_sn60_round`` through it.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import cmp_to_key

from kata.packages.plugin import (
    ProblemSet,
    ProgressUpdate,
    RunContext,
    ScoreCard,
    ScoringProfile,
    SubnetPlugin,
)


@dataclass(frozen=True)
class ScoredVariant:
    """One scored competitor (the king or a candidate)."""

    label: str
    agent_path: str
    card: ScoreCard


@dataclass(frozen=True)
class RoundOutcome:
    """The generic result of one round -- what the core needs, subnet-agnostic."""

    problems: ProblemSet
    benchmark_identity: str
    scoring_profile: ScoringProfile
    king: ScoredVariant | None
    ranked: list[ScoredVariant]  # best-first, per the plugin's comparator
    winner: ScoredVariant | None  # top-ranked challenger that beats the king


def _score_variant(
    plugin: SubnetPlugin,
    *,
    label: str,
    agent_path: str,
    problems: ProblemSet,
    output_root: str,
    progress,
) -> ScoredVariant:
    context = RunContext(
        output_root=output_root,
        env=plugin.environment_spec(),
        label=label,
        progress=progress,
    )
    raw = plugin.run_candidate(agent_path=agent_path, problems=problems, context=context)
    card = plugin.score(raw, problems)
    if progress is not None:
        progress(
            ProgressUpdate(
                variant=label,
                done=1,
                total=1,
                state="done" if card.passed else "failed",
                metrics=card.metrics,
            )
        )
    return ScoredVariant(label=label, agent_path=agent_path, card=card)


def run_plugin_round(
    plugin: SubnetPlugin,
    *,
    king_agent_path: str | None,
    candidates: list[tuple[str, str]],
    config: dict,
    output_root: str,
    seed: str,
    score_king: bool = True,
    progress=None,
    problems: ProblemSet = None,
) -> RoundOutcome:
    """Run one King-of-the-Hill round through ``plugin`` and return a generic outcome.

    ``candidates`` is a list of ``(label, agent_path)``. The king is scored once (unless
    ``score_king`` is False, e.g. candidate-only recovery), each candidate is scored,
    then they are ranked with ``plugin.compare`` and the winner is the top-ranked
    challenger for which ``plugin.beats_king`` holds. A pre-sampled ``problems`` may be
    passed to avoid re-sampling (e.g. when the caller sized progress from it).
    """
    if problems is None:
        problems = plugin.sample_problems(seed=seed, config=config)
    identity = plugin.benchmark_identity(problems)

    king: ScoredVariant | None = None
    if score_king and king_agent_path is not None:
        king = _score_variant(
            plugin,
            label="king",
            agent_path=king_agent_path,
            problems=problems,
            output_root=output_root,
            progress=progress,
        )

    scored: list[ScoredVariant] = [
        _score_variant(
            plugin,
            label=label,
            agent_path=agent_path,
            problems=problems,
            output_root=output_root,
            progress=progress,
        )
        for label, agent_path in candidates
    ]

    # Best-first per the plugin's comparator. compare(a, b) > 0 means a outranks b.
    ranked = sorted(
        scored,
        key=cmp_to_key(lambda a, b: plugin.compare(a.card, b.card)),
        reverse=True,
    )

    king_card = king.card if king is not None else None
    winner = next(
        (variant for variant in ranked if plugin.beats_king(variant.card, king_card)),
        None,
    )

    return RoundOutcome(
        problems=problems,
        benchmark_identity=identity,
        scoring_profile=plugin.scoring_profile,
        king=king,
        ranked=ranked,
        winner=winner,
    )
