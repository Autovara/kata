"""Subnet-agnostic challenge orchestrator.

This is the core King-of-the-Hill challenge, driven entirely through the
:class:`SubnetPlugin` interface: sample the problems, score the king once, score each
candidate, rank them with the plugin's comparator, and pick the top challenger that
beats the king. It knows nothing about any specific subnet.

Each subnet's challenge runner delegates here; the core knows nothing about any specific
subnet.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import cmp_to_key
from pathlib import Path
from uuid import uuid4

from kata.plugins.contract import (
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
class ChallengeOutcome:
    """The generic result of one challenge -- what the core needs, subnet-agnostic."""

    problems: ProblemSet
    benchmark_identity: str
    scoring_profile: ScoringProfile
    king: ScoredVariant | None
    ranked: list[ScoredVariant]  # best-first, per the plugin's comparator
    winner: ScoredVariant | None  # top-ranked challenger that beats the king


@dataclass(frozen=True)
class GenericChallengeSummary:
    """Promotion record produced by the default, ScoreCard-only challenge path.

    Plugins with a richer native result may keep writing their own summaries.  This
    small common shape means a plugin that only implements the public ScoreCard
    contract can nevertheless be verified and promoted by the normal Kata flow.
    """

    schema_version: int
    run_id: str
    mode: str
    candidate_artifact_hash: str
    king_artifact_hash: str
    validator_model: str
    promotion_ready: bool
    promotion_reason: str


@dataclass(frozen=True)
class GenericChallengeResult:
    """Artifacts and normalized result for the default plugin challenge runner."""

    run_id: str
    output_root: str
    outcome: ChallengeOutcome

    # Preserve the old default ``run_challenge`` ergonomics for callers that
    # inspect its outcome directly rather than serializing it for the bot.
    @property
    def king(self) -> ScoredVariant | None:
        return self.outcome.king

    @property
    def ranked(self) -> list[ScoredVariant]:
        return self.outcome.ranked

    @property
    def winner(self) -> ScoredVariant | None:
        return self.outcome.winner


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


def run_plugin_challenge(
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
) -> ChallengeOutcome:
    """Run one King-of-the-Hill challenge through ``plugin`` and return a generic outcome.

    ``candidates`` is a list of ``(label, agent_path)``. The king is scored once (unless
    ``score_king`` is False -- the lazy-king optimization skips it when no candidate
    qualified for scoring), each candidate is scored, then they are ranked with
    ``plugin.compare`` and the winner is the top-ranked challenger for which
    ``plugin.beats_king`` holds. A pre-sampled ``problems`` may be passed to avoid
    re-sampling (e.g. when the caller sized progress from it).
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

    return ChallengeOutcome(
        problems=problems,
        benchmark_identity=identity,
        scoring_profile=plugin.scoring_profile,
        king=king,
        ranked=ranked,
        winner=winner,
    )


def _card_rank_signals(card: ScoreCard) -> list[dict[str, object]]:
    """The universal one-signal rank contract for a plain :class:`ScoreCard`.

    A specialized plugin can still expose a richer ordered ``rank_signals`` list
    in its own JSON.  The default must not discard ScoreCard's comparable value:
    that value, direction, and threshold are enough for generic continuous
    promotion.
    """
    return [
        {
            "name": "comparable",
            "value": float(card.comparable),
            "higher_better": True,
            "beats_threshold": float(card.beats_threshold),
        }
    ]


def _variant_json(plugin: SubnetPlugin, variant: ScoredVariant) -> dict[str, object]:
    card = variant.card
    return {
        "submission_id": variant.label,
        "artifact_hash": plugin.hash_bundle(Path(variant.agent_path)),
        "passed": bool(card.passed),
        "comparable": float(card.comparable),
        "beats_threshold": float(card.beats_threshold),
        "rank_signals": _card_rank_signals(card),
        "metrics": dict(card.metrics),
    }


def _write_generic_summary(
    *,
    path: Path,
    plugin: SubnetPlugin,
    run_id: str,
    king_hash: str,
    candidate_hash: str,
    promotion_ready: bool,
) -> None:
    summary = GenericChallengeSummary(
        schema_version=1,
        run_id=run_id,
        mode=plugin.mode,
        candidate_artifact_hash=candidate_hash,
        king_artifact_hash=king_hash,
        validator_model=plugin.validator_identity,
        promotion_ready=promotion_ready,
        promotion_reason=(
            "candidate beat the current king"
            if promotion_ready
            else "candidate did not beat the current king"
        ),
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary.__dict__, indent=2, sort_keys=True), encoding="utf-8")


def run_generic_plugin_challenge(
    plugin: SubnetPlugin,
    *,
    king_agent_path: str | None,
    candidates: list[tuple[str, str]],
    config: dict,
    output_root: str,
    run_id: str | None = None,
    progress=None,
) -> GenericChallengeResult:
    """Run and persist the default ScoreCard-only challenge implementation.

    This is deliberately small: it serializes each card as a generic rank signal
    and writes a common summary for every challenger, so continuous promotion can
    later select a challenger using the king's running average without requiring a
    subnet-specific result format.
    """
    resolved_run_id = run_id or f"challenge-{uuid4().hex}"
    resolved_root = Path(output_root).expanduser().resolve() / resolved_run_id
    outcome = run_plugin_challenge(
        plugin,
        king_agent_path=king_agent_path,
        candidates=candidates,
        config=config,
        output_root=str(resolved_root),
        seed=resolved_run_id,
        progress=progress,
    )
    return GenericChallengeResult(
        run_id=resolved_run_id,
        output_root=str(resolved_root),
        outcome=outcome,
    )


def generic_challenge_result_json(plugin: SubnetPlugin, result: GenericChallengeResult) -> dict:
    """Return the persisted generic challenge payload used by CLI and kata-bot."""
    outcome = result.outcome
    root = Path(result.output_root)
    king_hash = (
        plugin.hash_bundle(Path(outcome.king.agent_path)) if outcome.king is not None else ""
    )
    king_card = outcome.king.card if outcome.king is not None else None
    candidate_summary_paths: dict[str, str] = {}
    for variant in outcome.ranked:
        candidate_hash = plugin.hash_bundle(Path(variant.agent_path))
        path = root / variant.label / "challenge_summary.json"
        _write_generic_summary(
            path=path,
            plugin=plugin,
            run_id=result.run_id,
            king_hash=king_hash,
            candidate_hash=candidate_hash,
            promotion_ready=plugin.beats_king(variant.card, king_card),
        )
        candidate_summary_paths[variant.label] = str(path)
    entries = [_variant_json(plugin, variant) for variant in outcome.ranked]
    payload: dict[str, object] = {
        "run_id": result.run_id,
        "competition_mode": "king_duel",
        "king": _variant_json(plugin, outcome.king) if outcome.king is not None else None,
        "entries": [
            {
                **entry,
                "beats_king": plugin.beats_king(variant.card, king_card),
                "selected_winner": (
                    outcome.winner is not None and variant.label == outcome.winner.label
                ),
                "challenge_summary_path": candidate_summary_paths[variant.label],
            }
            for entry, variant in zip(entries, outcome.ranked, strict=True)
        ],
        "winner_submission_id": outcome.winner.label if outcome.winner is not None else None,
        "winner_challenge_summary_path": (
            candidate_summary_paths.get(outcome.winner.label)
            if outcome.winner is not None
            else None
        ),
        "promotion_ready": outcome.winner is not None,
        "promotion_reason": (
            "candidate beat the current king"
            if outcome.winner is not None
            else "no candidate beat the current king"
        ),
    }
    result_path = root / "challenge_result.json"
    result_path.parent.mkdir(parents=True, exist_ok=True)
    result_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return payload


def load_generic_challenge_summary(path: str | Path) -> GenericChallengeSummary:
    """Load the common promotion fields emitted by ``run_generic_plugin_challenge``."""
    payload = json.loads(Path(path).expanduser().resolve().read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Generic challenge summary must be a JSON object.")
    return GenericChallengeSummary(
        schema_version=int(payload["schema_version"]),
        run_id=str(payload["run_id"]),
        mode=str(payload["mode"]),
        candidate_artifact_hash=str(payload["candidate_artifact_hash"]),
        king_artifact_hash=str(payload["king_artifact_hash"]),
        validator_model=str(payload["validator_model"]),
        promotion_ready=bool(payload["promotion_ready"]),
        promotion_reason=str(payload["promotion_reason"]),
    )
