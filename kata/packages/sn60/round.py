"""Build SN60's round artifacts from a generic RoundOutcome (Phase 3b).

``run_sn60_plugin_round`` runs a full SN60 round entirely through the subnet-agnostic
:func:`~kata.core.round.run_plugin_round` orchestrator and reconstructs the exact
``Sn60RoundResult`` (winner challenge summary + round_summary.json + board progress).
It preserves SN60's optional execution screener and lazy-king behavior, so it is a
drop-in for the legacy ``run_sn60_round``.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from kata.core.round import RoundOutcome, ScoredVariant, run_plugin_round
from kata.evaluators.sn60_bitsec import (
    Sn60DuelSummary,
    hash_bundle_root,
    write_sn60_duel_summary,
)
from kata.packages.sn60.validator_system.challenge import (
    DEFAULT_SN60_ROUND_SCHEMA_VERSION,
    Sn60RoundEntry,
    Sn60RoundResult,
    _sn60_variant_progress,
    build_sn60_round_id,
    failed_candidate_variant_summary,
    run_optional_sn60_screener_project,
    skipped_king_variant_summary,
    sn60_candidate_only_to_challenge_summary,
    sn60_duel_to_challenge_summary,
    sn60_variant_rank,
    write_challenge_summary,
    write_sn60_round_summary,
)
from kata.packages.sn60.validator_system.screening import screening_result_payload

from .plugin import Sn60BitsecPlugin, Sn60Problems
from .progress import Sn60RoundProgress


def _winner_duel_summary(
    outcome: RoundOutcome, *, run_id: str, output_root: str
) -> Sn60DuelSummary:
    """A single-duel summary (king vs winner) for the winner's challenge summary."""
    problems: Sn60Problems = outcome.problems
    winner = outcome.winner
    winner_root = Path(output_root) / winner.label
    return Sn60DuelSummary(
        schema_version=DEFAULT_SN60_ROUND_SCHEMA_VERSION,
        run_id=f"{run_id}-{winner.label}",
        created_at=datetime.now(UTC).isoformat(),
        output_root=str(winner_root),
        project_keys=list(problems.project_keys),
        replicas_per_project=problems.replicas_per_project,
        sandbox_source=problems.sandbox_source,
        king=outcome.king.card.payload,
        candidate=winner.card.payload,
    )


def build_sn60_round_result(
    outcome: RoundOutcome,
    plugin: Sn60BitsecPlugin,
    *,
    run_id: str,
    output_root: str,
    candidate_only: bool = False,
    screened_out: list[ScoredVariant] | None = None,
    screening_payloads: dict[str, dict] | None = None,
    screener_run_ids: dict[str, str] | None = None,
    screened_labels: frozenset[str] = frozenset(),
    king_skipped_reason: str | None = None,
    king_artifact_path: str | None = None,
    king_artifact_hash: str | None = None,
) -> Sn60RoundResult:
    """Reconstruct the SN60 round result from a generic outcome and write it.

    ``screened_out`` are candidates that failed the execution screener (never scored);
    they are merged in and ranked with the scored candidates, exactly like the legacy
    path.
    """
    screened_out = screened_out or []
    screening_payloads = screening_payloads or {}
    screener_run_ids = screener_run_ids or {}
    problems: Sn60Problems = outcome.problems
    king_card = outcome.king.card if outcome.king is not None else None

    # Rank scored + screener-failed candidates together by the SN60 comparator.
    all_variants = [*outcome.ranked, *screened_out]
    all_variants.sort(key=lambda v: sn60_variant_rank(v.card.payload), reverse=True)

    entries = []
    for variant in all_variants:
        if variant.label in screened_labels:
            beats_king = None if candidate_only else False
        else:
            beats_king = None if candidate_only else plugin.beats_king(variant.card, king_card)
        entries.append(
            Sn60RoundEntry(
                submission_id=variant.label,
                artifact_path=str(Path(variant.agent_path).expanduser().resolve()),
                artifact_hash=variant.card.payload.artifact_hash,
                beats_king=beats_king,
                duel_run_id=screener_run_ids.get(variant.label)
                or f"{run_id}-{variant.label}",
                candidate=variant.card.payload,
                selected_winner=(
                    outcome.winner is not None and variant.label == outcome.winner.label
                ),
                screening_result=screening_payloads.get(variant.label),
            )
        )

    resolved_reason = (
        king_skipped_reason
        or "Candidate-only recovery mode was enabled by the maintainer; "
        "the current king was not evaluated."
    )
    winner_challenge_summary_path: str | None = None
    if outcome.winner is not None and candidate_only:
        winner_challenge_summary_path = _write_candidate_only_winner_summary(
            outcome,
            plugin,
            run_id=run_id,
            output_root=output_root,
            king_artifact_path=king_artifact_path or "",
            king_artifact_hash=king_artifact_hash or "",
            reason=resolved_reason,
        )
    elif outcome.winner is not None and outcome.king is not None:
        duel = _winner_duel_summary(outcome, run_id=run_id, output_root=output_root)
        duel_root = Path(duel.output_root)
        duel_root.mkdir(parents=True, exist_ok=True)
        write_sn60_duel_summary(duel_root / "duel_summary.json", duel)
        summary = sn60_duel_to_challenge_summary(
            duel,
            lane_id=plugin.pack,
            screening_result=screening_payloads.get(outcome.winner.label),
        )
        summary_path = duel_root / "challenge_summary.json"
        write_challenge_summary(summary_path, summary)
        winner_challenge_summary_path = str(summary_path)

    if candidate_only:
        promotion_reason = (
            f"{outcome.winner.label} won candidate-only recovery mode; the current "
            "SN60 king was not evaluated"
            if outcome.winner is not None
            else (
                "No candidate found a true-positive vulnerability in candidate-only "
                "recovery mode, so no new king was promoted."
            )
        )
    else:
        promotion_reason = (
            f"{outcome.winner.label} beat the current SN60 king"
            if outcome.winner is not None
            else "no candidate beat the current SN60 king"
        )

    result = Sn60RoundResult(
        schema_version=DEFAULT_SN60_ROUND_SCHEMA_VERSION,
        run_id=run_id,
        created_at=datetime.now(UTC).isoformat(),
        output_root=str(output_root),
        project_keys=list(problems.project_keys),
        replicas_per_project=problems.replicas_per_project,
        sandbox_source=problems.sandbox_source,
        king=king_card.payload if king_card is not None else None,
        entries=entries,
        winner_submission_id=outcome.winner.label if outcome.winner is not None else None,
        promotion_ready=outcome.winner is not None,
        promotion_reason=promotion_reason,
        winner_challenge_summary_path=winner_challenge_summary_path,
        competition_mode="candidate_only" if candidate_only else "king_duel",
        king_skipped_reason=resolved_reason if candidate_only else None,
    )
    write_sn60_round_summary(Path(output_root) / "round_summary.json", result)
    return result


def _write_candidate_only_winner_summary(
    outcome: RoundOutcome,
    plugin: Sn60BitsecPlugin,
    *,
    run_id: str,
    output_root: str,
    king_artifact_path: str,
    king_artifact_hash: str,
    reason: str,
) -> str:
    """Write the candidate-only winner's challenge summary (king is skipped)."""
    problems: Sn60Problems = outcome.problems
    winner = outcome.winner
    winner_root = Path(output_root) / winner.label
    winner_root.mkdir(parents=True, exist_ok=True)

    # The "duel" here pairs the winner against a skipped (unscored) king so the
    # challenge summary's run_summary_path resolves to a well-formed duel summary.
    duel = Sn60DuelSummary(
        schema_version=DEFAULT_SN60_ROUND_SCHEMA_VERSION,
        run_id=f"{run_id}-{winner.label}",
        created_at=datetime.now(UTC).isoformat(),
        output_root=str(winner_root),
        project_keys=list(problems.project_keys),
        replicas_per_project=problems.replicas_per_project,
        sandbox_source=problems.sandbox_source,
        king=skipped_king_variant_summary(
            king_artifact_path=king_artifact_path,
            king_artifact_hash=king_artifact_hash,
        ),
        candidate=winner.card.payload,
    )
    candidate_summary_path = winner_root / "candidate_summary.json"
    write_sn60_duel_summary(candidate_summary_path, duel)

    summary = sn60_candidate_only_to_challenge_summary(
        candidate=winner.card.payload,
        candidate_summary_path=candidate_summary_path,
        king_artifact_path=king_artifact_path,
        king_artifact_hash=king_artifact_hash,
        sandbox_source=problems.sandbox_source,
        project_keys=list(problems.project_keys),
        replicas_per_project=problems.replicas_per_project,
        lane_id=plugin.pack,
        reason=reason,
    )
    summary_path = winner_root / "candidate_only_challenge_summary.json"
    write_challenge_summary(summary_path, summary)
    return str(summary_path)


def run_sn60_plugin_round(
    *,
    king_artifact_path: str,
    candidates: list[tuple[str, str]],
    config: dict,
    output_root: str,
    run_id: str | None = None,
    score_king: bool = True,
    plugin: Sn60BitsecPlugin | None = None,
    progress_path: str | None = None,
    king_skipped_reason: str | None = None,
) -> Sn60RoundResult:
    """Run a full SN60 round through the generic orchestrator and build its result.

    Screens each candidate (env-gated) before scoring, scores the king lazily (only
    when a candidate qualifies), and writes board-format live progress when
    ``progress_path`` is set.
    """
    plugin = plugin or Sn60BitsecPlugin()
    run_id = run_id or build_sn60_round_id()
    round_root = Path(output_root).expanduser().resolve() / run_id
    round_root.mkdir(parents=True, exist_ok=False)

    problems: Sn60Problems = plugin.sample_problems(seed=run_id, config=config)
    writer = (
        Sn60RoundProgress(
            run_id=run_id,
            project_keys=problems.project_keys,
            candidate_labels=[label for label, _ in candidates],
            per_variant_total=len(problems.project_keys) * problems.replicas_per_project,
            progress_path=progress_path,
            candidate_only=not score_king,
        )
        if progress_path
        else None
    )

    # Optional execution screener: partition candidates before scoring.
    execution_hook = plugin.resolve_execution_hook(problems.sandbox_source)
    qualified: list[tuple[str, str]] = []
    screened_out: list[ScoredVariant] = []
    screening_payloads: dict[str, dict] = {}
    screener_run_ids: dict[str, str] = {}
    screened_labels: set[str] = set()
    for label, agent_path in candidates:
        screening = run_optional_sn60_screener_project(
            candidate_artifact_path=agent_path,
            project_keys=problems.project_keys,
            output_root=str(round_root / label / "screening"),
            sandbox_source=problems.sandbox_source,
            execution_hook=execution_hook,
        )
        if screening is None:
            qualified.append((label, agent_path))
            continue
        payload = screening_result_payload(screening)
        screening_payloads[label] = payload
        if screening.passed:
            qualified.append((label, agent_path))
            continue
        candidate_root = Path(agent_path).expanduser().resolve()
        failed_summary = failed_candidate_variant_summary(
            candidate_artifact_path=str(candidate_root),
            candidate_artifact_hash=hash_bundle_root(candidate_root),
        )
        screened_out.append(
            ScoredVariant(
                label=label,
                agent_path=str(candidate_root),
                card=plugin.card_for_summary(failed_summary),
            )
        )
        screener_run_ids[label] = screening.run_id
        screened_labels.add(label)
        if writer is not None:
            writer.mark_screened_out(
                label,
                screening_result=payload,
                snapshot=_sn60_variant_progress(failed_summary),
            )

    # Lazy king: only score the king when a candidate qualified, so a round where
    # everyone is screened out never runs (or reports) the king.
    score_king_effective = score_king and bool(qualified)

    outcome = run_plugin_round(
        plugin,
        king_agent_path=king_artifact_path,
        candidates=qualified,
        config=config,
        output_root=str(round_root),
        seed=run_id,
        score_king=score_king_effective,
        progress=writer.on_update if writer is not None else None,
        problems=problems,
    )

    if writer is not None:
        writer.finalize(outcome, plugin)

    return build_sn60_round_result(
        outcome,
        plugin,
        run_id=run_id,
        output_root=str(round_root),
        candidate_only=not score_king,
        screened_out=screened_out,
        screening_payloads=screening_payloads,
        screener_run_ids=screener_run_ids,
        screened_labels=frozenset(screened_labels),
        king_skipped_reason=king_skipped_reason,
        king_artifact_path=str(Path(king_artifact_path).expanduser().resolve()),
        king_artifact_hash=hash_bundle_root(Path(king_artifact_path).expanduser().resolve()),
    )
