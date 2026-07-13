"""Build SN60's round artifacts from a generic RoundOutcome (Phase 3b).

``run_sn60_plugin_round`` runs a full SN60 round entirely through the subnet-agnostic
:func:`~kata.core.round.run_plugin_round` orchestrator and then reconstructs the exact
``Sn60RoundResult`` (and winner challenge summary + round_summary.json) from the generic
outcome. It is proven contract-equivalent to the legacy ``run_sn60_round`` and is the
path the core will eventually call. Progress emission and the optional execution
screener are handled by the production cutover, not here.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from kata.core.round import RoundOutcome, run_plugin_round
from kata.evaluators.sn60_bitsec import Sn60DuelSummary, write_sn60_duel_summary
from kata.validator_system.challenge import (
    DEFAULT_SN60_ROUND_SCHEMA_VERSION,
    Sn60RoundEntry,
    Sn60RoundResult,
    build_sn60_round_id,
    sn60_duel_to_challenge_summary,
    write_challenge_summary,
    write_sn60_round_summary,
)

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
) -> Sn60RoundResult:
    """Reconstruct the SN60 round result from a generic outcome and write it."""
    problems: Sn60Problems = outcome.problems
    king_card = outcome.king.card if outcome.king is not None else None

    entries = [
        Sn60RoundEntry(
            submission_id=variant.label,
            artifact_path=str(Path(variant.agent_path).expanduser().resolve()),
            artifact_hash=variant.card.payload.artifact_hash,
            beats_king=(
                None if candidate_only else plugin.beats_king(variant.card, king_card)
            ),
            duel_run_id=f"{run_id}-{variant.label}",
            candidate=variant.card.payload,
            selected_winner=(
                outcome.winner is not None and variant.label == outcome.winner.label
            ),
            screening_result=None,
        )
        for variant in outcome.ranked
    ]

    winner_challenge_summary_path: str | None = None
    if outcome.winner is not None and not candidate_only and outcome.king is not None:
        duel = _winner_duel_summary(outcome, run_id=run_id, output_root=output_root)
        duel_root = Path(duel.output_root)
        duel_root.mkdir(parents=True, exist_ok=True)
        write_sn60_duel_summary(duel_root / "duel_summary.json", duel)
        summary = sn60_duel_to_challenge_summary(duel, lane_id=plugin.pack)
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
    )
    write_sn60_round_summary(Path(output_root) / "round_summary.json", result)
    return result


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
) -> Sn60RoundResult:
    """Run a full SN60 round through the generic orchestrator and build its result.

    When ``progress_path`` is given, live progress is written there in the board's
    ``round-progress.json`` format via the SN60 progress bridge.
    """
    plugin = plugin or Sn60BitsecPlugin()
    run_id = run_id or build_sn60_round_id()
    round_root = Path(output_root).expanduser().resolve() / run_id
    round_root.mkdir(parents=True, exist_ok=False)

    # Pre-sample so the progress writer can be sized up front; pass it back into the
    # orchestrator to avoid re-sampling.
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

    outcome = run_plugin_round(
        plugin,
        king_agent_path=king_artifact_path,
        candidates=candidates,
        config=config,
        output_root=str(round_root),
        seed=run_id,
        score_king=score_king,
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
    )
