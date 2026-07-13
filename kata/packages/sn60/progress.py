"""SN60 live-progress writer for the plugin-driven round (Phase 3b progress bridge).

The generic orchestrator emits subnet-agnostic :class:`ProgressUpdate`s; this writer
folds them into the exact ``round-progress.json`` structure the dashboard reads today
(king + per-candidate entries, per-problem breakdowns, running metrics). Keeping the
board-specific format here means the core stays generic while the live view is
unchanged.
"""

from __future__ import annotations

from kata.core.round import RoundOutcome
from kata.packages.plugin import ProgressUpdate
from kata.validator_system.challenge import (
    DEFAULT_SN60_ROUND_SCHEMA_VERSION,
    _write_progress_atomic,
)

# Structural keys owned by the writer; metric keys from an update merge over the rest.
_STRUCTURAL_KEYS = frozenset({"done", "total", "state", "submission_id"})


class Sn60RoundProgress:
    """Maintains and atomically writes the board's round-progress.json."""

    def __init__(
        self,
        *,
        run_id: str,
        project_keys: list[str],
        candidate_labels: list[str],
        per_variant_total: int,
        progress_path: str,
        candidate_only: bool = False,
    ) -> None:
        self._path = progress_path
        self._progress: dict = {
            "schema_version": DEFAULT_SN60_ROUND_SCHEMA_VERSION,
            "state": "executing",
            "run_id": run_id,
            "competition_mode": "candidate_only" if candidate_only else "king_duel",
            "project_keys": list(project_keys),
            "king": {
                "done": 0,
                "total": 0 if candidate_only else per_variant_total,
                "state": "skipped" if candidate_only else "scoring",
            },
            "candidates": [
                {
                    "submission_id": label,
                    "done": 0,
                    "total": per_variant_total,
                    "state": "queued",
                }
                for label in candidate_labels
            ],
        }
        self._by_label = {c["submission_id"]: c for c in self._progress["candidates"]}
        self._write()

    def _target(self, variant: str) -> dict:
        if variant == "king":
            return self._progress["king"]
        return self._by_label[variant]

    def on_update(self, update: ProgressUpdate) -> None:
        """Fold one orchestrator progress tick into the board structure."""
        target = self._target(update.variant)
        if update.state == "done":
            # The generic per-variant "done" tick carries a coarse done/total (1/1);
            # mark the variant complete against its own replica total instead.
            target["done"] = target.get("total", update.total)
            target["state"] = "done"
        elif update.state == "failed":
            target["state"] = "failed"
        else:
            target["done"] = update.done
            target["state"] = "scoring"
        for key, value in update.metrics.items():
            if key not in _STRUCTURAL_KEYS:
                target[key] = value
        self._write()

    def finalize(self, outcome: RoundOutcome, plugin) -> None:
        """Mark the round completed and record the winner + per-candidate beats_king."""
        king_card = outcome.king.card if outcome.king is not None else None
        for variant in outcome.ranked:
            entry = self._by_label.get(variant.label)
            if entry is None:
                continue
            entry["beats_king"] = (
                None if king_card is None else plugin.beats_king(variant.card, king_card)
            )
        self._progress["state"] = "completed"
        self._progress["winner_submission_id"] = (
            outcome.winner.label if outcome.winner is not None else None
        )
        self._write()

    def _write(self) -> None:
        _write_progress_atomic(self._progress, self._path)
