"""Persistent per-project cache of the SN60 king's benchmark scores.

The king's score on a given project is stable for a fixed king artifact and a
fixed benchmark, so re-running the king every duel/round is wasted inference.
This module caches the king's per-project execution + evaluation payloads keyed
by ``(king_hash, benchmark_version)``.

Correctness comes from the key: a cached entry is only ever reused when both the
king hash and the benchmark version match the current king and benchmark, which
means the king code and the answer key are byte-identical and the score is
therefore unchanged. A new king (different hash) or an edited benchmark
(different version) can never serve a stale score -- the cache invalidates
itself implicitly, with nothing to clear by hand.

Storage is deliberately free of any ``sn60_bitsec`` import so the evaluator can
depend on this module without a cycle.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path


def benchmark_version_key(scorer_version: str, benchmark_sha256: str) -> str:
    """Identity of the scorer + answer key that produced a king score.

    Includes the benchmark content hash (not just a commit) so an edited
    benchmark file forces a recompute even without a sandbox commit change.
    """
    return f"{scorer_version}@{benchmark_sha256}"


@dataclass
class KingScoreboard:
    """Cached king runs for one ``(king_hash, benchmark_version)``.

    ``scores`` maps a project key to the list of per-replica runs recorded so
    far; each run holds the raw execution ``report`` and ``evaluation`` payloads
    so a cache hit can materialize identical artifacts without re-running.
    """

    king_hash: str
    benchmark_version: str
    scores: dict[str, list[dict[str, object]]] = field(default_factory=dict)

    def cached_run(self, project_key: str, replica_index: int) -> dict[str, object] | None:
        """Return the cached run for a 1-based replica index, or ``None``."""
        runs = self.scores.get(project_key)
        if runs is None or replica_index < 1 or replica_index > len(runs):
            return None
        return runs[replica_index - 1]

    def record_run(
        self,
        project_key: str,
        replica_index: int,
        report_payload: dict[str, object],
        evaluation_payload: dict[str, object],
    ) -> None:
        """Store a freshly-computed king run at its 1-based replica index."""
        runs = self.scores.setdefault(project_key, [])
        entry: dict[str, object] = {
            "report": report_payload,
            "evaluation": evaluation_payload,
        }
        if replica_index - 1 < len(runs):
            runs[replica_index - 1] = entry
        else:
            # Replicas are recorded in order; pad defensively if a gap appears.
            while len(runs) < replica_index - 1:
                runs.append({"report": {}, "evaluation": {}})
            runs.append(entry)


def load_king_scoreboard(
    path: str | Path,
    *,
    king_hash: str,
    benchmark_version: str,
) -> KingScoreboard:
    """Load the scoreboard for the current king+benchmark, or a fresh empty one.

    A file whose stored key does not match the current ``(king_hash,
    benchmark_version)`` is stale and ignored: the returned board starts empty
    and overwrites the stale file on the next save.
    """
    board_path = Path(path)
    if board_path.exists():
        try:
            data = json.loads(board_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            data = None
        if (
            isinstance(data, dict)
            and data.get("king_hash") == king_hash
            and data.get("benchmark_version") == benchmark_version
            and isinstance(data.get("scores"), dict)
        ):
            return KingScoreboard(
                king_hash=king_hash,
                benchmark_version=benchmark_version,
                scores=data["scores"],
            )
    return KingScoreboard(king_hash=king_hash, benchmark_version=benchmark_version)


def save_king_scoreboard(path: str | Path, board: KingScoreboard) -> None:
    """Atomically persist the scoreboard."""
    board_path = Path(path)
    board_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "king_hash": board.king_hash,
        "benchmark_version": board.benchmark_version,
        "scores": board.scores,
    }
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{board_path.name}.",
        suffix=".tmp",
        dir=board_path.parent,
        text=True,
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
        tmp_path.replace(board_path)
    finally:
        if tmp_path.exists():
            tmp_path.unlink()
