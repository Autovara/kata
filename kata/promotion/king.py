from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from kata.screening.engine import screen_submission
from kata.screening.rules import hash_submission_bundle
from kata.state.artifacts import (
    publish_public_king,
    resolve_kata_root,
    resolve_public_king_root,
)
from kata.state.lanes import (
    KING_STATE_SCHEMA_VERSION,
    LaneKingState,
    PackRegistryEntry,
    discover_active_lane_ids,
    lane_king_state_path,
    load_lane_king_state,
    load_pack_registry,
    write_lane_king_state,
)
from kata.submissions.bundle import (
    AGENT_MANIFEST_FILENAME,
    find_unexpected_bundle_paths,
    validate_agent_manifest,
)
from kata.submissions.constants import SUBMISSION_AGENT_FILENAME
from kata.submissions.models import SubmissionMetadata
from kata.util import write_json


@dataclass(frozen=True)
class LanePromotionResult:
    lane_id: str
    king_root: str
    king: LaneKingState


@dataclass(frozen=True)
class LaneBootstrapResult:
    """Result of explicitly seeding a lane with its maintained baseline."""

    lane_id: str
    king_root: str
    king: LaneKingState
    baseline_id: str


def find_evaluator_pack_entry(
    repo_pack: str,
    mode: str,
    *,
    public_root: str | None = None,
) -> PackRegistryEntry | None:
    # A missing registry loads as empty (returns None below); a corrupt registry
    # must surface loudly so production does not close valid PRs for the wrong
    # reason.
    registry = load_pack_registry(public_root=public_root)
    for pack in registry.packs:
        if pack.repo_pack == repo_pack and pack.mode == mode:
            return pack
    return None


def validate_submission_lane(
    repo_pack: str,
    mode: str,
    *,
    public_root: str | None = None,
) -> list[str]:
    entry = find_evaluator_pack_entry(repo_pack, mode, public_root=public_root)
    if entry is None:
        return [
            f"No evaluator-backed lane is registered in the pack registry for `{repo_pack}/{mode}`."
        ]
    if not entry.active:
        return [f"Evaluator-backed lane is not active in the pack registry: {entry.lane_id}"]
    return []


def resolve_lane_king_hash(
    lane_id: str,
    *,
    repo_pack: str,
    mode: str,
    public_root: str | None = None,
) -> str | None:
    """Resolve the current king artifact hash for a registry-backed lane."""
    if lane_king_state_path(lane_id, public_root=public_root).exists():
        king = load_lane_king_state(lane_id, public_root=public_root)
        if king.current_king_artifact_hash:
            return king.current_king_artifact_hash
    king_root = resolve_public_king_root(public_root=public_root, repo_pack=repo_pack, mode=mode)
    if (king_root / SUBMISSION_AGENT_FILENAME).exists():
        return hash_submission_bundle(king_root)
    return None


def resolve_lane_king_artifact(metadata: SubmissionMetadata) -> tuple[str, str]:
    """Resolve (lane_id, king_artifact_path) for a lane duel from the pack registry."""
    entry = find_evaluator_pack_entry(metadata.repo_pack, metadata.mode)
    if entry is None:
        raise ValueError(
            f"No evaluator-backed lane is registered for `{metadata.repo_pack}/{metadata.mode}`."
        )
    king_root = resolve_public_king_root(
        public_root=None,
        repo_pack=metadata.repo_pack,
        mode=metadata.mode,
    )
    if not (king_root / SUBMISSION_AGENT_FILENAME).exists():
        raise ValueError(
            f"Lane king artifact is not seeded: {king_root}. "
            "Seed the current king under kings/<subnet-pack>/<mode>/ before running duels."
        )
    return entry.lane_id, str(king_root)


def _baseline_public_results_path(
    *,
    entry: PackRegistryEntry,
    public_root: str | None,
) -> Path:
    """Return the public-current path without allowing lanes to overwrite each other."""
    root = resolve_kata_root(public_root)
    active_lane_ids = discover_active_lane_ids(public_root=str(root))
    if len(active_lane_ids) > 1:
        return root / "public-results" / entry.lane_id / "current.json"
    return root / "public-results" / "current.json"


def _read_public_current(path: Path) -> dict[str, object]:
    if not path.exists():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"Expected a JSON object in public result file: {path}")
    return payload


def _publish_baseline_public_current(
    *,
    entry: PackRegistryEntry,
    king: LaneKingState,
    public_root: str | None,
) -> Path:
    """Publish a public current-king record for a screened baseline seed.

    Baselines have no miner author or source PR, but they are real kings.  Keeping
    this record in sync with the lane state lets public consumers and the board
    show the initial competition state before the first promoted PR exists.
    """
    path = _baseline_public_results_path(entry=entry, public_root=public_root)
    existing = _read_public_current(path)
    benchmark = existing.get("benchmark")
    dashboard_url = existing.get("dashboard_url")
    payload = {
        "schema_version": 1,
        "updated_at": king.updated_at,
        "active_pack": entry.repo_pack,
        "active_mode": entry.mode,
        "current_king": {
            "author": None,
            "submission_id": king.current_king_submission_id,
            "source_pull_request": None,
            "path": f"kings/{entry.repo_pack}/{entry.mode}",
            "artifact_hash": king.current_king_artifact_hash,
            "promoted_at": king.promotion_timestamp,
        },
        "latest_round": None,
        "benchmark": benchmark if isinstance(benchmark, dict) else {},
        "dashboard_url": dashboard_url if isinstance(dashboard_url, str) else None,
    }
    return write_json(path, payload)


def bootstrap_lane_king(
    *,
    entry: PackRegistryEntry,
    baseline_path: str,
    baseline_id: str,
    public_root: str | None = None,
    replace_existing: bool = False,
) -> LaneBootstrapResult:
    """Screen and publish a maintained baseline as the first king of a lane.

    A baseline is not a PR promotion, but it must pass the exact generic and
    subnet-specific screening gate used for a miner submission.  This avoids an
    implicit empty king while keeping initialisation auditable and fail-closed.
    """
    from kata.plugins.discovery import plugin_for_evaluator

    root = Path(baseline_path).expanduser().resolve()
    if not baseline_id.strip():
        raise ValueError("Baseline id must not be empty.")
    if not root.is_dir():
        raise ValueError(f"Baseline artifact directory does not exist: {root}")
    if not (root / SUBMISSION_AGENT_FILENAME).is_file():
        raise ValueError(f"Baseline artifact is missing required file: {SUBMISSION_AGENT_FILENAME}")
    manifest_path = root / AGENT_MANIFEST_FILENAME
    if not manifest_path.is_file():
        raise ValueError(f"Baseline artifact is missing required file: {AGENT_MANIFEST_FILENAME}")
    manifest_reasons = validate_agent_manifest(manifest_path)
    if manifest_reasons:
        raise ValueError("Baseline agent manifest is invalid: " + "; ".join(manifest_reasons))
    unexpected = find_unexpected_bundle_paths(root)
    if unexpected:
        raise ValueError("Baseline artifact contains unsupported files: " + ", ".join(unexpected))

    current_path = lane_king_state_path(entry.lane_id, public_root=public_root)
    current = (
        load_lane_king_state(entry.lane_id, public_root=public_root)
        if current_path.exists()
        else None
    )
    if current and current.current_king_artifact_hash and not replace_existing:
        raise ValueError(
            f"Lane '{entry.lane_id}' already has a king. Use --replace only for an "
            "intentional baseline reset."
        )

    decision = screen_submission(
        submission_root=root,
        public_root=resolve_kata_root(public_root),
        repo_pack=entry.repo_pack,
        mode=entry.mode,
        check_current_king=False,
    )
    if not decision.passed:
        messages = decision.rejection_messages() or [
            "Baseline requires review before it can be seeded."
        ]
        raise ValueError("Baseline failed the screening gate: " + "; ".join(messages))

    plugin = plugin_for_evaluator(entry.evaluator_id)
    if plugin is None:
        raise ValueError(f"No subnet plugin is registered for evaluator '{entry.evaluator_id}'.")
    source_hash = plugin.hash_bundle(root)
    published = publish_public_king(
        public_root=str(resolve_kata_root(public_root)),
        repo_pack=entry.repo_pack,
        mode=entry.mode,
        submission_id=baseline_id.strip(),
        challenge_run_id=f"baseline:{baseline_id.strip()}",
        candidate_artifact_path=str(root),
        candidate_artifact_hash=source_hash,
        artifact_hasher=plugin.hash_bundle,
    )
    now = datetime.now(UTC).isoformat()
    king = LaneKingState(
        schema_version=KING_STATE_SCHEMA_VERSION,
        current_king_submission_id=baseline_id.strip(),
        current_king_artifact_hash=published.king_artifact_hash,
        promotion_source_pr=None,
        promotion_timestamp=now,
        updated_at=now,
    )
    write_lane_king_state(entry.lane_id, king, public_root=public_root)
    _publish_baseline_public_current(
        entry=entry,
        king=king,
        public_root=public_root,
    )
    return LaneBootstrapResult(
        lane_id=entry.lane_id,
        king_root=str(published.king_root),
        king=king,
        baseline_id=baseline_id.strip(),
    )


def promote_lane_king(
    *,
    entry: PackRegistryEntry,
    verification,
    summary,
    public_root: str | None = None,
) -> LanePromotionResult:
    from kata.plugins.discovery import plugin_for_evaluator

    plugin = plugin_for_evaluator(entry.evaluator_id)

    kata_root = str(resolve_kata_root(public_root))
    king_root = resolve_public_king_root(
        public_root=kata_root, repo_pack=verification.repo_pack, mode=verification.mode
    )
    state_path = lane_king_state_path(entry.lane_id, public_root=public_root)

    # Snapshot the current king bundle and lane state so that if publication fails
    # part-way through, the previous CONSISTENT king is restored rather than leaving a
    # missing/partial king (or a lane state that points at a different bundle than
    # kings/) -- either of which freezes the competition.
    king_backup = None
    if king_root.exists():
        king_backup = king_root.parent / f".{king_root.name}.rollback.{os.getpid()}"
        if king_backup.exists():
            shutil.rmtree(king_backup, ignore_errors=True)
        shutil.copytree(king_root, king_backup)
    state_backup = state_path.read_bytes() if state_path.exists() else None

    try:
        published = publish_public_king(
            public_root=kata_root,
            repo_pack=verification.repo_pack,
            mode=verification.mode,
            submission_id=verification.submission_id,
            challenge_run_id=summary.run_id,
            candidate_artifact_path=verification.submission_path,
            candidate_artifact_hash=verification.candidate_artifact_hash,
            # Hash the published king the way the subnet's round does, so king_is_current
            # stays true even for non-normalized submissions.
            artifact_hasher=plugin.hash_bundle if plugin is not None else hash_submission_bundle,
        )
        now = datetime.now(UTC).isoformat()
        king = LaneKingState(
            schema_version=KING_STATE_SCHEMA_VERSION,
            current_king_submission_id=verification.submission_id,
            current_king_artifact_hash=published.king_artifact_hash,
            promotion_source_pr=None,
            promotion_timestamp=now,
            updated_at=now,
        )
        # The king bundle and the lane state that points at it must both land before
        # anything else; the state records the just-published hash.
        write_lane_king_state(entry.lane_id, king, public_root=public_root)
    except BaseException:
        _restore_public_king(king_root, king_backup)
        _restore_lane_king_state(state_path, state_backup)
        raise
    finally:
        if king_backup is not None:
            shutil.rmtree(king_backup, ignore_errors=True)

    # The lane's plugin persists subnet-specific provenance (challenge state +
    # benchmark snapshot + promotion record); the core stays subnet-blind. This runs
    # LAST -- only after the throne actually changed hands -- so a failed publish never
    # leaves a promotion record for a king that never reigned.
    if plugin is not None:
        plugin.record_promotion_provenance(
            entry=entry,
            verification=verification,
            summary=summary,
            public_root=public_root,
        )
    return LanePromotionResult(
        lane_id=entry.lane_id,
        king_root=str(published.king_root),
        king=king,
    )


def _restore_public_king(king_root: Path, king_backup: Path | None) -> None:
    """Roll the published king directory back to its pre-promotion snapshot."""
    if king_root.exists():
        shutil.rmtree(king_root, ignore_errors=True)
    if king_backup is not None and king_backup.exists():
        shutil.copytree(king_backup, king_root)


def _restore_lane_king_state(state_path: Path, state_backup: bytes | None) -> None:
    """Roll the lane king-state file back to its pre-promotion bytes (or absence)."""
    if state_backup is not None:
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state_path.write_bytes(state_backup)
    elif state_path.exists():
        state_path.unlink()
