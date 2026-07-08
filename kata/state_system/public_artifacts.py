"""Public Kata artifact path and bundle publication helpers."""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path

from kata.submission_system.bundle import load_bundle_files, replace_bundle_contents

KATA_REPO_ROOT = Path(__file__).resolve().parents[1]
KATA_ROOT_ENV = "KATA_ROOT"
PUBLIC_KINGS_DIRNAME = "kings"
KING_METADATA_FILENAME = "king.json"


@dataclass(frozen=True)
class PublicKingMetadata:
    repo_pack: str
    mode: str
    submission_id: str
    challenge_run_id: str
    king_artifact_hash: str
    candidate_artifact_hash: str


@dataclass(frozen=True)
class PublishedKing:
    king_root: Path
    # Hash of the PUBLISHED bundle (post-mirror normalization), computed with
    # the same hasher a later duel uses on kings/. This is what lane state must
    # record so `king_is_current` stays true.
    king_artifact_hash: str


def resolve_kata_root(public_root: str | None = None) -> Path:
    configured_root = public_root or os.environ.get(KATA_ROOT_ENV)
    if configured_root:
        return Path(configured_root).expanduser().resolve()
    return KATA_REPO_ROOT.resolve()


def resolve_public_king_root(*, public_root: str | None, repo_pack: str, mode: str) -> Path:
    return resolve_kata_root(public_root) / PUBLIC_KINGS_DIRNAME / repo_pack / mode


def mirror_public_king_artifact(
    *,
    public_root: str | None,
    repo_pack: str,
    mode: str,
    artifact_path: str,
) -> Path:
    king_root = resolve_public_king_root(
        public_root=public_root,
        repo_pack=repo_pack,
        mode=mode,
    )
    candidate_root = Path(artifact_path).expanduser().resolve()
    replace_bundle_contents(king_root, load_bundle_files(candidate_root))
    return king_root


def publish_public_king(
    *,
    public_root: str,
    repo_pack: str,
    mode: str,
    submission_id: str,
    challenge_run_id: str,
    candidate_artifact_path: str,
    candidate_artifact_hash: str,
    artifact_hasher: Callable[[Path], str],
) -> PublishedKing:
    king_root = mirror_public_king_artifact(
        public_root=public_root,
        repo_pack=repo_pack,
        mode=mode,
        artifact_path=candidate_artifact_path,
    )
    # Hash the mirrored bundle, not the source: mirroring normalizes trailing
    # whitespace/newlines, so the published bytes (which future duels hash) can
    # differ from candidate_artifact_hash. Recording the source hash here would
    # make every later duel see king_is_current=False -> a permanent
    # rerun-stale livelock for any submission that wasn't already normalized.
    published_hash = artifact_hasher(king_root)
    metadata = PublicKingMetadata(
        repo_pack=repo_pack,
        mode=mode,
        submission_id=submission_id,
        challenge_run_id=challenge_run_id,
        king_artifact_hash=published_hash,
        candidate_artifact_hash=candidate_artifact_hash,
    )
    (king_root / KING_METADATA_FILENAME).write_text(
        json.dumps(asdict(metadata), indent=2) + "\n",
        encoding="utf-8",
    )
    return PublishedKing(king_root=king_root, king_artifact_hash=published_hash)
