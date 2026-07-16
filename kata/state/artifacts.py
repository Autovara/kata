"""Public Kata artifact path and bundle publication helpers."""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path

from kata.submissions.bundle import stage_submission_bundle

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
    # Hash of the PUBLISHED (byte-for-byte) bundle, computed with the same hasher
    # a later duel uses on kings/. This is what lane state must record so
    # `king_is_current` stays true.
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
    # Copy the winning bundle byte-for-byte (agent files, submission.json, and the
    # sealed_inference_key), NOT through a normalizing write. A miner seals its TEE
    # provider credential to the exact submitted bytes, and the room re-checks that
    # binding over the king's bytes on every re-scoring round. Normalizing trailing
    # whitespace/newlines -- or dropping submission.json -- would change those bytes
    # and make a promoted king's sealed key fail its binding, so the king could
    # never run in the room again (the original bytes are gone once the submission
    # directory is cleared). Staging preserves them exactly.
    stage_submission_bundle(candidate_root, king_root)
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
    # Hash the published bundle with the same hasher a later duel uses on kings/.
    # Publication is now byte-for-byte, so this equals candidate_artifact_hash;
    # recording the published hash keeps `king_is_current` robust even if the
    # hasher's file set ever diverges from the source snapshot.
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
