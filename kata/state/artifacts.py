"""Public Kata artifact path and bundle publication helpers."""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path

from kata.submissions.bundle import stage_submission_bundle

KATA_ROOT_ENV = "KATA_ROOT"

#: The ONE thing that identifies a competition tree: the lane registry.
#:
#: Deliberately a single strong marker. An earlier version also accepted a bare ``kings/``
#: directory, on the theory that a freshly initialised tree might have one before the other. That
#: made any unrelated ancestor holding a folder called ``kings`` win the search -- reproducing the
#: exact failure this function exists to prevent, since such a root has no registry and lane
#: discovery comes back empty.
#:
#: It bought nothing, either: a tree is bootstrapped with ``--public-root`` or ``KATA_ROOT``, both
#: of which accept an empty destination. ``kata lane init --public-root <empty dir>`` creates
#: ``lanes/registry.json`` itself. Discovery never has to guess at a half-built tree.
#:
#: Directory NAMES alone would not be enough in any case: this distribution contains
#: ``kata/state/lanes/`` and ``kata/submissions/``, both Python packages.
KATA_ROOT_MARKER = "lanes/registry.json"


def _is_kata_root(path: Path) -> bool:
    # A package is never a competition tree. Belt and braces alongside the registry check, because
    # the cost of a wrong root here is silent: every consumer reads an empty tree and reports
    # success.
    if (path / "__init__.py").is_file():
        return False
    return (path / "lanes" / "registry.json").is_file()


def _search_upward(start: Path) -> Path | None:
    """The nearest ancestor of ``start`` (inclusive) that looks like a Kata root, or None.

    Bounded by the filesystem root: ``Path.parents`` terminates, so this cannot loop.
    """
    for candidate in (start, *start.parents):
        if _is_kata_root(candidate):
            return candidate
    return None


def discover_kata_root() -> Path | None:
    """Where the competition tree is, when nobody said.

    Searched in order of how much the answer can be trusted:

    1. **this module's location** -- a source checkout, where the tree sits above the package. This
       is a KNOWN location, fixed by the code being executed;
    2. **the working directory** -- where a maintainer running an installed CLI stands, and what the
       README's ``KATA_ROOT="$(pwd)"`` workaround was standing in for.

    The module comes first on purpose. The working directory is whatever the caller happened to be
    in, so letting it win means an ancestor directory decides which competition tree is read. In a
    source checkout both answers are the same; when they differ, the deterministic one wins and
    ``KATA_ROOT`` remains available to say otherwise.

    Returns None when neither finds one -- the normal case for an INSTALLED distribution with no
    tree nearby. A fixed parent index cannot express that; it just returns some unrelated directory
    with confidence.
    """
    return _search_upward(Path(__file__).resolve().parent) or _search_upward(Path.cwd().resolve())


#: Kept as a module attribute because it was one, but no longer a fixed parent index.
#:
#: It used to be ``parents[1]``, which pointed one level too high after the engine packages were
#: reorganised and this file moved into ``kata/state/``. With ``KATA_ROOT`` unset, every path
#: resolved under ``kata/lanes`` and ``kata/kings`` -- neither of which exists -- so lane discovery
#: returned nothing and the king-copycat screen silently accepted a verbatim copy of the reigning
#: king. Nothing raised; the checks simply found nothing to compare against.
KATA_REPO_ROOT = discover_kata_root() or Path(__file__).resolve().parents[2]
PUBLIC_KINGS_DIRNAME = "kings"
KING_METADATA_FILENAME = "king.json"


class KataRootNotFound(RuntimeError):
    """No competition tree could be located and none was configured."""


@dataclass(frozen=True)
class PublicKingMetadata:
    subnet_pack: str
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
    """The competition tree this call operates on.

    An explicit ``public_root`` wins, then ``KATA_ROOT``; production always sets one of the two --
    kata-bot exports ``KATA_ROOT`` into every child it spawns. Only an unconfigured caller reaches
    the search, and if that finds nothing this RAISES rather than guessing.

    Failing loudly is the point. The previous default returned a directory that existed and simply
    had no ``lanes/`` or ``kings/`` in it, so every consumer read an empty tree and reported
    success. A wrong path that resolves is worse than no path at all.
    """
    configured_root = public_root or os.environ.get(KATA_ROOT_ENV)
    if configured_root:
        return Path(configured_root).expanduser().resolve()
    discovered = discover_kata_root()
    if discovered is None:
        raise KataRootNotFound(
            f"no Kata competition tree found. Looked for {KATA_ROOT_MARKER} from the installed "
            f"package and from the working directory. Set {KATA_ROOT_ENV}, or pass --public-root, "
            f"or run from a Kata checkout."
        )
    return discovered


def resolve_public_king_root(*, public_root: str | None, subnet_pack: str, mode: str) -> Path:
    return resolve_kata_root(public_root) / PUBLIC_KINGS_DIRNAME / subnet_pack / mode


def mirror_public_king_artifact(
    *,
    public_root: str | None,
    subnet_pack: str,
    mode: str,
    artifact_path: str,
) -> Path:
    king_root = resolve_public_king_root(
        public_root=public_root,
        subnet_pack=subnet_pack,
        mode=mode,
    )
    candidate_root = Path(artifact_path).expanduser().resolve()
    # Copy the winning bundle byte-for-byte (agent files, submission.json, and the
    # sealed_inference_key), NOT through a normalizing write. A miner seals its TEE
    # provider credential to the exact submitted bytes, and the room re-checks that
    # binding over the king's bytes on every re-scoring pass. Normalizing trailing
    # whitespace/newlines -- or dropping submission.json -- would change those bytes
    # and make a promoted king's sealed key fail its binding, so the king could
    # never run in the room again (the original bytes are gone once the submission
    # directory is cleared). Staging preserves them exactly.
    stage_submission_bundle(candidate_root, king_root)
    return king_root


def publish_public_king(
    *,
    public_root: str,
    subnet_pack: str,
    mode: str,
    submission_id: str,
    challenge_run_id: str,
    candidate_artifact_path: str,
    candidate_artifact_hash: str,
    artifact_hasher: Callable[[Path], str],
) -> PublishedKing:
    king_root = mirror_public_king_artifact(
        public_root=public_root,
        subnet_pack=subnet_pack,
        mode=mode,
        artifact_path=candidate_artifact_path,
    )
    # Hash the published bundle with the same hasher a later duel uses on kings/.
    # Publication is now byte-for-byte, so this equals candidate_artifact_hash;
    # recording the published hash keeps `king_is_current` robust even if the
    # hasher's file set ever diverges from the source snapshot.
    published_hash = artifact_hasher(king_root)
    metadata = PublicKingMetadata(
        subnet_pack=subnet_pack,
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
