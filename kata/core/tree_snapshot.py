"""Integrity of a vendored source tree, pinned by a manifest of per-file digests.

A lane that vendors its upstream is claiming to score against *a specific commit*. That claim is
only worth something if it can be checked without the upstream's ``.git`` directory, because a tree
produced by ``git archive`` does not have one.

Subnet-neutral on purpose, and for a concrete reason. SN22 already carried this logic; SN60 needed
the same thing when its sandbox moved from a clone into the plugin repository. Two copies of
security-critical verification that must agree is the failure this repository has already paid for
once -- see ``kata/core/execution_backend.py``, which exists because SN22 and SN60 held
byte-identical backend-selection logic differing only in an environment-variable name, so a fix to
one silently did not reach the other.

Nothing here knows what a tree contains or what it is for. The caller supplies the root, the
upstream identity and the manifest name, because those are the subnet's; this module supplies only
the discipline.

**It fails closed, and the asymmetry is the whole design.** An unlisted file matters as much as a
changed one: whatever imports or executes from this tree would execute an extra ``sitecustomize.py``
too. A symlink matters because silently following one is how a link to a credential file ends up
inside a "verified" tree. So a missing file, an unexpected file, a digest mismatch, a symlink and a
path that escapes the root are all findings, and a caller that must not proceed calls
:func:`require_intact`.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

MANIFEST_SCHEMA_VERSION = 1


class SnapshotError(Exception):
    """The vendored tree cannot be trusted, or its manifest cannot be read."""


@dataclass(frozen=True)
class SnapshotIdentity:
    """Which upstream a vendored tree claims to be, and where the manifest lives.

    ``manifest_name`` is part of the identity rather than a constant because the file sits *inside*
    the tree it describes and must therefore be excluded from its own digest; a caller that renamed
    it without telling this module would see the manifest reported as an unlisted file.
    """

    repo: str
    commit: str
    manifest_name: str = "UPSTREAM_MANIFEST.json"


def _iter_files(root: Path):
    """Every entry under ``root`` as (posix-relative, path), sorted.

    Symlinks are YIELDED rather than skipped. The caller has to be able to report one; skipping it
    quietly is the bug this guards against.
    """
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames):
            path = Path(dirpath) / name
            yield path.relative_to(root).as_posix(), path


def _digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tree_digest(files: dict[str, str]) -> str:
    """One digest over the whole tree: sorted ``path\\0sha256\\n`` lines.

    Path AND content, because a file moved from one package to another is a different tree even
    though every byte is unchanged.
    """
    body = "".join(f"{path}\0{files[path]}\n" for path in sorted(files))
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def compute_manifest(root: Path, identity: SnapshotIdentity) -> dict:
    """Build a manifest from what is on disk. Used to GENERATE, never to verify.

    Generating and verifying must stay separate operations: a build that regenerates its own pin can
    never detect drift, because the pin would always describe whatever it just found.
    """
    root = Path(root).resolve()
    if not root.is_dir():
        raise SnapshotError(f"vendored tree is absent at {root}")
    files: dict[str, str] = {}
    for relative, path in _iter_files(root):
        if relative == identity.manifest_name:
            continue   # the manifest cannot contain its own digest
        if path.is_symlink() or not path.is_file():
            raise SnapshotError(f"tree entry {relative} is not a regular file")
        files[relative] = _digest_file(path)
    if not files:
        raise SnapshotError(
            f"vendored tree at {root} contains no files; an empty manifest would verify anything"
        )
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "upstream_repo": identity.repo,
        "upstream_commit": identity.commit,
        "file_count": len(files),
        "tree_sha256": tree_digest(files),
        "files": dict(sorted(files.items())),
    }


def load_manifest(root: Path, identity: SnapshotIdentity) -> dict:
    root = Path(root).resolve()
    path = root / identity.manifest_name
    if not path.is_file():
        raise SnapshotError(f"vendored tree has no {identity.manifest_name} at {path}")
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise SnapshotError(f"{identity.manifest_name} is not valid JSON: {exc}") from exc
    if manifest.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        raise SnapshotError(
            f"{identity.manifest_name} schema {manifest.get('schema_version')!r} "
            f"is not {MANIFEST_SCHEMA_VERSION}"
        )
    if manifest.get("upstream_commit") != identity.commit:
        raise SnapshotError(
            f"{identity.manifest_name} pins {manifest.get('upstream_commit')!r} but this lane is "
            f"built for {identity.commit!r}"
        )
    return manifest


@dataclass(frozen=True)
class SnapshotVerification:
    """The result of checking a tree against its manifest. Empty ``findings`` means intact."""

    root: str
    expected_tree_sha256: str
    observed_tree_sha256: str
    findings: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.findings

    def as_dict(self) -> dict:
        return {
            "root": self.root,
            "expected_tree_sha256": self.expected_tree_sha256,
            "observed_tree_sha256": self.observed_tree_sha256,
            "ok": self.ok,
            "findings": list(self.findings),
        }


def verify_snapshot(root: Path, identity: SnapshotIdentity) -> SnapshotVerification:
    """Check the on-disk tree against its manifest. Reports every finding, never raises on drift.

    Returning findings rather than raising on the first one is deliberate: an operator looking at a
    tampered install wants the whole list, and a caller that wants failure reads ``ok``.
    """
    root = Path(root).resolve()
    manifest = load_manifest(root, identity)
    expected: dict[str, str] = dict(manifest.get("files") or {})
    findings: list[str] = []
    observed: dict[str, str] = {}

    for relative, path in _iter_files(root):
        if relative == identity.manifest_name:
            continue
        if path.is_symlink():
            findings.append(f"{relative}: symlink in the vendored tree")
            continue
        # A resolved path outside the root means a bind/junction escape; refuse to digest it.
        try:
            path.resolve().relative_to(root)
        except ValueError:
            findings.append(f"{relative}: resolves outside the vendored tree root")
            continue
        if not path.is_file():
            findings.append(f"{relative}: not a regular file")
            continue
        observed[relative] = _digest_file(path)

    for relative in sorted(set(expected) - set(observed)):
        findings.append(f"{relative}: listed in the manifest but missing from the tree")
    for relative in sorted(set(observed) - set(expected)):
        findings.append(f"{relative}: present in the tree but not listed in the manifest")
    for relative in sorted(set(expected) & set(observed)):
        if expected[relative] != observed[relative]:
            findings.append(
                f"{relative}: digest drift "
                f"({expected[relative][:12]} -> {observed[relative][:12]})"
            )

    return SnapshotVerification(
        root=str(root),
        expected_tree_sha256=str(manifest.get("tree_sha256") or ""),
        observed_tree_sha256=tree_digest(observed),
        findings=tuple(findings),
    )


def require_intact(root: Path, identity: SnapshotIdentity) -> str:
    """Verify and return the tree digest, or raise. For callers that must fail closed."""
    verification = verify_snapshot(root, identity)
    if not verification.ok:
        raise SnapshotError(
            "vendored tree failed verification:\n  " + "\n  ".join(verification.findings)
        )
    if verification.observed_tree_sha256 != verification.expected_tree_sha256:
        raise SnapshotError("vendored tree digest does not match the manifest")
    return verification.observed_tree_sha256


__all__ = [
    "MANIFEST_SCHEMA_VERSION",
    "SnapshotError",
    "SnapshotIdentity",
    "SnapshotVerification",
    "compute_manifest",
    "load_manifest",
    "require_intact",
    "tree_digest",
    "verify_snapshot",
]
