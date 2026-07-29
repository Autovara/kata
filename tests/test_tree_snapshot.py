"""The vendored-tree verifier, on its own.

This is engine machinery a subnet leans on to prove *which upstream it scored against*. SN60's
sandbox and SN22's upstream are both pinned this way, so a hole here is a hole in both lanes'
provenance at once -- which is precisely why it lives in core rather than being copied into each
plugin. ``kata/core/execution_backend.py`` exists for the same reason, after two byte-identical
copies drifted.

The properties worth pinning are the refusals. Anyone can write a checker that passes on a good
tree; the question is whether it fails on every bad one.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kata.core.tree_snapshot import (
    MANIFEST_SCHEMA_VERSION,
    SnapshotError,
    SnapshotIdentity,
    compute_manifest,
    load_manifest,
    require_intact,
    tree_digest,
    verify_snapshot,
)

IDENTITY = SnapshotIdentity(repo="https://example.invalid/upstream", commit="a" * 40)


def _tree(root: Path) -> Path:
    (root / "pkg").mkdir(parents=True)
    (root / "pkg" / "scorer.py").write_text("def score():\n    return 1\n", encoding="utf-8")
    (root / "data.json").write_text('{"k": 1}\n', encoding="utf-8")
    manifest = compute_manifest(root, IDENTITY)
    (root / IDENTITY.manifest_name).write_text(json.dumps(manifest), encoding="utf-8")
    return root


def test_an_intact_tree_verifies(tmp_path: Path):
    root = _tree(tmp_path / "t")
    verification = verify_snapshot(root, IDENTITY)
    assert verification.ok, verification.findings
    assert verification.observed_tree_sha256 == verification.expected_tree_sha256
    assert require_intact(root, IDENTITY) == verification.expected_tree_sha256


def test_the_manifest_is_excluded_from_its_own_digest(tmp_path: Path):
    """It lives inside the tree it describes, so including it would be a fixpoint that can never
    hold -- and would report itself as an unlisted file."""
    root = _tree(tmp_path / "t")
    assert IDENTITY.manifest_name not in load_manifest(root, IDENTITY)["files"]


def test_a_changed_file_is_a_finding(tmp_path: Path):
    root = _tree(tmp_path / "t")
    (root / "data.json").write_text('{"k": 2}\n', encoding="utf-8")
    assert any("digest drift" in f for f in verify_snapshot(root, IDENTITY).findings)


def test_an_unlisted_file_is_a_finding(tmp_path: Path):
    """As serious as a changed one: a caller executes out of this tree, so an extra
    ``sitecustomize.py`` is code execution nobody reviewed."""
    root = _tree(tmp_path / "t")
    (root / "sitecustomize.py").write_text("import os\n", encoding="utf-8")
    assert any("not listed in the manifest" in f for f in verify_snapshot(root, IDENTITY).findings)


def test_a_missing_file_is_a_finding(tmp_path: Path):
    root = _tree(tmp_path / "t")
    (root / "pkg" / "scorer.py").unlink()
    assert any("missing from the tree" in f for f in verify_snapshot(root, IDENTITY).findings)


def test_a_symlink_is_a_finding_rather_than_being_followed(tmp_path: Path):
    """Silently following one is how a link to a credential file ends up inside a
    "verified" tree."""
    root = _tree(tmp_path / "t")
    (root / "link.json").symlink_to(tmp_path / "outside.txt")
    (tmp_path / "outside.txt").write_text("secret\n", encoding="utf-8")
    assert any("symlink" in f for f in verify_snapshot(root, IDENTITY).findings)


def test_every_finding_is_reported_not_just_the_first(tmp_path: Path):
    """An operator looking at a tampered install wants the whole list."""
    root = _tree(tmp_path / "t")
    (root / "data.json").write_text("changed\n", encoding="utf-8")
    (root / "extra.py").write_text("x = 1\n", encoding="utf-8")
    (root / "pkg" / "scorer.py").unlink()
    assert len(verify_snapshot(root, IDENTITY).findings) >= 3


def test_require_intact_raises_on_any_finding(tmp_path: Path):
    root = _tree(tmp_path / "t")
    (root / "extra.py").write_text("x = 1\n", encoding="utf-8")
    with pytest.raises(SnapshotError):
        require_intact(root, IDENTITY)


def test_a_manifest_for_a_different_commit_is_refused(tmp_path: Path):
    """The digest proves the bytes; this proves the bytes are the ones this lane was built for."""
    root = _tree(tmp_path / "t")
    document = json.loads((root / IDENTITY.manifest_name).read_text(encoding="utf-8"))
    document["upstream_commit"] = "b" * 40
    (root / IDENTITY.manifest_name).write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(SnapshotError, match="built for"):
        load_manifest(root, IDENTITY)


def test_an_unknown_schema_version_is_refused(tmp_path: Path):
    root = _tree(tmp_path / "t")
    document = json.loads((root / IDENTITY.manifest_name).read_text(encoding="utf-8"))
    document["schema_version"] = MANIFEST_SCHEMA_VERSION + 1
    (root / IDENTITY.manifest_name).write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(SnapshotError):
        load_manifest(root, IDENTITY)


def test_a_missing_manifest_is_refused(tmp_path: Path):
    root = _tree(tmp_path / "t")
    (root / IDENTITY.manifest_name).unlink()
    with pytest.raises(SnapshotError):
        verify_snapshot(root, IDENTITY)


def test_an_empty_tree_cannot_be_pinned(tmp_path: Path):
    """An empty manifest would verify anything, including an empty tree that should have contained
    a scorer."""
    root = tmp_path / "empty"
    root.mkdir()
    with pytest.raises(SnapshotError, match="no files"):
        compute_manifest(root, IDENTITY)


def test_the_digest_covers_paths_as_well_as_contents(tmp_path: Path):
    """A file moved between packages is a different tree even though every byte is unchanged."""
    assert tree_digest({"a/x.py": "d" * 64}) != tree_digest({"b/x.py": "d" * 64})


def test_moving_a_file_is_detected(tmp_path: Path):
    root = _tree(tmp_path / "t")
    (root / "pkg" / "scorer.py").rename(root / "scorer.py")
    findings = verify_snapshot(root, IDENTITY).findings
    assert any("missing from the tree" in f for f in findings)
    assert any("not listed in the manifest" in f for f in findings)
