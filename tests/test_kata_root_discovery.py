"""Finding the competition tree when nobody said where it is.

`resolve_kata_root()` decides where `lanes/`, `kings/` and `submissions/` are read from. It used to
be a fixed parent index -- `Path(__file__).resolve().parents[1]` -- which pointed one level too high
after the engine packages were reorganised and this module moved into `kata/state/`.

The consequence was silent, which is why it survived. Nothing raised. With `KATA_ROOT` unset every
path resolved under `kata/lanes` and `kata/kings`, neither of which exists, so:

* lane discovery returned no packs;
* `resolve_public_king_root` pointed at nothing;
* the king-copycat screen accepted a VERBATIM copy of the reigning king, because it could not find
  a king to compare against.

Production masked it -- kata-bot exports `KATA_ROOT` into every child it spawns -- so only local CLI
use and any new caller trusting the default were affected. Issue #210.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from kata.state import artifacts
from kata.state.artifacts import (
    KATA_ROOT_ENV,
    KataRootNotFound,
    resolve_kata_root,
)

REPO = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _no_configured_root(monkeypatch):
    """Every test here is about the UNCONFIGURED path; a leaked env var would hide the bug."""
    monkeypatch.delenv(KATA_ROOT_ENV, raising=False)


def _make_tree(root: Path) -> Path:
    (root / "lanes").mkdir(parents=True)
    (root / "lanes" / "registry.json").write_text('{"schema_version": 1, "packs": []}\n')
    (root / "kings").mkdir()
    return root


# ---- the bug ---

def test_the_default_root_contains_the_competition_tree(monkeypatch, tmp_path):
    """THE regression. The old default returned a directory that existed and simply had no lanes or
    kings in it, so every consumer read an empty tree and reported success."""
    monkeypatch.chdir(REPO)
    root = resolve_kata_root()
    assert (root / "lanes").is_dir(), f"{root} has no lanes/"
    assert (root / "kings").is_dir(), f"{root} has no kings/"


def test_the_default_root_is_not_the_package_directory(monkeypatch):
    """`parents[1]` was `<repo>/kata` -- the package, not the tree."""
    monkeypatch.chdir(REPO)
    assert resolve_kata_root() != Path(artifacts.__file__).resolve().parents[1]


# ---- precedence ---

def test_an_explicit_public_root_wins(tmp_path, monkeypatch):
    monkeypatch.setenv(KATA_ROOT_ENV, str(tmp_path / "from-env"))
    explicit = _make_tree(tmp_path / "explicit")
    assert resolve_kata_root(str(explicit)) == explicit.resolve()


def test_the_environment_wins_over_discovery(tmp_path, monkeypatch):
    """Production always sets it, so discovery must never override what an operator configured."""
    configured = _make_tree(tmp_path / "configured")
    monkeypatch.setenv(KATA_ROOT_ENV, str(configured))
    monkeypatch.chdir(REPO)
    assert resolve_kata_root() == configured.resolve()


def test_a_configured_root_is_used_even_when_it_has_no_tree_yet(tmp_path, monkeypatch):
    """`kata lane init` has to be able to create the tree it is pointed at."""
    empty = tmp_path / "brand-new"
    empty.mkdir()
    monkeypatch.setenv(KATA_ROOT_ENV, str(empty))
    assert resolve_kata_root() == empty.resolve()


def test_the_working_directory_is_searched_when_the_package_has_no_tree(tmp_path, monkeypatch):
    """The installed case: the package sits in site-packages with no tree above it, so where the
    maintainer is standing is the only signal left. This is what the README's
    ``KATA_ROOT="$(pwd)"`` workaround was standing in for.

    The module search is stubbed out because this checkout HAS a tree above the package -- without
    stubbing, the test would pass for the wrong reason and prove nothing about the fallback.
    """
    tree = _make_tree(tmp_path / "checkout")
    nested = tree / "submissions" / "sn60__bitsec" / "miner"
    nested.mkdir(parents=True)
    monkeypatch.chdir(nested)

    real_search = artifacts._search_upward
    package_dir = Path(artifacts.__file__).resolve().parent
    monkeypatch.setattr(
        artifacts, "_search_upward",
        lambda start: None if start == package_dir else real_search(start))
    assert resolve_kata_root() == tree.resolve()


# ---- failing loudly ---

def test_no_tree_anywhere_raises_instead_of_guessing(tmp_path, monkeypatch):
    """A wrong path that resolves is worse than no path: it makes every consumer read an empty tree
    and report success. Simulates the installed case, where the package sits in site-packages with
    no competition tree above it."""
    isolated = tmp_path / "isolated"
    isolated.mkdir()
    monkeypatch.chdir(isolated)
    monkeypatch.setattr(artifacts, "discover_kata_root", lambda: None)
    with pytest.raises(KataRootNotFound) as excinfo:
        resolve_kata_root()
    message = str(excinfo.value)
    assert KATA_ROOT_ENV in message, "the error must name the variable that fixes it"
    assert "--public-root" in message


# ---- what must NOT be mistaken for a root ---

def test_a_package_directory_itself_is_never_a_root(tmp_path):
    """Belt and braces: a directory carrying `__init__.py` is a package, whatever is inside it."""
    package = tmp_path / "pkg"
    (package / "kings").mkdir(parents=True)
    (package / "__init__.py").write_text("")
    assert artifacts._is_kata_root(package) is False


def test_a_lanes_package_without_a_registry_is_not_a_root(tmp_path):
    """`kata/state/lanes/` is a Python package. The registry FILE is what makes a root."""
    package = tmp_path / "state"
    (package / "lanes").mkdir(parents=True)
    (package / "lanes" / "__init__.py").write_text("")
    assert artifacts._is_kata_root(package) is False


def test_the_engine_package_directories_are_not_roots():
    """Asserted against the REAL tree, so a future package named `kings/` is caught here."""
    for suspect in (REPO / "kata", REPO / "kata" / "state", REPO / "kata" / "submissions"):
        if suspect.is_dir():
            assert artifacts._is_kata_root(suspect) is False, f"{suspect} looks like a root"


def test_a_real_tree_is_recognised(tmp_path):
    assert artifacts._is_kata_root(_make_tree(tmp_path / "real")) is True


def test_a_kings_only_directory_is_NOT_a_root(tmp_path):
    """Reversed from what an earlier version asserted, because that version was wrong.

    Accepting a bare ``kings/`` made any unrelated ancestor holding a folder of that name win the
    search -- reproducing the very failure this module exists to prevent, since such a root has no
    registry and lane discovery comes back empty.

    It bought nothing: a tree is bootstrapped with ``--public-root`` or ``KATA_ROOT``, both of which
    accept an empty destination, and ``kata lane init`` creates the registry itself. Discovery never
    has to guess at a half-built tree.
    """
    root = tmp_path / "kings-only"
    (root / "kings").mkdir(parents=True)
    assert artifacts._is_kata_root(root) is False


def test_an_unrelated_ancestor_with_a_kings_folder_is_ignored(tmp_path, monkeypatch):
    """THE regression for the second round.

    Standing anywhere under a directory that happens to contain ``kings/`` must not hijack the
    search. Reproduced before this fix: the decoy won, ``lanes/registry.json`` was absent, and
    ``load_pack_registry()`` returned an empty list -- the original symptom, by a new route.
    """
    decoy = tmp_path / "unrelated-project"
    (decoy / "kings").mkdir(parents=True)
    nested = decoy / "src" / "nested"
    nested.mkdir(parents=True)
    monkeypatch.chdir(nested)

    resolved = resolve_kata_root()
    assert not str(resolved).startswith(str(decoy)), f"an unrelated ancestor won: {resolved}"
    assert (resolved / "lanes" / "registry.json").is_file()


def test_a_directory_without_a_registry_is_not_a_root(tmp_path):
    """The registry FILE is the marker, not a directory named lanes."""
    root = tmp_path / "no-registry"
    (root / "lanes").mkdir(parents=True)
    assert artifacts._is_kata_root(root) is False


def test_the_source_checkout_is_preferred_over_the_working_directory(tmp_path, monkeypatch):
    """When the two disagree the deterministic answer wins: the working directory is whatever the
    caller happened to be in, so letting it win means an ancestor decides which tree is read.
    ``KATA_ROOT`` remains available to say otherwise -- covered above."""
    other = _make_tree(tmp_path / "another-tree")
    monkeypatch.chdir(other)
    assert resolve_kata_root() == REPO.resolve()


def test_the_search_terminates_at_the_filesystem_root(tmp_path, monkeypatch):
    """`Path.parents` is finite, but an upward walk is the shape that hangs when it is not."""
    deep = tmp_path / "a" / "b" / "c" / "d"
    deep.mkdir(parents=True)
    monkeypatch.chdir(deep)
    assert artifacts._search_upward(deep) is None or artifacts._search_upward(deep).is_dir()


# ---- the consequences the bug actually had ---

def test_lane_discovery_finds_the_registry(monkeypatch):
    from kata.state.lanes import list_lane_ids

    monkeypatch.chdir(REPO)
    if not (REPO / "lanes" / "registry.json").is_file():
        pytest.skip("this checkout has no lane registry")
    assert list_lane_ids(), "lane discovery found no packs from the default root"


def test_the_king_copycat_screen_sees_the_reigning_king(monkeypatch, tmp_path):
    """The sharpest consequence: with the wrong root this ACCEPTED a verbatim copy of the king,
    because it had no king to compare against."""
    from kata.screening.similarity import screen_current_king_copycat

    king = REPO / "kings" / "sn60__bitsec" / "miner"
    if not (king / "agent.py").is_file():
        pytest.skip("no SN60 king in this checkout")

    monkeypatch.chdir(REPO)
    submission = tmp_path / "alice-20260729-01"
    submission.mkdir()
    for name in ("agent.py", "agent_manifest.json", "submission.json"):
        if (king / name).is_file():
            shutil.copy(king / name, submission / name)
    files = {p.name: p.read_text(encoding="utf-8", errors="replace")
             for p in submission.iterdir()}

    rejects, _reviews, _score = screen_current_king_copycat(
        submission_root=submission, bundle_files=files,
        subnet_pack="sn60__bitsec", mode="miner")
    assert rejects, "a verbatim copy of the reigning king was accepted"


def test_the_public_king_root_points_at_the_real_kings(monkeypatch):
    from kata.state.artifacts import resolve_public_king_root

    monkeypatch.chdir(REPO)
    resolved = resolve_public_king_root(
        public_root=None, subnet_pack="sn60__bitsec", mode="miner")
    assert resolved == REPO / "kings" / "sn60__bitsec" / "miner"
