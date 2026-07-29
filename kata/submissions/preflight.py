"""Dependency-free preflight checks for submission bundles in the public repository.

This is the fast check used by branch protection and by contributors before opening a pull request.
It validates repository layout and cheap source-level rules without importing a subnet plugin or
installing third-party dependencies. Subnet scoring and authoritative screening remain owned by the
subnet packages.

Run it from a Kata source checkout:

    python -m kata.submissions.preflight submissions/sn60__bitsec/miner/<submission-id>
    python -m kata.submissions.preflight --all
"""

from __future__ import annotations

import argparse
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from kata.submissions.bundle import (
    AGENT_ENTRY_FILENAME,
    AGENT_MANIFEST_FILENAME,
    AGENT_MANIFEST_SCHEMA_VERSION,
    DEFAULT_AGENT_RUNTIME,
    HELPERS_DIRNAME,
    SEALED_KEY_FILENAME,
)
from kata.submissions.constants import (
    SUBMISSION_METADATA_FILENAME,
    SUBMISSION_SCHEMA_VERSION,
    SUBMISSIONS_DIRNAME,
)

SUBMISSION_MODE = "miner"
MAX_AGENT_BYTES = 1_000_000
SUBMISSION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}-\d{8}-\d{2}$")

# SN22's static screen repeats this dependency-free list. Its relay-only agent contract has no
# legitimate direct-network path; SN60, by contrast, must reach its in-room inference gateway.
SN22_DIRECT_NETWORK_MARKERS = (
    "import socket",
    "import requests",
    "import httpx",
    "urllib.request",
    "http.client",
    "import subprocess",
)


@dataclass(frozen=True)
class PackPreflightPolicy:
    """The small amount of pack policy the dependency-free repository gate must know."""

    banned_source_markers: tuple[str, ...] = ()
    banned_source_reason: str = ""


PACK_POLICIES = {
    "sn60__bitsec": PackPreflightPolicy(),
    "sn22__desearch": PackPreflightPolicy(
        banned_source_markers=SN22_DIRECT_NETWORK_MARKERS,
        banned_source_reason=(
            "sn22__desearch submissions reach providers through the broker capability, never "
            "directly, so this module reaches nothing"
        ),
    ),
}
SUPPORTED_PACKS = tuple(PACK_POLICIES)

# Shapes that mean someone committed a credential. Broad on purpose: a false positive costs one
# edit, while a false negative publishes a live key.
SECRET_SHAPES = (
    re.compile(r"\bsk-[A-Za-z0-9]{16,}"),
    re.compile(r"\bghp_[A-Za-z0-9]{20,}"),
    re.compile(r"\bapify_api_[A-Za-z0-9]{16,}", re.IGNORECASE),
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
)

ALLOWED_TOP_LEVEL_ENTRIES = frozenset(
    {
        AGENT_ENTRY_FILENAME,
        AGENT_MANIFEST_FILENAME,
        HELPERS_DIRNAME,
        SEALED_KEY_FILENAME,
        SUBMISSION_METADATA_FILENAME,
    }
)
REQUIRED_FILES = (
    AGENT_ENTRY_FILENAME,
    AGENT_MANIFEST_FILENAME,
    SUBMISSION_METADATA_FILENAME,
)


def default_repository_root() -> Path:
    """Return the source checkout containing this module."""

    return Path(__file__).resolve().parents[2]


def check_submission(
    root: Path,
    *,
    repository_root: Path | None = None,
) -> list[str]:
    """Return every preflight problem found in one submission directory."""

    repo_root = (repository_root or default_repository_root()).resolve()
    submission_root = root.resolve()
    problems: list[str] = []

    try:
        parts = submission_root.relative_to(repo_root).parts
    except ValueError:
        return [f"{submission_root} is not inside this repository"]
    if len(parts) != 4 or parts[0] != SUBMISSIONS_DIRNAME:
        return [
            f"{_relative(submission_root, repo_root)}: path must be "
            f"{SUBMISSIONS_DIRNAME}/<subnet-pack>/<mode>/<submission-id>"
        ]

    _, pack, mode, submission_id = parts
    if pack not in PACK_POLICIES:
        problems.append(
            f"subnet pack must be one of {', '.join(SUPPORTED_PACKS)}, got {pack!r}"
        )
    if mode != SUBMISSION_MODE:
        problems.append(f"mode must be {SUBMISSION_MODE!r}, got {mode!r}")
    if not SUBMISSION_ID_RE.fullmatch(submission_id):
        problems.append(
            f"submission id {submission_id!r} must be "
            "<github-username>-YYYYMMDD-NN, e.g. alice-20260727-01"
        )

    if not submission_root.is_dir():
        return problems + [f"{_relative(submission_root, repo_root)} is not a directory"]

    problems.extend(_check_required_files(submission_root))
    problems.extend(_check_bundle_shape(submission_root, repo_root))
    problems.extend(_check_manifest(submission_root / AGENT_MANIFEST_FILENAME))
    problems.extend(
        _check_metadata(
            submission_root / SUBMISSION_METADATA_FILENAME,
            pack=pack,
            submission_id=submission_id,
        )
    )
    problems.extend(_check_python_sources(submission_root, repo_root, pack=pack))
    problems.extend(_check_secrets(submission_root, repo_root))
    return problems


def _check_required_files(root: Path) -> list[str]:
    problems: list[str] = []
    for name in REQUIRED_FILES:
        path = root / name
        if not path.exists():
            problems.append(f"missing required file {name}")
        elif path.is_symlink() or not path.is_file():
            problems.append(f"{name} must be a regular file, not a symlink or directory")

    agent = root / AGENT_ENTRY_FILENAME
    if agent.is_file() and not agent.is_symlink() and agent.stat().st_size > MAX_AGENT_BYTES:
        problems.append(f"{AGENT_ENTRY_FILENAME} is over 1 MB")
    return problems


def _check_bundle_shape(root: Path, repository_root: Path) -> list[str]:
    problems: list[str] = []
    for entry in sorted(root.iterdir()):
        if entry.name.startswith("."):
            problems.append(f"remove hidden entry {entry.name}: the bundle ships as-is")
        elif entry.name not in ALLOWED_TOP_LEVEL_ENTRIES:
            allowed = ", ".join(sorted(ALLOWED_TOP_LEVEL_ENTRIES))
            problems.append(f"unexpected top-level entry {entry.name!r}; allowed: {allowed}")
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            problems.append(
                f"{_relative(path, repository_root)}: symlinks are not allowed anywhere in a bundle"
            )
    return problems


def _check_manifest(path: Path) -> list[str]:
    if not path.is_file():
        return []
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return [f"{AGENT_MANIFEST_FILENAME}: not valid JSON ({exc})"]
    if not isinstance(document, dict):
        return [f"{AGENT_MANIFEST_FILENAME}: must be a JSON object"]

    problems: list[str] = []
    if document.get("schema_version") != AGENT_MANIFEST_SCHEMA_VERSION:
        problems.append(
            f"{AGENT_MANIFEST_FILENAME}: schema_version must be "
            f"{AGENT_MANIFEST_SCHEMA_VERSION}"
        )
    if document.get("runtime") != DEFAULT_AGENT_RUNTIME:
        problems.append(
            f'{AGENT_MANIFEST_FILENAME}: runtime must be "{DEFAULT_AGENT_RUNTIME}"'
        )
    if document.get("entrypoint") != AGENT_ENTRY_FILENAME:
        problems.append(
            f'{AGENT_MANIFEST_FILENAME}: entrypoint must be "{AGENT_ENTRY_FILENAME}"'
        )
    return problems


def _check_metadata(path: Path, *, pack: str, submission_id: str) -> list[str]:
    if not path.is_file():
        return []
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return [f"{SUBMISSION_METADATA_FILENAME}: not valid JSON ({exc})"]
    if not isinstance(document, dict):
        return [f"{SUBMISSION_METADATA_FILENAME}: must be a JSON object"]

    problems: list[str] = []
    expected = {
        "schema_version": SUBMISSION_SCHEMA_VERSION,
        "subnet_pack": pack,
        "mode": SUBMISSION_MODE,
        "submission_id": submission_id,
    }
    for key, value in expected.items():
        if document.get(key) != value:
            problems.append(
                f"{SUBMISSION_METADATA_FILENAME}: {key} must be {value!r}, "
                f"got {document.get(key)!r}"
            )
    created_at = document.get("created_at")
    if not isinstance(created_at, str) or not created_at.strip():
        problems.append(
            f"{SUBMISSION_METADATA_FILENAME}: created_at must be an ISO-8601 timestamp"
        )
    return problems


def _check_python_sources(root: Path, repository_root: Path, *, pack: str) -> list[str]:
    problems: list[str] = []
    policy = PACK_POLICIES.get(pack, PackPreflightPolicy())
    for path in sorted(root.rglob("*.py")):
        if path.is_symlink() or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            problems.append(
                f"{_relative(path, repository_root)}: not readable as UTF-8 ({exc})"
            )
            continue
        for marker in policy.banned_source_markers:
            if marker in text:
                problems.append(
                    f"{_relative(path, repository_root)}: uses {marker!r}. "
                    f"{policy.banned_source_reason}"
                )
        try:
            compile(text, str(path), "exec")
        except SyntaxError as exc:
            problems.append(
                f"{_relative(path, repository_root)}: syntax error on line "
                f"{exc.lineno}: {exc.msg}"
            )
    return problems


def _check_secrets(root: Path, repository_root: Path) -> list[str]:
    problems: list[str] = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if any(shape.search(text) for shape in SECRET_SHAPES):
            problems.append(
                f"{_relative(path, repository_root)}: looks like it contains a credential. "
                "Remove it and ROTATE it — anything committed publicly is compromised"
            )
    return problems


def discover_submissions(repository_root: Path) -> list[Path]:
    """Return all submission directories handled by this repository gate."""

    found: list[Path] = []
    for pack in SUPPORTED_PACKS:
        base = repository_root / SUBMISSIONS_DIRNAME / pack / SUBMISSION_MODE
        if base.is_dir():
            found.extend(sorted(path for path in base.iterdir() if path.is_dir()))
    return found


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", help="Submission directories to check.")
    parser.add_argument("--all", action="store_true", help="Check every submission in the repo.")
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    repository_root: Path | None = None,
) -> int:
    """Run the dependency-free submission preflight CLI."""

    repo_root = (repository_root or default_repository_root()).resolve()
    args = build_parser().parse_args(argv)
    targets = [Path(path) for path in args.paths]
    if args.all or not targets:
        targets = discover_submissions(repo_root)
    if not targets:
        print("no submissions found")
        return 0

    failed = 0
    for target in targets:
        problems = check_submission(target, repository_root=repo_root)
        if problems:
            failed += 1
            print(f"FAIL  {_relative(target.resolve(), repo_root)}")
            for problem in problems:
                print(f"        {problem}")
        else:
            print(f"ok    {_relative(target.resolve(), repo_root)}")
    if failed:
        print(f"\n{failed} submission(s) would be rejected.")
    return 1 if failed else 0


def _relative(path: Path, repository_root: Path) -> str:
    try:
        return str(path.relative_to(repository_root))
    except ValueError:
        return str(path)


if __name__ == "__main__":
    raise SystemExit(main())
