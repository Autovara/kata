#!/usr/bin/env python3
"""Check one submission against the layout and screening rules, offline.

The point is to fail *here* rather than on a closed pull request. Every rule below is one the bot
enforces, so a clean run means the layout will not be the reason your PR is rejected. It cannot tell
you whether your agent is any good, and it does not know any subnet's scoring rules -- those live in
that subnet's own repository.

Deliberately dependency-free and standard-library only, for the same reason a submission is: it has
to run identically on a contributor's laptop and in CI, with nothing installed.

    python tools/check_submission.py submissions/sn22__desearch/miner/<dir>
    python tools/check_submission.py submissions/sn60__bitsec/miner/<dir>
    python tools/check_submission.py --all
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

#: Every subnet that takes submissions in this repository. A PR's subnet is decided by which of
#: these directories it lands in -- there is nothing to declare, and nothing that can disagree.
LANE_PACKS = ("sn60__bitsec", "sn22__desearch")
LANE_MODE = "miner"
SUBMISSIONS_DIRNAME = "submissions"

SUBMISSION_SCHEMA_VERSION = 2
AGENT_MANIFEST_SCHEMA_VERSION = 1
AGENT_FILENAME = "agent.py"
AGENT_MANIFEST_FILENAME = "agent_manifest.json"
METADATA_FILENAME = "submission.json"
HELPERS_DIRNAME = "helpers"

#: ``<github-username>-YYYYMMDD-NN``. Dated and sequenced so two submissions from one author are
#: distinguishable in a listing without opening either.
SUBMISSION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}-\d{8}-\d{2}$")

MAX_AGENT_BYTES = 1_000_000

#: The static screen's list, reproduced exactly. Under ``relay_only`` these modules reach nothing,
#: so their presence says the submission expects to contact providers itself.
BANNED_IMPORTS = ("import socket", "import requests", "import httpx", "urllib.request",
                  "http.client", "import subprocess")

#: Shapes that mean someone committed a credential. Broad on purpose: a false positive costs one
#: edit, a false negative publishes a live key.
SECRET_SHAPES = (
    re.compile(r"\bsk-[A-Za-z0-9]{16,}"),
    re.compile(r"\bghp_[A-Za-z0-9]{20,}"),
    re.compile(r"\bapify_api_[A-Za-z0-9]{16,}", re.IGNORECASE),
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
)


def _rel(path: Path) -> str:
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def check_submission(root: Path) -> list[str]:
    """Every problem with one submission directory, or an empty list."""
    problems: list[str] = []
    root = root.resolve()

    # ---- location ------------------------------------------------------------------------------
    try:
        parts = root.relative_to(REPO_ROOT).parts
    except ValueError:
        return [f"{root} is not inside this repository"]
    if len(parts) != 4 or parts[0] != SUBMISSIONS_DIRNAME:
        return [f"{_rel(root)}: path must be "
                f"{SUBMISSIONS_DIRNAME}/<subnet-pack>/<mode>/<submission-id>"]
    _, pack, mode, submission_id = parts
    if pack not in LANE_PACKS:
        problems.append(f"subnet pack must be one of {', '.join(LANE_PACKS)}, got {pack!r}")
    if mode != LANE_MODE:
        problems.append(f"mode must be {LANE_MODE!r}, got {mode!r}")
    if not SUBMISSION_ID_RE.fullmatch(submission_id):
        problems.append(f"submission id {submission_id!r} must be "
                        f"<github-username>-YYYYMMDD-NN, e.g. alice-20260727-01")

    if not root.is_dir():
        return problems + [f"{_rel(root)} is not a directory"]

    # ---- required files ------------------------------------------------------------------------
    for name in (AGENT_FILENAME, AGENT_MANIFEST_FILENAME, METADATA_FILENAME):
        path = root / name
        if not path.exists():
            problems.append(f"missing required file {name}")
        elif path.is_symlink() or not path.is_file():
            problems.append(f"{name} must be a regular file, not a symlink or directory")

    agent = root / AGENT_FILENAME
    if agent.is_file() and not agent.is_symlink() and agent.stat().st_size > MAX_AGENT_BYTES:
        problems.append(f"{AGENT_FILENAME} is over 1 MB")

    # ---- bundle shape --------------------------------------------------------------------------
    allowed_top = {AGENT_FILENAME, AGENT_MANIFEST_FILENAME, METADATA_FILENAME, HELPERS_DIRNAME}
    for entry in sorted(root.iterdir()):
        if entry.name.startswith("."):
            problems.append(f"remove hidden entry {entry.name}: the bundle ships as-is")
        elif entry.name not in allowed_top:
            problems.append(f"unexpected top-level entry {entry.name!r}; allowed: "
                            f"{', '.join(sorted(allowed_top))}")
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            problems.append(f"{_rel(path)}: symlinks are not allowed anywhere in a bundle")

    # ---- manifests -----------------------------------------------------------------------------
    problems.extend(_check_manifest(root / AGENT_MANIFEST_FILENAME))
    problems.extend(_check_metadata(root / METADATA_FILENAME, pack, submission_id))

    # ---- source --------------------------------------------------------------------------------
    for path in sorted(root.rglob("*.py")):
        if path.is_symlink() or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            problems.append(f"{_rel(path)}: not readable as UTF-8 ({exc})")
            continue
        for marker in BANNED_IMPORTS:
            if marker in text:
                problems.append(f"{_rel(path)}: uses {marker!r}. The sandbox has no network; "
                                f"reach search through the relay capability instead")
        try:
            compile(text, str(path), "exec")
        except SyntaxError as exc:
            problems.append(f"{_rel(path)}: syntax error on line {exc.lineno}: {exc.msg}")

    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for shape in SECRET_SHAPES:
            if shape.search(text):
                problems.append(f"{_rel(path)}: looks like it contains a credential. Remove it and "
                                f"ROTATE it — anything committed publicly is compromised")
                break

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
    problems = []
    if document.get("schema_version") != AGENT_MANIFEST_SCHEMA_VERSION:
        problems.append(f"{AGENT_MANIFEST_FILENAME}: schema_version must be "
                        f"{AGENT_MANIFEST_SCHEMA_VERSION}")
    if document.get("runtime") != "python":
        problems.append(f"{AGENT_MANIFEST_FILENAME}: runtime must be \"python\"")
    if document.get("entrypoint") != AGENT_FILENAME:
        problems.append(f"{AGENT_MANIFEST_FILENAME}: entrypoint must be \"{AGENT_FILENAME}\"")
    return problems


def _check_metadata(path: Path, pack: str, submission_id: str) -> list[str]:
    if not path.is_file():
        return []
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return [f"{METADATA_FILENAME}: not valid JSON ({exc})"]
    if not isinstance(document, dict):
        return [f"{METADATA_FILENAME}: must be a JSON object"]
    problems = []
    expected = {"schema_version": SUBMISSION_SCHEMA_VERSION, "subnet_pack": pack,
                "mode": LANE_MODE, "submission_id": submission_id}
    for key, value in expected.items():
        if document.get(key) != value:
            problems.append(f"{METADATA_FILENAME}: {key} must be {value!r}, "
                            f"got {document.get(key)!r}")
    created = document.get("created_at")
    if not isinstance(created, str) or not created.strip():
        problems.append(f"{METADATA_FILENAME}: created_at must be an ISO-8601 timestamp")
    return problems


def discover(root: Path) -> list[Path]:
    found: list[Path] = []
    for pack in LANE_PACKS:
        base = root / SUBMISSIONS_DIRNAME / pack / LANE_MODE
        if base.is_dir():
            found.extend(sorted(p for p in base.iterdir() if p.is_dir()))
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", help="Submission directories to check.")
    parser.add_argument("--all", action="store_true", help="Check every submission in the repo.")
    args = parser.parse_args()

    targets = [Path(p) for p in args.paths]
    if args.all or not targets:
        targets = discover(REPO_ROOT)
    if not targets:
        print("no submissions found")
        return 0

    failed = 0
    for target in targets:
        problems = check_submission(target)
        if problems:
            failed += 1
            print(f"FAIL  {_rel(target.resolve())}")
            for problem in problems:
                print(f"        {problem}")
        else:
            print(f"ok    {_rel(target.resolve())}")
    if failed:
        print(f"\n{failed} submission(s) would be rejected.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
