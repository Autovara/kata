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
#: ``sn60__bitsec``. Checked so a policy key cannot be a path fragment or a stray JSON key.
PACK_NAME_RE = re.compile(r"^[a-z0-9]+__[a-z0-9_]+$")

#: Where each pack's policy is published, relative to the competition root.
#:
#: This gate used to carry a literal table of subnet names. That made a general framework know two
#: specific subnets, and getting the table wrong rejected every correct SN60 agent (issue #209).
#:
#: Whether a submission may reach the network is a property of the SUBNET's agent contract, so the
#: subnet declares it in its own ``deploy/settings.json`` and kata-subnets-deploy publishes it here
#: as data. The gate reads; it does not know.
#:
#: Data rather than an import because this gate is dependency-free on purpose:
#: ``validate-submission.yml`` runs it on a bare Python with no ``pip install``, and CI checks out
#: only the competition repository, so no plugin is importable at the moment the question is asked.
POLICIES_RELATIVE_PATH = Path("submissions") / "policies.json"
POLICIES_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class PackPreflightPolicy:
    """One pack's answer to "may a submission reach the network itself?"."""

    banned_source_markers: tuple[str, ...] = ()
    banned_source_reason: str = ""


#: The policy applied to a pack the published document does not describe.
#:
#: FAILS CLOSED, and the two ways of being wrong are not symmetric. Applying a ban a pack does not
#: want rejects honest submissions loudly, and the contributor says so within the hour. Skipping a
#: ban a pack does need removes a guarantee silently, and nobody finds out until someone exploits
#: it. So an undeclared pack gets the strictest rule anyone declared.
UNDECLARED_PACK_REASON = (
    "this pack publishes no submission policy, so the strictest known rule is applied. Declare "
    "submission_policy in the subnet's deploy/settings.json and republish "
    "submissions/policies.json"
)


class PolicyDocumentError(Exception):
    """The published policy document cannot be trusted.

    Raised rather than degraded-to-a-default on purpose. The earlier version skipped entries it
    could not parse and dropped markers of the wrong type, which turned a corrupt *security rule*
    into a quietly permissive one: ``banned_source_markers: [42]`` became ``()``, and the string
    ``"urllib"`` became the six single-character bans ``('u','r','l','l','i','b')``. Both read as a
    successful load. A rule nobody can parse is not a weaker rule; it is an unknown one.
    """


def _require(condition: object, message: str) -> None:
    if not condition:
        raise PolicyDocumentError(message)


def load_pack_policies(repository_root: Path) -> dict[str, PackPreflightPolicy]:
    """Every pack's policy, as published into the competition repository.

    Validated as a COMPLETE UNIT: any invalid shape anywhere fails the whole document. Partial
    acceptance would mean the gate enforcing some rules while believing it enforced all of them,
    and the packs whose entries were dropped are exactly the ones nobody would notice.

    Raises ``PolicyDocumentError`` if the document is missing, unreadable or invalid in any way.
    Callers must treat that as a refusal to check, never as "nothing to check".
    """
    path = repository_root / POLICIES_RELATIVE_PATH
    republish = "Republish with kata-subnets-deploy/installer/generate_submission_policies.py"
    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyDocumentError(
            f"cannot read {POLICIES_RELATIVE_PATH}: {exc}. {republish}"
        ) from exc
    try:
        document = json.loads(raw_text)
    except ValueError as exc:
        raise PolicyDocumentError(
            f"{POLICIES_RELATIVE_PATH} is not valid JSON: {exc}"
        ) from exc

    _require(isinstance(document, dict), f"{POLICIES_RELATIVE_PATH}: top level must be an object")
    _require(
        document.get("schema_version") == POLICIES_SCHEMA_VERSION,
        f"{POLICIES_RELATIVE_PATH}: schema_version must be {POLICIES_SCHEMA_VERSION}, got "
        f"{document.get('schema_version')!r}. {republish}",
    )
    entries = document.get("policies")
    _require(isinstance(entries, dict), f"{POLICIES_RELATIVE_PATH}: policies must be an object")
    _require(
        entries,
        f"{POLICIES_RELATIVE_PATH}: declares no policies. An empty document cannot be "
        f"distinguished from a document that failed to generate. {republish}",
    )

    policies: dict[str, PackPreflightPolicy] = {}
    for pack, entry in entries.items():
        where = f"{POLICIES_RELATIVE_PATH}: policy {pack!r}"
        _require(PACK_NAME_RE.fullmatch(pack), f"{where}: not a valid subnet pack name")
        _require(isinstance(entry, dict), f"{where}: must be an object")

        allowed = entry.get("direct_network_allowed")
        _require(
            isinstance(allowed, bool),
            f"{where}: direct_network_allowed must be true or false, got {allowed!r}",
        )

        markers = entry.get("banned_source_markers")
        # A bare string is the dangerous shape: it is iterable, so a laxer check would accept it
        # and ban individual letters.
        _require(
            isinstance(markers, list),
            f"{where}: banned_source_markers must be a list, got {type(markers).__name__}",
        )
        for marker in markers:
            _require(
                isinstance(marker, str) and marker,
                f"{where}: every banned_source_marker must be a non-empty string, got {marker!r}",
            )

        # The two fields must agree, or the document says one thing and enforces another.
        _require(
            not (allowed and markers),
            f"{where}: direct_network_allowed is true but bans {len(markers)} source marker(s)",
        )
        _require(
            allowed or markers,
            f"{where}: direct_network_allowed is false but bans nothing, so the rule does nothing",
        )

        reason = entry.get("banned_source_reason")
        _require(isinstance(reason, str), f"{where}: banned_source_reason must be a string")
        _require(
            reason or not markers,
            f"{where}: bans source markers but gives no reason. The reason is what a contributor "
            f"reads when their submission is refused",
        )
        policies[pack] = PackPreflightPolicy(
            banned_source_markers=tuple(markers), banned_source_reason=reason
        )
    return policies


def strictest_policy(policies: dict[str, PackPreflightPolicy]) -> PackPreflightPolicy:
    """The union of every declared ban -- what an undeclared pack is held to."""
    markers: tuple[str, ...] = ()
    for policy in policies.values():
        markers += tuple(m for m in policy.banned_source_markers if m not in markers)
    return PackPreflightPolicy(banned_source_markers=markers,
                               banned_source_reason=UNDECLARED_PACK_REASON)

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
    try:
        known_packs = tuple(sorted(load_pack_policies(repo_root)))
    except PolicyDocumentError as exc:
        # Every source rule in this gate is read from that document. Reporting anything other than
        # a failure would be reporting on rules that were never applied.
        return [str(exc)]
    if pack not in known_packs:
        problems.append(
            f"subnet pack must be one of {', '.join(known_packs)}, got {pack!r}"
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
    # Reached only after check_submission has loaded the document successfully.
    policies = load_pack_policies(repository_root)
    policy = policies.get(pack) or strictest_policy(policies)
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
    """Every submission directory present in the tree.

    Deliberately independent of the policy document. An earlier version iterated the policy KEYS,
    which meant a missing or undeclared pack made real submissions invisible: ``--all`` -- the form
    branch protection runs -- printed "no submissions found" and exited 0 with an unchecked agent
    sitting in the tree. Discovery must answer "what was submitted", a question about the
    repository; only the CHECKING of a submission depends on policy.

    So a submission under an unknown pack is still found here, and rejected downstream by name.
    """
    base = repository_root / SUBMISSIONS_DIRNAME
    if not base.is_dir():
        return []
    found: list[Path] = []
    for pack in sorted(path for path in base.iterdir() if path.is_dir()):
        mode = pack / SUBMISSION_MODE
        if mode.is_dir():
            found.extend(sorted(path for path in mode.iterdir() if path.is_dir()))
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

    # Validated up front, and fatal, even when the tree is empty. An empty repository is a
    # legitimate state; a repository whose security rules will not load is not, and the two used to
    # produce the same silent success. This runs on every pull request, so the document is proven
    # loadable on each one rather than on the first round that happens to have a submission.
    try:
        load_pack_policies(repo_root)
    except PolicyDocumentError as exc:
        print(f"cannot check submissions: {exc}")
        return 2

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
