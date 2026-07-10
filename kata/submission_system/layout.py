from __future__ import annotations

import json
import re
from dataclasses import asdict
from pathlib import Path

from kata.submission_system.constants import (
    DEFAULT_AGENT_PLACEHOLDER,
    SUBMISSION_AGENT_FILENAME,
    SUBMISSION_AGENT_MANIFEST_FILENAME,
    SUBMISSION_ID_CONVENTION,
    SUBMISSION_METADATA_FILENAME,
    SUBMISSIONS_DIRNAME,
    SUPPORTED_SUBMISSION_MODES,
)
from kata.submission_system.models import SubmissionDescriptor, SubmissionMetadata


def resolve_submission_descriptor(
    submission_root: Path,
    *,
    repo_root: Path | None,
    require_exists: bool = True,
) -> tuple[SubmissionDescriptor | None, list[str]]:
    reasons: list[str] = []
    root = submission_root.resolve()
    if require_exists:
        if not root.exists():
            return None, [f"Submission path does not exist: {submission_root}"]
        if not root.is_dir():
            return None, [f"Submission path must be a directory: {submission_root}"]

    if repo_root is not None:
        try:
            relative = root.relative_to(repo_root)
        except ValueError:
            return None, ["Submission path must live under the Kata repo root."]
        parts = relative.parts
    else:
        parts = root.parts
        if SUBMISSIONS_DIRNAME in parts:
            parts = parts[parts.index(SUBMISSIONS_DIRNAME) :]

    if len(parts) < 4 or parts[0] != SUBMISSIONS_DIRNAME:
        reasons.append(
            "Submission path must match `submissions/<subnet-pack>/<mode>/<submission-id>`."
        )
        return None, reasons

    repo_pack = parts[1]
    mode = parts[2]
    submission_id = parts[3]
    if mode not in SUPPORTED_SUBMISSION_MODES:
        reasons.append(
            "Submission mode must be one of: " + ", ".join(sorted(SUPPORTED_SUBMISSION_MODES))
        )
    return (
        SubmissionDescriptor(
            root=root,
            repo_pack=repo_pack,
            mode=mode,
            submission_id=submission_id,
            agent_path=root / SUBMISSION_AGENT_FILENAME,
            agent_manifest_path=root / SUBMISSION_AGENT_MANIFEST_FILENAME,
            metadata_path=root / SUBMISSION_METADATA_FILENAME,
        ),
        reasons,
    )


def load_submission_metadata(path: Path) -> SubmissionMetadata:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"Submission metadata must contain a JSON object: {path}")
    try:
        return SubmissionMetadata(
            schema_version=int(payload["schema_version"]),
            repo_pack=read_submission_subnet_pack(payload),
            mode=str(payload["mode"]),
            submission_id=str(payload["submission_id"]),
            created_at=str(payload["created_at"]),
            author=str(payload["author"]) if payload.get("author") is not None else None,
            title=str(payload["title"]) if payload.get("title") is not None else None,
            notes=str(payload["notes"]) if payload.get("notes") is not None else None,
        )
    except KeyError as exc:
        raise ValueError(f"Submission metadata is missing required field: {exc.args[0]}") from exc
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Submission metadata has an invalid field: {exc}") from exc


def read_submission_subnet_pack(payload: dict[str, object]) -> str:
    value = payload.get("subnet_pack", payload.get("repo_pack"))
    if value is None:
        raise KeyError("subnet_pack")
    return str(value)


def write_submission_metadata(path: Path, metadata: SubmissionMetadata) -> None:
    payload = asdict(metadata)
    payload["subnet_pack"] = payload.pop("repo_pack")
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def validate_submission_mode(mode: str) -> None:
    if mode not in SUPPORTED_SUBMISSION_MODES:
        raise ValueError(
            "Submission mode must be one of: " + ", ".join(sorted(SUPPORTED_SUBMISSION_MODES))
        )


def default_submissions_root() -> Path:
    return Path.cwd().resolve() / SUBMISSIONS_DIRNAME


def default_submission_agent() -> str:
    return (
        "from __future__ import annotations\n\n"
        '"""Kata submission scaffold for the miner lane."""\n\n'
        "def agent_main(\n"
        "    project_dir: str | None = None,\n"
        "    inference_api: str | None = None,\n"
        ") -> dict:\n"
        f"    # {DEFAULT_AGENT_PLACEHOLDER}\n"
        "    return {\n"
        '        "vulnerabilities": [],\n'
        "    }\n"
    )


def default_submission_notes() -> str:
    lines = [
        "Recommended conventions:",
        "- author: your GitHub username",
        f"- submission_id: {SUBMISSION_ID_CONVENTION}",
        "- implement a real agent in agent.py before opening the PR",
        "- optional Python helpers may live under helpers/",
    ]
    return "\n".join(lines) + "\n"


def required_submission_entrypoint_reason() -> str:
    return "Submission agent must define agent_main(...)."


def agent_defines_required_entrypoint(agent_source: str) -> bool:
    pattern = re.compile(r"(?m)^(?:async\s+)?def\s+agent_main\s*\(")
    return pattern.search(agent_source) is not None


def infer_submission_dirs(changed_paths: list[str]) -> list[str]:
    candidate_dirs: list[str] = []
    for changed_path in changed_paths:
        parts = Path(changed_path).parts
        if len(parts) < 5 or parts[0] != SUBMISSIONS_DIRNAME:
            continue
        candidate_dir = Path(*parts[:4]).as_posix()
        if candidate_dir not in candidate_dirs:
            candidate_dirs.append(candidate_dir)
    return candidate_dirs


def read_changed_paths_file(path: str) -> list[str]:
    file_path = Path(path).expanduser().resolve()
    return [
        line.strip() for line in file_path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


def normalize_changed_paths(changed_paths: list[str]) -> list[str]:
    normalized: list[str] = []
    for changed_path in changed_paths:
        value = changed_path.strip()
        if not value:
            continue
        normalized.append(value.strip("/"))
    return normalized
