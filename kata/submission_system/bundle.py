"""Submission bundle file IO, manifest, and safety helpers."""

from __future__ import annotations

import json
import shutil
from dataclasses import asdict, dataclass
from pathlib import Path

AGENT_ENTRY_FILENAME = "agent.py"
AGENT_MANIFEST_FILENAME = "agent_manifest.json"
# The miner's inference key, sealed to the room (sealed-room / TEE execution). Ciphertext,
# only openable inside the attested room -- safe to carry in the public submission bundle.
SEALED_KEY_FILENAME = "sealed_inference_key"
HELPERS_DIRNAME = "helpers"
AGENT_MANIFEST_SCHEMA_VERSION = 1
DEFAULT_AGENT_RUNTIME = "python"
IGNORED_BUNDLE_DIRS = {"__pycache__"}
IGNORED_BUNDLE_SUFFIXES = {".pyc", ".pyo"}


@dataclass(frozen=True)
class AgentManifest:
    schema_version: int
    runtime: str
    entrypoint: str


def default_agent_manifest() -> AgentManifest:
    return AgentManifest(
        schema_version=AGENT_MANIFEST_SCHEMA_VERSION,
        runtime=DEFAULT_AGENT_RUNTIME,
        entrypoint=AGENT_ENTRY_FILENAME,
    )


def write_agent_manifest(path: Path, manifest: AgentManifest | None = None) -> None:
    payload = asdict(manifest or default_agent_manifest())
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def load_agent_manifest(path: Path) -> AgentManifest:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"Agent manifest must contain a JSON object: {path}")
    return AgentManifest(
        schema_version=int(payload["schema_version"]),
        runtime=str(payload["runtime"]),
        entrypoint=str(payload["entrypoint"]),
    )


def validate_agent_manifest(path: Path) -> list[str]:
    reasons: list[str] = []
    try:
        manifest = load_agent_manifest(path)
    except (ValueError, TypeError, json.JSONDecodeError, KeyError) as exc:
        return [str(exc)]
    if manifest.schema_version != AGENT_MANIFEST_SCHEMA_VERSION:
        reasons.append(
            "Unsupported agent_manifest.json schema version: "
            f"{manifest.schema_version}. Expected {AGENT_MANIFEST_SCHEMA_VERSION}."
        )
    if manifest.runtime != DEFAULT_AGENT_RUNTIME:
        reasons.append(
            "agent_manifest.json runtime must be `python` for the current Kata validator."
        )
    if manifest.entrypoint != AGENT_ENTRY_FILENAME:
        reasons.append(
            "agent_manifest.json entrypoint must be `agent.py` for the current Kata validator."
        )
    return reasons


def is_allowed_bundle_relative_path(relative_path: str) -> bool:
    path = Path(relative_path)
    if path.is_absolute():
        return False
    if any(part in {"..", ""} for part in path.parts):
        return False
    if path.as_posix() in {AGENT_ENTRY_FILENAME, AGENT_MANIFEST_FILENAME, SEALED_KEY_FILENAME}:
        return True
    if not path.parts or path.parts[0] != HELPERS_DIRNAME:
        return False
    if path.suffix != ".py":
        return False
    return len(path.parts) >= 2


def collect_bundle_relative_paths(root: Path) -> list[str]:
    relative_paths: list[str] = []
    for file_path in sorted(root.rglob("*")):
        if file_path.is_symlink() or not file_path.is_file():
            continue
        if should_ignore_bundle_path(file_path.relative_to(root)):
            continue
        relative_path = file_path.relative_to(root).as_posix()
        if is_allowed_bundle_relative_path(relative_path):
            relative_paths.append(relative_path)
    return relative_paths


def find_unexpected_bundle_paths(root: Path) -> list[str]:
    unexpected: list[str] = []
    for file_path in sorted(root.rglob("*")):
        if file_path.is_symlink() or not file_path.is_file():
            continue
        relative = file_path.relative_to(root)
        if should_ignore_bundle_path(relative):
            continue
        relative_path = relative.as_posix()
        if relative_path == "submission.json":
            continue
        if not is_allowed_bundle_relative_path(relative_path):
            unexpected.append(relative_path)
    return unexpected


def should_ignore_bundle_path(relative_path: Path) -> bool:
    if any(part in IGNORED_BUNDLE_DIRS for part in relative_path.parts):
        return True
    if relative_path.suffix in IGNORED_BUNDLE_SUFFIXES:
        return True
    return False


def load_bundle_files(root: Path) -> dict[str, str]:
    bundle_files: dict[str, str] = {}
    for relative_path in collect_bundle_relative_paths(root):
        bundle_files[relative_path] = (root / relative_path).read_text(encoding="utf-8")
    return bundle_files


def write_bundle_files(root: Path, files: dict[str, str]) -> None:
    for relative_path, content in files.items():
        path = root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content.rstrip() + "\n", encoding="utf-8")


def replace_bundle_contents(destination_root: Path, files: dict[str, str]) -> None:
    if destination_root.exists():
        for child in destination_root.iterdir():
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()
    destination_root.mkdir(parents=True, exist_ok=True)
    write_bundle_files(destination_root, files)
