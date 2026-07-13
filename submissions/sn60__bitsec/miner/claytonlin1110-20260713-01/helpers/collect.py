from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

SOURCE_SUFFIXES = {".sol", ".vy", ".cairo"}
IGNORED_DIRS = {
    ".git",
    ".github",
    ".venv",
    "artifacts",
    "broadcast",
    "cache",
    "coverage",
    "dist",
    "docs",
    "example",
    "examples",
    "lib",
    "node_modules",
    "out",
    "script",
    "scripts",
    "target",
    "test",
    "tests",
    "vendor",
}
MAX_FILES = 80
MAX_BYTES = 300_000


@dataclass(frozen=True)
class SourceFile:
    rel: str
    text: str
    suffix: str


def resolve_project_root(project_dir: str | None) -> Path | None:
    candidates: list[str] = []
    if project_dir:
        candidates.append(project_dir)
    for key in ("PROJECT_DIR", "PROJECT_PATH", "PROJECT_ROOT", "PROJECT_CODE"):
        value = os.environ.get(key)
        if value:
            candidates.append(value)
    candidates.extend(("/app/project_code", "/app/project", "/project", "/code", "."))
    for raw in candidates:
        try:
            path = Path(raw).expanduser().resolve()
        except (OSError, RuntimeError):
            continue
        if path.is_dir() and _has_sources(path):
            return path
    return None


def collect_sources(root: Path) -> list[SourceFile]:
    files: list[SourceFile] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        if _should_skip(path, root):
            continue
        try:
            if path.stat().st_size > MAX_BYTES:
                continue
        except OSError:
            continue
        text = _read(path)
        if not text.strip():
            continue
        rel = path.relative_to(root).as_posix()
        files.append(SourceFile(rel=rel, text=text, suffix=path.suffix.lower()))
        if len(files) >= MAX_FILES:
            break
    return files


def _has_sources(root: Path) -> bool:
    try:
        for path in root.rglob("*"):
            if path.is_file() and path.suffix.lower() in SOURCE_SUFFIXES:
                return True
    except OSError:
        return False
    return False


def _should_skip(path: Path, root: Path) -> bool:
    try:
        rel = path.relative_to(root)
    except ValueError:
        return True
    for part in rel.parts[:-1]:
        low = part.lower()
        if low in IGNORED_DIRS or low.startswith("."):
            return True
    name = rel.name.lower()
    return name.endswith((".t.sol", ".s.sol", "_test.sol", ".test.sol"))


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""
