from __future__ import annotations

import re
import subprocess
from pathlib import Path

ALWAYS_INCLUDE = (
    "README.md",
    "CONTRIBUTING.md",
    "package.json",
    ".github/CODEOWNERS",
)
TEXT_SUFFIXES = {".md", ".mdx", ".json", ".txt", ".yml", ".yaml"}
MAX_FILE_BYTES = 8000
MAX_TOTAL_BYTES = 50000
MAX_FILES = 14
STOP_WORDS = {
    "the",
    "and",
    "for",
    "with",
    "from",
    "that",
    "this",
    "into",
    "only",
    "file",
    "files",
    "article",
    "articles",
    "repo",
    "repository",
    "content",
    "page",
    "pages",
    "fix",
    "add",
    "update",
    "write",
    "edit",
    "change",
    "make",
}


def build_repo_context(*, repo_root: Path, issue: str) -> str:
    tracked_files = list_tracked_files(repo_root)
    ranked = rank_paths(tracked_files, issue)
    selected = select_files(repo_root, ranked)
    file_sections = [render_file_section(repo_root, relative_path) for relative_path in selected]
    file_sections = [section for section in file_sections if section]
    return (
        "## Priority Files\n"
        + "\n".join(f"- {path}" for path in selected)
        + "\n\n## Repository File Index\n"
        + "\n".join(f"- {path}" for path in ranked[:80])
        + "\n\n## File Contents\n"
        + ("\n\n".join(file_sections) if file_sections else "(no file contents captured)")
    )


def list_tracked_files(repo_root: Path) -> list[str]:
    completed = subprocess.run(
        ["git", "ls-files"],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode == 0:
        return [line.strip() for line in completed.stdout.splitlines() if line.strip()]
    return [
        path.relative_to(repo_root).as_posix()
        for path in sorted(repo_root.rglob("*"))
        if path.is_file()
    ]


def rank_paths(paths: list[str], issue: str) -> list[str]:
    explicit_paths = extract_explicit_paths(issue)
    keywords = extract_keywords(issue)
    scored = sorted(paths, key=lambda path: score_path(path, explicit_paths, keywords), reverse=True)
    return dedupe_paths(scored)


def extract_explicit_paths(issue: str) -> set[str]:
    return set(re.findall(r"(?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]+", issue))


def extract_keywords(issue: str) -> list[str]:
    parts = re.split(r"[^A-Za-z0-9]+", issue.lower())
    return [
        part
        for part in parts
        if len(part) >= 3 and part not in STOP_WORDS
    ]


def score_path(path: str, explicit_paths: set[str], keywords: list[str]) -> tuple[int, int, int, str]:
    score = 0
    if path in ALWAYS_INCLUDE:
        score += 200
    if any(path == explicit or path.startswith(explicit.rstrip("/") + "/") for explicit in explicit_paths):
        score += 400
    if path.startswith("content/pages/"):
        score += 120
    if path.endswith("/index.mdx"):
        score += 40
    name = path.lower()
    keyword_hits = 0
    for keyword in keywords:
        if keyword in name:
            score += 35
            keyword_hits += 1
    return (score, keyword_hits, -len(path), path)


def select_files(repo_root: Path, ranked_paths: list[str]) -> list[str]:
    selected: list[str] = []
    total_bytes = 0
    for relative_path in ranked_paths:
        if len(selected) >= MAX_FILES:
            break
        absolute_path = repo_root / relative_path
        if not absolute_path.is_file():
            continue
        if absolute_path.suffix.lower() not in TEXT_SUFFIXES and relative_path not in ALWAYS_INCLUDE:
            continue
        file_size = absolute_path.stat().st_size
        if file_size > MAX_FILE_BYTES:
            continue
        if total_bytes + file_size > MAX_TOTAL_BYTES:
            continue
        selected.append(relative_path)
        total_bytes += file_size
    return selected


def render_file_section(repo_root: Path, relative_path: str) -> str:
    absolute_path = repo_root / relative_path
    try:
        content = absolute_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return ""
    return f"### FILE: {relative_path}\n```\n{content.rstrip()}\n```"


def dedupe_paths(paths: list[str]) -> list[str]:
    unique: list[str] = []
    seen: set[str] = set()
    for path in paths:
        if path in seen:
            continue
        unique.append(path)
        seen.add(path)
    return unique
