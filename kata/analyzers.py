from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path

from kata.models import SourceFact
from kata.repository import RepositoryContext

COMMAND_PREFIXES = (
    "python",
    "pytest",
    "uv",
    "pip",
    "npm",
    "pnpm",
    "yarn",
    "cargo",
    "make",
    "cmake",
    "ctest",
    "ruff",
    "mypy",
    "pyright",
    "go test",
    "docker",
)

RULE_KEYWORDS = (
    "must",
    "required",
    "do not",
    "don't",
    "cannot",
    "should",
    "before you open",
    "protected",
    "forbidden",
    "not accepted",
    "review",
)

AGENT_RULE_KEYWORDS = (
    "must",
    "do not",
    "don't",
    "mandatory",
    "when in doubt",
)


def first_existing(root: Path, candidates: tuple[str, ...]) -> Path | None:
    for candidate in candidates:
        path = root / candidate
        if path.exists():
            return path
    return None


def read_text(path: Path | None) -> str:
    if path is None:
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def discover_repo_sources(repo: RepositoryContext) -> dict[str, Path | list[Path] | None]:
    workflows_root = repo.root / ".github" / "workflows"
    return {
        "readme": first_existing(repo.root, ("README.md", "README.rst")),
        "contributing": first_existing(repo.root, ("CONTRIBUTING.md", "CONTRIBUTING.rst")),
        "agents": first_existing(repo.root, ("AGENTS.md",)),
        "codeowners": first_existing(repo.root, (".github/CODEOWNERS", "CODEOWNERS")),
        "local_weights": first_existing(repo.root, (".gittensor/weights.json",)),
        "workflows": sorted(workflows_root.glob("*")) if workflows_root.exists() else [],
    }


def extract_title(readme_text: str) -> str | None:
    for line in readme_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            return stripped.lstrip("#").strip()
    return None


def extract_summary(readme_text: str, source: str) -> SourceFact | None:
    for paragraph in markdown_paragraphs(readme_text):
        cleaned = clean_markdown_text(paragraph)
        if is_summary_candidate(cleaned):
            return SourceFact(cleaned, source)
    return None


def extract_rules(text: str, source: str) -> list[SourceFact]:
    rules: list[SourceFact] = []
    source_is_agents = source.endswith("AGENTS.md")
    for candidate in sentence_candidates(text):
        cleaned = compress_rule_text(clean_markdown_text(candidate))
        lowered = cleaned.lower()
        if not is_rule_candidate(cleaned, lowered, source_is_agents):
            continue
        rules.append(SourceFact(cleaned, source))
    return dedupe_facts(rules, limit=8)


def extract_commands(text: str, source: str) -> list[SourceFact]:
    commands: list[SourceFact] = []
    commands.extend(extract_fenced_commands(text, source))
    commands.extend(extract_run_commands(text, source))
    return dedupe_facts(commands, limit=10)


def extract_protected_paths(codeowners_text: str, source: str) -> list[SourceFact]:
    facts: list[SourceFact] = []
    for raw_line in codeowners_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        path = line.split()[0]
        if path == "*":
            facts.append(SourceFact("Repository-wide ownership rules exist (`*`).", source))
            continue
        facts.append(SourceFact(f"`{path}`", source))
    return dedupe_facts(facts, limit=12)


def format_source_path(repo: RepositoryContext, path: Path) -> str:
    relative = path.relative_to(repo.root).as_posix()
    return f"repo:{relative}"


def markdown_paragraphs(text: str) -> list[str]:
    return [chunk.strip() for chunk in re.split(r"\n\s*\n", text) if chunk.strip()]


def sentence_candidates(text: str) -> list[str]:
    candidates: list[str] = []
    in_code_block = False
    paragraph_parts: list[str] = []
    list_item_parts: list[str] = []

    def flush_paragraph() -> None:
        if paragraph_parts:
            candidates.append(" ".join(paragraph_parts))
            paragraph_parts.clear()

    def flush_list_item() -> None:
        if list_item_parts:
            candidates.append(" ".join(list_item_parts))
            list_item_parts.clear()

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if line.strip().startswith("```"):
            flush_paragraph()
            flush_list_item()
            in_code_block = not in_code_block
            continue
        if in_code_block:
            continue
        stripped = line.strip()
        if not stripped:
            flush_paragraph()
            flush_list_item()
            continue
        if stripped.startswith("#"):
            flush_paragraph()
            flush_list_item()
            continue
        if stripped.startswith(("- ", "* ")):
            flush_paragraph()
            flush_list_item()
            list_item_parts.append(stripped[2:].strip())
            continue
        if re.match(r"^\d+\.\s+", stripped):
            flush_paragraph()
            flush_list_item()
            list_item_parts.append(re.sub(r"^\d+\.\s+", "", stripped))
            continue
        if list_item_parts:
            list_item_parts.append(stripped)
            continue
        paragraph_parts.append(stripped)
    flush_paragraph()
    flush_list_item()
    return candidates


def extract_fenced_commands(text: str, source: str) -> list[SourceFact]:
    facts: list[SourceFact] = []
    for block in re.findall(r"```(?:\w+)?\n(.*?)```", text, flags=re.DOTALL):
        for line in block.splitlines():
            command = normalize_command(line)
            if command:
                facts.append(SourceFact(command, source))
    return facts


def extract_run_commands(text: str, source: str) -> list[SourceFact]:
    facts: list[SourceFact] = []
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        raw_line = lines[index]
        match = re.match(r"^(\s*)run:\s*(.*)$", raw_line)
        if not match:
            index += 1
            continue
        indent = len(match.group(1))
        run_value = match.group(2).strip()
        if run_value and run_value != "|":
            command = normalize_command(run_value)
            if command:
                facts.append(SourceFact(command, source))
            index += 1
            continue
        index += 1
        while index < len(lines):
            nested_line = lines[index]
            if not nested_line.strip():
                index += 1
                continue
            nested_indent = len(nested_line) - len(nested_line.lstrip(" "))
            if nested_indent <= indent:
                break
            command = normalize_command(nested_line)
            if command:
                facts.append(SourceFact(command, source))
            index += 1
    return facts


def normalize_command(line: str) -> str | None:
    stripped = line.strip().lstrip("-").strip()
    if not stripped or stripped.startswith("#"):
        return None
    if any(marker in stripped for marker in ("${{", "$GITHUB_OUTPUT", ";;", 'echo "patterns=')):
        return None
    if "#" in stripped:
        stripped = stripped.split("#", 1)[0].rstrip()
    if stripped.endswith("\\"):
        return None
    lowered = stripped.lower()
    if any(lowered.startswith(prefix) for prefix in COMMAND_PREFIXES):
        return collapse_whitespace(stripped)
    inline_run = re.search(
        r"\brun\s+((?:pytest|python|uv|pip|npm|pnpm|yarn|cargo|make|cmake|ctest|ruff|"
        r"mypy|pyright|go test|docker)(?:\s+[a-z0-9:_./-]+)*)",
        lowered,
    )
    if inline_run:
        candidate = collapse_whitespace(stripped[inline_run.start(1) : inline_run.end(1)])
        if any(candidate.lower().startswith(prefix) for prefix in COMMAND_PREFIXES):
            return candidate
    return None


def clean_markdown_text(text: str) -> str:
    text = re.sub(r"\*\*([^*]+)\*\*", r"\1", text)
    text = re.sub(r"`([^`]+)`", r"\1", text)
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    text = re.sub(r"<[^>]+>", " ", text)
    return collapse_whitespace(text)


def is_summary_candidate(text: str) -> bool:
    if len(text) < 40:
        return False
    if text.startswith(("!", "<", "|")):
        return False
    if "alt=" in text.lower():
        return False
    if text.count(" ") < 5:
        return False
    return bool(re.search(r"[A-Za-z]", text))


def is_rule_candidate(cleaned: str, lowered: str, source_is_agents: bool) -> bool:
    if len(cleaned) < 25:
        return False
    if cleaned.count(" ") < 4:
        return False
    if not any(keyword in lowered for keyword in RULE_KEYWORDS):
        return False
    if source_is_agents and not any(keyword in lowered for keyword in AGENT_RULE_KEYWORDS):
        return False
    if "skill orchestrates" in lowered:
        return False
    if "/review-impl" in cleaned:
        return False
    if "open-source" in lowered and "rules engine" in lowered:
        return False
    if cleaned.endswith((":", "->")):
        return False
    return True


def collapse_whitespace(text: str) -> str:
    return " ".join(text.split())


def compress_rule_text(text: str) -> str:
    if len(text) <= 220:
        return text
    sentences = re.split(r"(?<=[.!?])\s+", text)
    if len(sentences) <= 1:
        return text
    first = sentences[0].strip()
    if len(first) >= 60 or len(sentences) == 2:
        return first
    return f"{first} {sentences[1].strip()}".strip()


def dedupe_facts(facts: Iterable[SourceFact], limit: int) -> list[SourceFact]:
    result: list[SourceFact] = []
    seen: set[str] = set()
    for fact in facts:
        key = fact.value
        if key in seen:
            continue
        seen.add(key)
        result.append(fact)
        if len(result) >= limit:
            break
    return result
