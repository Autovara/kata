from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass
from difflib import unified_diff
from pathlib import Path

REQUEST_TIMEOUT_SECONDS = 50
MAX_MODEL_ATTEMPTS = 3
MAX_TARGET_BYTES = 32000
MAX_RELATED_BYTES = 14000
MAX_TOTAL_CONTEXT_BYTES = 110000
MAX_RELATED_FILES = 6
MAX_INDEX_ARTICLES = 180
MAX_ERROR_CHARS = 3000

FILE_PATH_PATTERN = re.compile(
    r"`([^`]+?\.(?:mdx|md|json|ya?ml|toml|txt|ts|tsx|js|jsx|py))`"
)
WIKI_LINK_PATTERN = re.compile(r"\[\[([^\]|]+)(?:\|[^\]]+)?\]\]")
HTTP_LINK_PATTERN = re.compile(r"(?<!\!)\[[^\]]+\]\(https?://[^)]+\)", re.IGNORECASE)
HEADING_PATTERN = re.compile(r"^(#{1,3}\s+.+)$", re.MULTILINE)
TOKEN_PATTERN = re.compile(r"[a-z0-9_]+")
FENCE_PATTERN = re.compile(r"^[ \t]*(```|~~~)", re.MULTILINE)

SYSTEM_PROMPT = """You are a Taopedia contributor agent competing in Kata.

Solve the task using only the repository snapshot and task description.

Output contract:
- Return JSON only.
- JSON schema:
  {
    "summary": "short sentence",
    "files": [
      {
        "path": "relative/path",
        "content": "full final file content"
      }
    ]
  }
- `files` must contain only files that should change.
- Each `content` value must be the complete final file contents, not a diff.

Taopedia repo rules:
- Articles live under `content/pages/<slug>/index.mdx`.
- Keep edits narrow and preserve unrelated wording, front matter, and structure when possible.
- Sources are required for factual and technical claims.
- Internal article links should use `[[Article Title]]`.
- Published articles must not contain fenced code blocks.
- Do not use `Bittensor` as a catch-all category or tag.
- Prefer official docs, release notes, specs, and implementation repos.
- If the task says "fix", replace or remove the wrong statement instead of adding duplicates.
- If the task says "improve", make the smallest complete source-backed improvement.
- If asked for a distinction, add a concise `## Distinction from ...` section.
"""


@dataclass(frozen=True)
class TaskSpec:
    title: str
    target_paths: tuple[str, ...]
    target_article_paths: tuple[str, ...]
    tokens: frozenset[str]
    wants_distinction: bool


@dataclass(frozen=True)
class ModelResponse:
    summary: str
    files: dict[str, str]


def solve(repo_path: str, issue: str, model: str, api_base: str, api_key: str) -> dict:
    if not model:
        return {"success": False, "message": "validator did not provide a model", "diff": ""}
    if not api_base:
        return {"success": False, "message": "validator did not provide an api_base", "diff": ""}

    repo_root = Path(repo_path).resolve()
    task = parse_task(repo_root, issue)
    repo_context = build_repo_context(repo_root, task)

    repair_notes = ""
    last_error = "model did not return a valid proposal"
    for _ in range(MAX_MODEL_ATTEMPTS):
        response_text = request_candidate(
            model=model,
            api_base=api_base,
            api_key=api_key,
            issue=issue,
            repo_context=repo_context,
            repair_notes=repair_notes,
        )
        try:
            candidate = parse_model_response(response_text)
            diff_text = build_candidate_diff(repo_root, task, candidate)
            validation_errors = validate_candidate(repo_root, task, candidate, diff_text)
            if not validation_errors:
                return {
                    "success": True,
                    "message": candidate.summary or "validated Taopedia candidate diff",
                    "diff": diff_text,
                }
            last_error = "; ".join(validation_errors)
            repair_notes = build_repair_notes(candidate, validation_errors)
        except Exception as exc:
            last_error = str(exc)
            repair_notes = (
                "The previous response was unusable.\n"
                f"Error: {truncate(last_error, MAX_ERROR_CHARS)}\n"
                "Return corrected JSON only."
            )

    return {
        "success": False,
        "message": f"unable to produce a valid patch: {truncate(last_error, 240)}",
        "diff": "",
    }


def parse_task(repo_root: Path, issue: str) -> TaskSpec:
    title = first_nonempty_line(issue)
    raw_paths = tuple(
        dict.fromkeys(path for path in FILE_PATH_PATTERN.findall(issue) if not path.startswith("."))
    )
    raw_tokens = set(TOKEN_PATTERN.findall(issue.lower()))
    noisy_tokens = {
        "task",
        "title",
        "goal",
        "fix",
        "improve",
        "update",
        "change",
        "content",
        "pages",
        "index",
        "mdx",
        "article",
        "repo",
        "file",
    }
    tokens = frozenset(
        token for token in raw_tokens if len(token) > 2 and token not in noisy_tokens
    )

    article_map = discover_article_map(repo_root)
    explicit_article_paths = tuple(path for path in raw_paths if path.startswith("content/pages/"))
    inferred_article_paths = infer_article_paths(issue, tokens, article_map)
    target_article_paths = explicit_article_paths or inferred_article_paths
    target_paths = tuple(dict.fromkeys(raw_paths or target_article_paths))
    wants_distinction = "distinction" in raw_tokens or "distinguish" in raw_tokens

    return TaskSpec(
        title=title,
        target_paths=target_paths,
        target_article_paths=target_article_paths,
        tokens=tokens,
        wants_distinction=wants_distinction,
    )


def discover_article_map(repo_root: Path) -> dict[str, str]:
    article_map: dict[str, str] = {}
    content_root = repo_root / "content" / "pages"
    if not content_root.is_dir():
        return article_map
    for article_path in sorted(content_root.glob("*/index.mdx")):
        relative_path = article_path.relative_to(repo_root).as_posix()
        slug = article_path.parent.name
        article_map[slug] = relative_path
        title = extract_frontmatter_scalar(
            article_path.read_text(encoding="utf-8", errors="replace"),
            "title",
        )
        if title:
            article_map[slugify_wiki_link(title)] = relative_path
    return article_map


def infer_article_paths(
    issue: str,
    tokens: frozenset[str],
    article_map: dict[str, str],
) -> tuple[str, ...]:
    matches: list[tuple[int, str]] = []
    normalized_issue = issue.lower()
    for key, path in article_map.items():
        score = 0
        if key and key in normalized_issue:
            score += 5
        key_tokens = set(TOKEN_PATTERN.findall(key))
        score += sum(1 for token in key_tokens if token in tokens)
        slug = Path(path).parent.name
        slug_parts = set(slug.split("_")) | set(slug.split("-"))
        score += sum(1 for token in slug_parts if token in tokens)
        if score > 0:
            matches.append((score, path))
    matches.sort(key=lambda item: (-item[0], item[1]))
    ordered = []
    for _, path in matches:
        if path not in ordered:
            ordered.append(path)
    return tuple(ordered[:2])


def first_nonempty_line(value: str) -> str:
    for line in value.splitlines():
        stripped = line.strip("#: \t")
        if stripped:
            return stripped[:180]
    return "Kata benchmark task"


def build_repo_context(repo_root: Path, task: TaskSpec) -> str:
    sections: list[str] = []
    budget = MAX_TOTAL_CONTEXT_BYTES

    sections.append(
        "## Parsed Task\n"
        f"Title: {task.title}\n"
        f"Target paths: {', '.join(task.target_paths) if task.target_paths else '(none parsed)'}\n"
        f"Target articles: {render_target_articles(task)}\n"
        f"Important tokens: {', '.join(sorted(task.tokens)) or '(none)'}\n"
        f"Wants distinction: {'yes' if task.wants_distinction else 'no'}"
    )

    sections.append(
        "## Validation Rules\n"
        "- Published articles need at least one non-image Markdown http(s) source link.\n"
        "- Published articles must not contain fenced code blocks.\n"
        "- Required front matter keys: title, summary, category, tags.\n"
        "- Internal wiki links must resolve to an existing article slug.\n"
        "- Keep images local to the article directory when using local paths.\n"
        '- Do not use "Bittensor" as the category or as a tag.\n'
        "- Keep edits as narrow as possible."
    )

    for relative_path, limit in (
        ("README.md", MAX_RELATED_BYTES),
        ("CONTRIBUTING.md", MAX_RELATED_BYTES),
        ("package.json", 6000),
        ("scripts/validate-content.mjs", 18000),
    ):
        chunk = file_section(repo_root, relative_path, limit)
        if chunk and fits_budget(chunk, budget):
            sections.append(chunk)
            budget -= byte_len(chunk)

    for relative_path in task.target_paths:
        chunk = file_section(repo_root, relative_path, MAX_TARGET_BYTES)
        if chunk and fits_budget(chunk, budget):
            sections.append(chunk)
            budget -= byte_len(chunk)

    for relative_path in related_article_paths(repo_root, task):
        if relative_path in task.target_paths:
            continue
        chunk = file_section(repo_root, relative_path, MAX_RELATED_BYTES)
        if chunk and fits_budget(chunk, budget):
            sections.append(chunk)
            budget -= byte_len(chunk)

    index_section = article_index(repo_root, task)
    if index_section and fits_budget(index_section, budget):
        sections.append(index_section)

    return "\n\n".join(sections)


def related_article_paths(repo_root: Path, task: TaskSpec) -> list[str]:
    content_root = repo_root / "content" / "pages"
    if not content_root.is_dir():
        return []

    scored: list[tuple[int, str]] = []
    for path in content_root.glob("*/index.mdx"):
        relative_path = path.relative_to(repo_root).as_posix()
        if relative_path in task.target_article_paths:
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        haystack = f"{relative_path}\n{extract_headings(content)}\n{content[:4000]}".lower()
        score = sum(1 for token in task.tokens if token in haystack)
        if task.wants_distinction and "## distinction from " in content.lower():
            score += 5
        if score > 0:
            scored.append((score, relative_path))

    scored.sort(key=lambda item: (-item[0], item[1]))
    return [relative_path for _, relative_path in scored[:MAX_RELATED_FILES]]


def article_index(repo_root: Path, task: TaskSpec) -> str:
    content_root = repo_root / "content" / "pages"
    if not content_root.is_dir():
        return ""
    slugs = sorted(path.parent.name for path in content_root.glob("*/index.mdx"))
    selected: list[str] = []
    for target in task.target_article_paths:
        slug = Path(target).parent.name
        if slug in slugs and slug not in selected:
            selected.append(slug)
    for slug in slugs:
        if len(selected) >= MAX_INDEX_ARTICLES:
            break
        if slug not in selected:
            selected.append(slug)
    if len(slugs) > len(selected):
        selected.append(f"... {len(slugs) - len(selected)} more")
    return "## Article Slug Index\n" + "\n".join(selected)


def extract_headings(content: str) -> str:
    return "\n".join(match.group(1) for match in HEADING_PATTERN.finditer(content))


def file_section(repo_root: Path, relative_path: str, max_bytes: int) -> str:
    path = repo_root / relative_path
    if not path.is_file():
        return ""
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    encoded = content.encode("utf-8")
    truncated = ""
    if len(encoded) > max_bytes:
        content = encoded[:max_bytes].decode("utf-8", errors="ignore")
        truncated = "\n...[truncated]"
    return f"### FILE: {relative_path}\n```\n{content.rstrip()}{truncated}\n```"


def render_target_articles(task: TaskSpec) -> str:
    if not task.target_article_paths:
        return "(none inferred)"
    return ", ".join(task.target_article_paths)


def fits_budget(value: str, remaining: int) -> bool:
    return byte_len(value) <= remaining


def byte_len(value: str) -> int:
    return len(value.encode("utf-8"))


def request_candidate(
    *,
    model: str,
    api_base: str,
    api_key: str,
    issue: str,
    repo_context: str,
    repair_notes: str,
) -> str:
    user_prompt = (
        "Task:\n"
        f"{issue.strip()}\n\n"
        f"{repo_context}\n\n"
        "Requirements:\n"
        "- Change only files that materially need edits.\n"
        "- Preserve valid front matter unless the task requires changing it.\n"
        "- Keep wording concise and sourced.\n"
        "- Return JSON only.\n"
    )
    if repair_notes:
        user_prompt += f"\nRepair notes:\n{repair_notes.strip()}\n"
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
        "max_tokens": 5000,
    }
    request = urllib.request.Request(
        build_chat_completions_url(api_base),
        data=json.dumps(payload).encode("utf-8"),
        headers=build_headers(api_key),
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            response_payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"chat completion request failed: {exc.code} {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"chat completion request failed: {exc.reason}") from exc
    return extract_message_content(response_payload)


def build_chat_completions_url(api_base: str) -> str:
    base = api_base.rstrip("/")
    if base.endswith("/chat/completions"):
        return base
    return base + "/chat/completions"


def build_headers(api_key: str) -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    return headers


def extract_message_content(payload: dict) -> str:
    choices = payload.get("choices") or []
    if not choices:
        return ""
    message = choices[0].get("message") or {}
    content = message.get("content", "")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                parts.append(str(item.get("text", "")))
        return "".join(parts)
    return str(content)


def parse_model_response(value: str) -> ModelResponse:
    text = value.strip()
    if not text:
        raise ValueError("empty model response")
    if text.startswith("```"):
        lines = text.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end >= start:
        text = text[start : end + 1]
    payload = json.loads(text)
    if not isinstance(payload, dict):
        raise ValueError("model response must be a JSON object")
    raw_files = payload.get("files")
    if not isinstance(raw_files, list) or not raw_files:
        raise ValueError("model response must contain a non-empty files array")
    files: dict[str, str] = {}
    for item in raw_files:
        if not isinstance(item, dict):
            raise ValueError("each files entry must be an object")
        path = item.get("path")
        content = item.get("content")
        if not isinstance(path, str) or not path.strip():
            raise ValueError("each files entry requires a non-empty path")
        if not isinstance(content, str):
            raise ValueError(f"files entry {path!r} must contain string content")
        normalized_path = normalize_relative_path(path)
        files[normalized_path] = ensure_trailing_newline(content)
    return ModelResponse(summary=str(payload.get("summary") or "").strip(), files=files)


def normalize_relative_path(value: str) -> str:
    path = Path(value.strip())
    if path.is_absolute():
        raise ValueError(f"absolute paths are not allowed: {value}")
    normalized = path.as_posix().strip("/")
    if not normalized or normalized.startswith("../") or "/../" in normalized or normalized == "..":
        raise ValueError(f"unsafe relative path: {value}")
    return normalized


def ensure_trailing_newline(value: str) -> str:
    return value.rstrip("\n") + "\n"


def build_candidate_diff(repo_root: Path, task: TaskSpec, candidate: ModelResponse) -> str:
    allowed_paths = set(task.target_paths or task.target_article_paths or candidate.files.keys())
    diff_chunks: list[str] = []
    for relative_path, new_content in sorted(candidate.files.items()):
        if allowed_paths and relative_path not in allowed_paths:
            raise ValueError(f"candidate changed unexpected file: {relative_path}")
        original_path = repo_root / relative_path
        if original_path.exists():
            old_content = original_path.read_text(encoding="utf-8", errors="replace")
        else:
            old_content = ""
        if old_content == new_content:
            continue
        diff_lines = unified_diff(
            old_content.splitlines(),
            new_content.splitlines(),
            fromfile=f"a/{relative_path}",
            tofile=f"b/{relative_path}",
            lineterm="",
        )
        diff_chunks.append("\n".join(diff_lines))
    diff_text = "\n".join(chunk for chunk in diff_chunks if chunk).strip()
    if not diff_text:
        raise ValueError("candidate did not produce any file changes")
    return diff_text + "\n"


def validate_candidate(
    repo_root: Path,
    task: TaskSpec,
    candidate: ModelResponse,
    diff_text: str,
) -> list[str]:
    errors: list[str] = []
    if not git_apply_check(repo_root, diff_text):
        errors.append("generated diff failed git apply --check")
        return errors

    with tempfile.TemporaryDirectory(prefix="kata-taopedia-") as tmpdir:
        temp_root = Path(tmpdir)
        apply_candidate_files(repo_root, temp_root, candidate.files)
        for relative_path in candidate.files:
            errors.extend(validate_changed_file(temp_root, relative_path))
    return dedupe(errors)


def git_apply_check(repo_root: Path, diff_text: str) -> bool:
    completed = subprocess.run(
        ["git", "apply", "--check", "-"],
        cwd=str(repo_root),
        input=diff_text,
        capture_output=True,
        text=True,
        check=False,
    )
    return completed.returncode == 0


def apply_candidate_files(repo_root: Path, temp_root: Path, files: dict[str, str]) -> None:
    shutil.copytree(repo_root, temp_root, dirs_exist_ok=True)
    for relative_path, content in files.items():
        path = temp_root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def validate_changed_file(repo_root: Path, relative_path: str) -> list[str]:
    path = repo_root / relative_path
    if not path.exists():
        return [f"changed file does not exist after applying candidate: {relative_path}"]
    if relative_path.endswith("/index.mdx") and relative_path.startswith("content/pages/"):
        return validate_article_file(repo_root, relative_path)
    return []


def validate_article_file(repo_root: Path, relative_path: str) -> list[str]:
    errors: list[str] = []
    path = repo_root / relative_path
    text = path.read_text(encoding="utf-8", errors="replace")

    if not text.startswith("---\n"):
        errors.append(f"{relative_path}: missing front matter block")
    for field in ("title", "summary", "category", "tags"):
        if not has_frontmatter_field(text, field):
            errors.append(f"{relative_path}: missing front matter field `{field}`")

    category = extract_frontmatter_scalar(text, "category")
    if category and category.strip().lower() == "bittensor":
        errors.append(f'{relative_path}: category must not be "Bittensor"')

    if "bittensor" in extract_tags(text):
        errors.append(f'{relative_path}: tags must not include "Bittensor"')

    body = strip_frontmatter(text)
    if FENCE_PATTERN.search(body):
        errors.append(f"{relative_path}: published articles must not contain fenced code blocks")

    if not is_draft_article(text) and not HTTP_LINK_PATTERN.search(body):
        errors.append(f"{relative_path}: published articles must include at least one source link")

    slugs = discover_existing_slugs(repo_root)
    for target in WIKI_LINK_PATTERN.findall(text):
        normalized = slugify_wiki_link(target.strip())
        if normalized not in slugs:
            errors.append(f"{relative_path}: wiki link does not resolve: [[{target.strip()}]]")

    return errors


def has_frontmatter_field(text: str, field: str) -> bool:
    frontmatter = extract_frontmatter(text)
    if not frontmatter:
        return False
    pattern = re.compile(rf"(?m)^{re.escape(field)}\s*:")
    return pattern.search(frontmatter) is not None


def extract_frontmatter(text: str) -> str:
    if not text.startswith("---\n"):
        return ""
    end = text.find("\n---\n", 4)
    if end < 0:
        return ""
    return text[4:end]


def strip_frontmatter(text: str) -> str:
    if not text.startswith("---\n"):
        return text
    end = text.find("\n---\n", 4)
    if end < 0:
        return text
    return text[end + 5 :]


def extract_frontmatter_scalar(text: str, field: str) -> str:
    frontmatter = extract_frontmatter(text)
    if not frontmatter:
        return ""
    match = re.search(rf"(?m)^{re.escape(field)}\s*:\s*(.+)$", frontmatter)
    if match:
        return match.group(1).strip().strip('"').strip("'")
    block_match = re.search(
        rf"(?ms)^{re.escape(field)}\s*:\s*\n((?:^[ \t].*\n?)*)",
        frontmatter,
    )
    if block_match:
        lines = [line.strip().strip('"').strip("'") for line in block_match.group(1).splitlines()]
        return " ".join(line for line in lines if line)
    return ""


def extract_tags(text: str) -> set[str]:
    frontmatter = extract_frontmatter(text)
    if not frontmatter:
        return set()
    inline = re.search(r"(?m)^tags\s*:\s*\[(.+)\]\s*$", frontmatter)
    values: list[str] = []
    if inline:
        values.extend(part.strip().strip('"').strip("'") for part in inline.group(1).split(","))
    else:
        block = re.search(r"(?ms)^tags\s*:\s*\n((?:^[ \t]*-.*\n?)*)", frontmatter)
        if block:
            for line in block.group(1).splitlines():
                stripped = line.strip()
                if stripped.startswith("-"):
                    values.append(stripped[1:].strip().strip('"').strip("'"))
    return {value.lower() for value in values if value}


def is_draft_article(text: str) -> bool:
    frontmatter = extract_frontmatter(text).lower()
    return re.search(r"(?m)^draft\s*:\s*true\s*$", frontmatter) is not None


def discover_existing_slugs(repo_root: Path) -> set[str]:
    content_root = repo_root / "content" / "pages"
    if not content_root.is_dir():
        return set()
    slugs = set()
    for path in content_root.glob("*/index.mdx"):
        slugs.add(path.parent.name)
        title = extract_frontmatter_scalar(
            path.read_text(encoding="utf-8", errors="replace"),
            "title",
        )
        if title:
            slugs.add(slugify_wiki_link(title))
    return slugs


def slugify_wiki_link(value: str) -> str:
    return re.sub(r"[^\w-]", "", value.lower().replace(" ", "_"))


def build_repair_notes(candidate: ModelResponse, errors: list[str]) -> str:
    payload = {
        "summary": candidate.summary,
        "files": [{"path": path, "content": content} for path, content in candidate.files.items()],
    }
    return (
        "The previous proposal failed local validation.\n"
        "Errors:\n- " + "\n- ".join(errors[:12]) + "\n\n"
        f"Previous proposal:\n{json.dumps(payload, ensure_ascii=True)[:MAX_ERROR_CHARS]}\n\n"
        "Return corrected JSON only."
    )


def truncate(value: str, limit: int) -> str:
    text = value.strip()
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def dedupe(values: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value in seen:
            continue
        result.append(value)
        seen.add(value)
    return result
