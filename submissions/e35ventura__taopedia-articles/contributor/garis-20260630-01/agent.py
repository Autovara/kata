from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path

from helpers.context_builder import build_repo_context

LANE_MODE = "contributor"
AGENT_LABEL = "garis-taopedia-candidate"
REPO_INSTRUCTIONS = """# Taopedia contributor rules

- Keep edits factual, sourced, concise, and useful to builders, validators, miners, and TAO holders.
- Articles live under `content/pages/<slug>/index.mdx`.
- Use required front matter: `title`, `summary`, `category`, `tags`.
- Do not use `Bittensor` as a catch-all category or tag.
- Prefer exact article edits over unrelated cleanup.
- Return only a unified diff that can be applied with `git apply`.
"""


def solve(repo_path: str, issue: str, model: str, api_base: str, api_key: str) -> dict:
    issue_text = issue.strip()
    if not issue_text:
        return {
            "success": False,
            "message": "validator did not provide a task",
            "diff": "",
        }
    if not model:
        return {
            "success": False,
            "message": "validator did not provide a model",
            "diff": "",
        }
    if not api_base:
        return {
            "success": False,
            "message": "validator did not provide an api_base",
            "diff": "",
        }

    repo_root = Path(repo_path).resolve()
    repo_context = build_repo_context(repo_root=repo_root, issue=issue_text)
    reply = request_diff(
        model=model,
        api_base=api_base,
        api_key=api_key,
        issue=issue_text,
        repo_context=repo_context,
    )
    diff_text = normalize_diff(reply)
    if not diff_text:
        return {
            "success": False,
            "message": "model did not return a unified diff",
            "diff": "",
        }
    return {
        "success": True,
        "message": f"{AGENT_LABEL} produced a diff",
        "diff": diff_text,
    }


def request_diff(
    *,
    model: str,
    api_base: str,
    api_key: str,
    issue: str,
    repo_context: str,
) -> str:
    system_prompt = (
        "You are a repo-specific coding agent for Kata.\n"
        "Solve the task by producing only a final unified diff.\n"
        "Do not return prose, code fences, JSON, or explanations.\n\n"
        f"{REPO_INSTRUCTIONS}"
    )
    user_prompt = (
        f"Lane mode: {LANE_MODE}\n\n"
        "Task:\n"
        f"{issue}\n\n"
        "Repository context:\n"
        f"{repo_context}\n\n"
        "Output requirement:\n"
        "- Return only the final unified diff.\n"
        "- Touch only files needed for the task.\n"
        "- Preserve valid MDX and front matter when editing articles.\n"
    )
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "max_tokens": 2500,
    }
    request = urllib.request.Request(
        build_chat_completions_url(api_base),
        data=json.dumps(payload).encode("utf-8"),
        headers=build_headers(api_key),
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=180) as response:
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


def normalize_diff(value: str) -> str:
    text = value.strip()
    if not text:
        return ""
    if text.startswith("```"):
        lines = text.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    if text.startswith("diff --git") or text.startswith("--- "):
        return text + "\n"
    return ""
