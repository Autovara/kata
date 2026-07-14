"""Sample SN60 miner agent for Kata (sealed-room competition).

CONTRACT (required by the bitsec harness that runs your agent):
  * define  agent_main(project_dir=None, inference_api=None) -> {"vulnerabilities": [...]}
  * the harness runs it against the project's smart-contract code and scores your findings
    against hidden ground truth. More correct, high-severity findings = higher score.

INFERENCE (how you call the AI inside the room):
  POST  {inference_api}/inference
    headers: {"x-inference-api-key": os.environ["INFERENCE_API_KEY"]}
    body:    {"messages": [...], "max_tokens": N}     # NOTE: no "model" -- the relay pins it
    resp:    OpenAI-style {"choices": [{"message": {"content": "..."}}]}
  The model is pinned and paid by YOUR sealed key -- you just send messages.

This is a STARTING POINT. It discovers source files, asks the model to find bugs, and
returns them. Improve the prompts / add heuristics / pick better files to win.
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from pathlib import Path

SOURCE_EXTS = (".sol", ".vy", ".cairo")
MAX_FILES = 12          # cap how many files you audit (inference costs YOUR key)
MAX_FILE_CHARS = 12_000
MAX_FINDINGS = 10
HTTP_TIMEOUT = 120


def _project_root(project_dir: str | None) -> Path | None:
    """Where the contract code lives. The harness mounts it at /app/project_code."""
    candidates = [project_dir, os.environ.get("PROJECT_DIR"),
                  "/app/project_code", "/app/project", "/code", "."]
    for c in candidates:
        if c and Path(c).is_dir():
            return Path(c)
    return None


def _source_files(root: Path) -> list[tuple[str, str]]:
    files: list[tuple[str, str]] = []
    for p in sorted(root.rglob("*")):
        if len(files) >= MAX_FILES:
            break
        if p.suffix.lower() not in SOURCE_EXTS or not p.is_file():
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if text.strip():
            files.append((str(p.relative_to(root)), text[:MAX_FILE_CHARS]))
    return files


def _ask_model(inference_api: str | None, rel: str, code: str) -> list[dict]:
    endpoint = (inference_api or os.environ.get("INFERENCE_API") or "").rstrip("/")
    if not endpoint:
        return []
    prompt = (
        "You are an expert smart-contract security auditor. Find REAL, exploitable, "
        "high-severity vulnerabilities in the file below. Return ONLY a JSON array; each "
        'item = {"title": str, "severity": "high|medium|low", "line": int, '
        '"description": str}. Return [] if there are none.\n\n'
        f"FILE: {rel}\n```\n{code}\n```"
    )
    body = json.dumps(
        {"messages": [{"role": "user", "content": prompt}], "max_tokens": 1500}
    ).encode("utf-8")
    req = urllib.request.Request(
        endpoint + "/inference",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "x-inference-api-key": os.environ.get("INFERENCE_API_KEY", ""),
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            payload = json.loads(resp.read().decode("utf-8", "replace"))
        content = payload["choices"][0]["message"]["content"]
    except (urllib.error.URLError, OSError, KeyError, IndexError, ValueError):
        return []
    return _parse_findings(content, rel)


def _parse_findings(content: str, rel: str) -> list[dict]:
    match = re.search(r"\[.*\]", content, re.DOTALL)
    if not match:
        return []
    try:
        items = json.loads(match.group(0))
    except ValueError:
        return []
    findings: list[dict] = []
    for it in items if isinstance(items, list) else []:
        if not isinstance(it, dict):
            continue
        try:
            line = int(it.get("line", 0))
        except (ValueError, TypeError):
            line = 0
        findings.append({
            "title": str(it.get("title", "vulnerability"))[:200],
            "severity": str(it.get("severity", "medium")).lower(),
            "file": rel,
            "line": line,
            "description": str(it.get("description", ""))[:1000],
        })
    return findings


def agent_main(project_dir: str | None = None, inference_api: str | None = None) -> dict:
    root = _project_root(project_dir)
    if root is None:
        return {"vulnerabilities": []}
    findings: list[dict] = []
    for rel, code in _source_files(root):
        findings.extend(_ask_model(inference_api, rel, code))
        if len(findings) >= MAX_FINDINGS:
            break
    return {"vulnerabilities": findings[:MAX_FINDINGS]}


if __name__ == "__main__":
    # Local run: prints the findings JSON (needs INFERENCE_API + INFERENCE_API_KEY set,
    # and code under ./ or /app/project_code).
    print(json.dumps(agent_main(), indent=2))
