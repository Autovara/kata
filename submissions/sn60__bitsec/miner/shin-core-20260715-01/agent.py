"""SN60 (Bitsec) vulnerability-finding agent.

General, project-agnostic Solidity auditor. It discovers the project's Solidity
sources, prioritizes core contracts over tests/mocks/interfaces, sends prioritized
code windows to the evaluator-supplied inference relay with a category-driven audit
prompt, and returns a de-duplicated list of high/critical findings.

Design goals:
- Recall-oriented: report every plausible high/critical issue the model surfaces.
- Robust: never raise. A missing project dir, empty tree, or dead inference
  endpoint yields an empty report, never a crash.
- General: analyzes whatever code it receives; it does not recognize benchmark
  projects or replay prewritten answers.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from pathlib import Path

# --- discovery / budget limits -------------------------------------------------

MAX_FILES = 14           # prioritized source files to audit per run
MAX_FILE_CHARS = 14_000  # characters per code window sent to the model
CHUNK_OVERLAP = 800      # overlap between windows of a large file
MAX_CHUNKS_PER_FILE = 2  # cap windows for any single large file
MAX_FINDINGS = 40        # recall-oriented cap on returned findings
REQUEST_TIMEOUT = 120
MAX_TOKENS = 2400

# Directory / filename fragments that are rarely the audit target. Files whose
# relative path contains one of these are deprioritized (still eligible if the
# project has nothing else).
DEPRIORITIZE_HINTS = (
    "/test/",
    "/tests/",
    "/mock/",
    "/mocks/",
    "/interface/",
    "/interfaces/",
    "/lib/",
    "/libs/",
    "node_modules",
    "/script/",
    "/scripts/",
    ".t.sol",
    ".s.sol",
    "mock",
    "test",
)

# Fragments that hint a file is a core, high-value audit target.
PRIORITIZE_HINTS = (
    "vault",
    "token",
    "pool",
    "staking",
    "stake",
    "lend",
    "borrow",
    "oracle",
    "bridge",
    "governance",
    "treasury",
    "controller",
    "manager",
    "router",
    "strategy",
    "reward",
    "auction",
    "market",
    "core",
)

SEVERITIES = {"critical", "high", "medium", "low", "informational"}


def _project_root(project_dir: str | None) -> Path | None:
    for candidate in (
        project_dir,
        os.environ.get("PROJECT_DIR"),
        "/app/project_code",
        ".",
    ):
        try:
            if candidate and Path(candidate).is_dir():
                return Path(candidate)
        except OSError:
            continue
    return None


def _score_path(rel_path: str) -> int:
    """Higher score = more likely a valuable audit target."""
    lowered = rel_path.lower()
    score = 0
    for hint in DEPRIORITIZE_HINTS:
        if hint in lowered:
            score -= 5
    for hint in PRIORITIZE_HINTS:
        if hint in lowered:
            score += 3
    # Shallow files (closer to src/contracts root) tend to be primary contracts.
    depth = lowered.count("/")
    score -= depth
    return score


def _discover_sources(root: Path) -> list[tuple[str, str]]:
    """Return (relative_path, source) for prioritized Solidity files."""
    entries: list[tuple[int, str, str]] = []
    try:
        paths = sorted(root.rglob("*.sol"))
    except OSError:
        return []
    for path in paths:
        try:
            if not path.is_file():
                continue
            source = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if not source.strip():
            continue
        try:
            rel = str(path.relative_to(root))
        except ValueError:
            rel = str(path)
        entries.append((_score_path(rel), rel, source))
    # Highest priority first; stable on ties by path for determinism.
    entries.sort(key=lambda item: (-item[0], item[1]))
    return [(rel, source) for _, rel, source in entries[:MAX_FILES]]


def _windows(source: str) -> list[str]:
    """Split a source file into at most MAX_CHUNKS_PER_FILE overlapping windows."""
    if len(source) <= MAX_FILE_CHARS:
        return [source]
    windows: list[str] = []
    start = 0
    step = MAX_FILE_CHARS - CHUNK_OVERLAP
    while start < len(source) and len(windows) < MAX_CHUNKS_PER_FILE:
        windows.append(source[start : start + MAX_FILE_CHARS])
        start += step
    return windows


def _prompt(source_file: str, code: str) -> str:
    return (
        "You are a senior smart-contract security auditor. Analyze the following "
        "Solidity source for HIGH and CRITICAL severity vulnerabilities that a "
        "professional audit (Code4rena / Sherlock / Cantina style) would flag.\n\n"
        "Consider, among others: reentrancy (single/cross-function/cross-contract), "
        "broken or missing access control, unchecked external calls / return values, "
        "arithmetic issues (overflow/underflow, rounding, precision loss, division "
        "order), oracle / price manipulation, first-depositor / share inflation, "
        "flash-loan abuse, incorrect accounting or fund custody, unsafe delegatecall, "
        "signature replay / missing nonce, front-running / MEV, uninitialized or "
        "unprotected initializers/proxies, incorrect slippage / deadline handling, "
        "and logic errors that let funds be drained or locked.\n\n"
        "Report ONLY genuine high/critical issues you can justify from the code. Do "
        "not invent findings and do not report style or gas issues.\n\n"
        "Return ONLY a JSON array (no prose). Each element must be an object with: "
        '"title" (short), "severity" (one of critical/high/medium), "line" (integer, '
        'best guess, 0 if unknown), and "description" (root cause + impact).\n\n'
        f"FILE: {source_file}\n```solidity\n{code}\n```"
    )


def _call_model(endpoint: str, prompt: str) -> str | None:
    body = json.dumps(
        {"messages": [{"role": "user", "content": prompt}], "max_tokens": MAX_TOKENS}
    ).encode()
    request = urllib.request.Request(
        endpoint + "/inference",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "x-inference-api-key": os.environ.get("INFERENCE_API_KEY", ""),
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
            payload = json.loads(response.read().decode("utf-8", "replace"))
        return payload["choices"][0]["message"]["content"]
    except (urllib.error.URLError, OSError, KeyError, IndexError, TypeError, ValueError):
        return None


def _extract_json_array(content: str) -> list:
    """Best-effort parse of a JSON array from a model response."""
    if not content:
        return []
    # Strip a common ```json ... ``` fence if present.
    fenced = re.search(r"```(?:json)?\s*(\[.*?\])\s*```", content, re.DOTALL)
    candidate = fenced.group(1) if fenced else None
    if candidate is None:
        match = re.search(r"\[.*\]", content, re.DOTALL)
        candidate = match.group(0) if match else None
    if candidate is None:
        return []
    try:
        parsed = json.loads(candidate)
    except ValueError:
        return []
    return parsed if isinstance(parsed, list) else []


def _normalize_finding(item: object, source_file: str) -> dict | None:
    if not isinstance(item, dict):
        return None
    title = str(item.get("title") or item.get("name") or "").strip()
    description = str(item.get("description") or item.get("detail") or "").strip()
    if not title and not description:
        return None
    severity = str(item.get("severity", "high")).strip().lower()
    if severity not in SEVERITIES:
        severity = "high"
    try:
        line = int(item.get("line", 0) or 0)
    except (TypeError, ValueError):
        line = 0
    if line < 0:
        line = 0
    return {
        "title": (title or "security issue")[:200],
        "severity": severity,
        "file": source_file,
        "line": line,
        "description": description[:1200],
    }


def _dedupe_key(finding: dict) -> tuple:
    title = re.sub(r"\s+", " ", finding["title"].lower()).strip()
    return (finding["file"], title)


def agent_main(project_dir: str | None = None, inference_api: str | None = None) -> dict:
    findings: list[dict] = []
    seen: set[tuple] = set()

    root = _project_root(project_dir)
    endpoint = (inference_api or os.environ.get("INFERENCE_API") or "").rstrip("/")
    if root is None or not endpoint:
        return {"vulnerabilities": findings}

    try:
        sources = _discover_sources(root)
    except Exception:
        sources = []

    for source_file, source in sources:
        if len(findings) >= MAX_FINDINGS:
            break
        for window in _windows(source):
            content = _call_model(endpoint, _prompt(source_file, window))
            if content is None:
                continue
            for raw in _extract_json_array(content):
                finding = _normalize_finding(raw, source_file)
                if finding is None:
                    continue
                key = _dedupe_key(finding)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(finding)
                if len(findings) >= MAX_FINDINGS:
                    break
            if len(findings) >= MAX_FINDINGS:
                break

    return {"vulnerabilities": findings[:MAX_FINDINGS]}
