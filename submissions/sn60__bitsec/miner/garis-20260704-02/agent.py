"""SN60 bitsec miner agent — LLM-driven smart-contract vulnerability auditor.

Self-contained, standard-library-only agent for the ``sn60__bitsec/miner``
lane. It reads the project source mounted into the sandbox, runs a
security-audit pass over the code through the validator-provided inference
proxy, and reports HIGH/CRITICAL findings in the SN60 report shape.

Contract (see docs/submissions.md):
- ``agent_main`` is synchronous and callable with no arguments.
- Inference goes to ``POST <inference_api>/inference`` with the
  ``x-inference-api-key`` header; the key comes from ``INFERENCE_API_KEY`` and
  the endpoint from the ``inference_api`` argument or the ``INFERENCE_API``
  environment variable.
- The request body is an OpenAI-chat-shaped payload. The model is NOT set here;
  the validator pins it.
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path

# The Bitsec mount path is defined by the sandbox image, not by this repo, so
# we probe the common locations in order instead of assuming a single one. The
# caller-provided project_dir and the PROJECT_DIR env var always take priority.
PROJECT_DIR_CANDIDATES = (
    "/app/project_code",
    "/app/project",
    "/app/code",
    "/app/src",
    "/app",
    "/repo",
    "/project",
    "/code",
    "/src",
    "/workspace",
)
DEFAULT_INFERENCE_API = "http://bitsec_proxy:8000"

# Suffixes worth auditing for on-chain vulnerabilities.
SOURCE_SUFFIXES = (".sol", ".vy", ".rs", ".cairo", ".move", ".fe")
# Directory names that never hold the audited contract logic.
SKIP_DIR_NAMES = {
    "node_modules", ".git", "lib", "out", "artifacts", "cache",
    "test", "tests", "mock", "mocks", "script", "scripts",
    "target", "build", "dist", "coverage", "typechain", "typechain-types",
    "forge-std", "openzeppelin", "openzeppelin-contracts",
}

MAX_FINDINGS = 100
MIN_DESCRIPTION_CHARS = 80
PER_FILE_CHAR_CAP = 24_000
BATCH_CHAR_BUDGET = 40_000
MAX_TOKENS = 4000
INFERENCE_RETRIES = 2
# The screening sandbox run is killed at ~300s (docs/submissions.md), and a run
# killed by that timeout is an invalid screening run. Stay well under it: cap the
# whole audit at 240s and never let a single request block past the shared
# deadline.
DEFAULT_BUDGET_SECONDS = 240.0
MAX_REQUEST_TIMEOUT_SECONDS = 120
MIN_REQUEST_TIMEOUT_SECONDS = 10

AUDIT_SYSTEM_PROMPT = (
    "You are an elite smart-contract security auditor. You are shown source "
    "files from a single project. Identify only HIGH or CRITICAL severity, "
    "concretely exploitable vulnerabilities that a professional audit would "
    "report as a real finding: missing/incorrect access control, reentrancy, "
    "unchecked external calls, arithmetic or rounding errors that lose funds, "
    "broken accounting or invariants, signature/replay issues, price or oracle "
    "manipulation, and unprotected initialization or upgrade paths. Ignore "
    "style, gas, and informational or low/medium issues. Never invent issues; "
    "every finding must be grounded in the code shown. Respond with a STRICT "
    "JSON object of the form: "
    '{"vulnerabilities": [{"title": string, "severity": "high" | "critical", '
    '"file": string, "function": string, "vulnerability_type": string, '
    '"description": string, "confidence": number}]}. Set "file" to the exact '
    "path shown in the FILE header. The description must state the root cause, "
    "the exploit path, and the impact in at least two sentences. If nothing is "
    'exploitable, return {"vulnerabilities": []}.'
)


def _budget_seconds() -> float:
    raw = os.environ.get("KATA_AGENT_BUDGET_SECONDS", "")
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return DEFAULT_BUDGET_SECONDS
    return value if value > 0 else DEFAULT_BUDGET_SECONDS


def resolve_project_root(project_dir: str | None) -> Path | None:
    """Locate the mounted project source.

    Tries the explicit hint first (argument, then PROJECT_DIR), then the known
    sandbox mount candidates, then the current working directory. Returns the
    first directory that actually contains auditable source files, or None.
    """
    hints: list[str] = []
    if project_dir:
        hints.append(project_dir)
    env_dir = os.environ.get("PROJECT_DIR")
    if env_dir:
        hints.append(env_dir)
    hints.extend(PROJECT_DIR_CANDIDATES)
    hints.append(os.getcwd())

    checked: set[str] = set()
    for hint in hints:
        if not hint or hint in checked:
            continue
        checked.add(hint)
        root = Path(hint)
        if root.is_dir() and _has_source_file(root):
            return root
    return None


def _is_auditable(path: Path) -> bool:
    if path.is_symlink() or not path.is_file():
        return False
    if path.suffix.lower() not in SOURCE_SUFFIXES:
        return False
    return not ({part.lower() for part in path.parts} & SKIP_DIR_NAMES)


def _has_source_file(root: Path) -> bool:
    """True if root holds at least one auditable source file (early-exit)."""
    try:
        for path in root.rglob("*"):
            if _is_auditable(path):
                return True
    except OSError:
        return False
    return False


def discover_source_files(root: Path) -> list[Path]:
    """Return auditable source files, most-likely-vulnerable first."""
    files = [path for path in root.rglob("*") if _is_auditable(path)]

    def priority(path: Path) -> tuple[int, int, int]:
        lowered = str(path).lower()
        in_core = 0 if any(
            marker in lowered for marker in ("/src/", "/contracts/", "/programs/")
        ) else 1
        is_interface = int(
            path.suffix.lower() == ".sol" and bool(re.match(r"I[A-Z]", path.name))
        )
        try:
            size = path.stat().st_size
        except OSError:
            size = 0
        return (in_core, is_interface, -size)

    files.sort(key=priority)
    return files


def read_source(path: Path) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    if len(text) > PER_FILE_CHAR_CAP:
        text = text[:PER_FILE_CHAR_CAP] + "\n// ...[truncated for length]...\n"
    return text


def build_batches(files: list[Path], root: Path) -> list[list[tuple[str, str]]]:
    """Group files into char-bounded batches, preserving priority order."""
    batches: list[list[tuple[str, str]]] = []
    current: list[tuple[str, str]] = []
    current_chars = 0
    for path in files:
        text = read_source(path)
        if not text.strip():
            continue
        rel = path.relative_to(root).as_posix()
        block_chars = len(text) + len(rel)
        if current and current_chars + block_chars > BATCH_CHAR_BUDGET:
            batches.append(current)
            current, current_chars = [], 0
        current.append((rel, text))
        current_chars += block_chars
    if current:
        batches.append(current)
    return batches


def render_batch(batch: list[tuple[str, str]]) -> str:
    sections = [f"// FILE: {rel}\n{text}" for rel, text in batch]
    return (
        "Audit these smart-contract source files and report only HIGH or "
        "CRITICAL exploitable vulnerabilities. Use the exact path from each "
        "FILE header as the finding's `file` value.\n\n" + "\n\n".join(sections)
    )


def call_inference(inference_api: str, api_key: str, user_content: str, deadline: float) -> str:
    endpoint = inference_api.rstrip("/") + "/inference"
    body = json.dumps(
        {
            "messages": [
                {"role": "system", "content": AUDIT_SYSTEM_PROMPT},
                {"role": "user", "content": user_content},
            ],
            "max_tokens": MAX_TOKENS,
            "response_format": {"type": "json_object"},
        }
    ).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "x-inference-api-key": api_key,
        "x-request-phase": "execution",
    }
    last_error: Exception | None = None
    for attempt in range(1, INFERENCE_RETRIES + 1):
        # Never start (or block on) a request that could run past the shared
        # deadline; the screening timeout kills the whole run, not just the call.
        remaining = deadline - time.monotonic()
        if remaining < MIN_REQUEST_TIMEOUT_SECONDS:
            break
        timeout = min(MAX_REQUEST_TIMEOUT_SECONDS, remaining)
        request = urllib.request.Request(endpoint, data=body, method="POST", headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
            return str(payload["choices"][0]["message"]["content"])
        except (urllib.error.URLError, TimeoutError, ConnectionError, ValueError, KeyError) as exc:
            last_error = exc
            if attempt < INFERENCE_RETRIES:
                # Back off, but not past the deadline.
                slack = deadline - time.monotonic() - MIN_REQUEST_TIMEOUT_SECONDS
                backoff = min(2.0 * attempt, slack)
                if backoff <= 0:
                    break
                time.sleep(backoff)
    raise RuntimeError(f"Inference failed after {INFERENCE_RETRIES} attempts: {last_error}")


def extract_json_object(content: str) -> dict:
    text = content.strip()
    if text.startswith("```"):
        text = re.sub(r"^```[A-Za-z0-9]*\n?", "", text)
        text = re.sub(r"\n?```$", "", text).strip()
    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, dict) else {}
    except ValueError:
        pass
    start, end = text.find("{"), text.rfind("}")
    if 0 <= start < end:
        try:
            parsed = json.loads(text[start : end + 1])
            return parsed if isinstance(parsed, dict) else {}
        except ValueError:
            return {}
    return {}


def _guess_file(text: str, source_files: list[Path]) -> str:
    for path in source_files:
        if path.name in text:
            return path.name
    match = re.search(r"[\w./-]+\.(?:sol|vy|rs|cairo|move|fe)", text)
    return match.group(0) if match else ""


def _ensure_description(
    title: str, vuln_type: str, file_hint: str, function: str, description: str
) -> str:
    if len(description) >= MIN_DESCRIPTION_CHARS:
        return description
    where = f" in {function}()" if function else ""
    base = description or title
    return (
        f"{base}. This {vuln_type or 'security'} issue is located in "
        f"{file_hint}{where} and can be exploited to compromise the contract's "
        "funds or state invariants; it should be treated as a high-severity "
        "finding and remediated before deployment."
    )


def normalize_findings(raw: dict, source_files: list[Path]) -> list[dict]:
    items = raw.get("vulnerabilities") if isinstance(raw, dict) else None
    if not isinstance(items, list):
        return []
    findings: list[dict] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        title = str(item.get("title", "")).strip()
        if not title:
            continue
        severity = str(item.get("severity", "")).strip().lower()
        if severity not in {"high", "critical"}:
            continue
        file_hint = str(item.get("file") or item.get("path") or item.get("location") or "").strip()
        description = str(item.get("description", "")).strip()
        function = str(item.get("function", "")).strip()
        vuln_type = str(item.get("vulnerability_type") or item.get("type") or "").strip()
        if not file_hint:
            file_hint = _guess_file(f"{title} {description}", source_files)
        if not file_hint:
            continue
        finding = {
            "title": title[:200],
            "severity": severity,
            "file": file_hint,
            "vulnerability_type": vuln_type or "security",
            "description": _ensure_description(title, vuln_type, file_hint, function, description),
        }
        if function:
            finding["function"] = function
        confidence = item.get("confidence")
        if isinstance(confidence, (int, float)) and not isinstance(confidence, bool):
            finding["confidence"] = float(confidence)
        findings.append(finding)
    return findings


def dedupe_findings(findings: list[dict]) -> list[dict]:
    seen: set[tuple[str, str, str]] = set()
    unique: list[dict] = []
    for finding in findings:
        key = (
            finding["title"].lower(),
            finding["file"].lower(),
            finding.get("function", "").lower(),
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def agent_main(project_dir: str | None = None, inference_api: str | None = None) -> dict:
    inference_api = inference_api or os.environ.get("INFERENCE_API") or DEFAULT_INFERENCE_API
    api_key = os.environ.get("INFERENCE_API_KEY", "")
    if not api_key:
        raise RuntimeError("INFERENCE_API_KEY is not set; the validator must provide it.")

    root = resolve_project_root(project_dir)
    if root is None:
        raise RuntimeError(
            "No smart-contract source files found. Checked the project_dir "
            "argument, PROJECT_DIR, the current directory, and known sandbox "
            "mount points: " + ", ".join(PROJECT_DIR_CANDIDATES)
        )

    source_files = discover_source_files(root)
    if not source_files:
        raise RuntimeError(f"No smart-contract source files found under {root}.")

    batches = build_batches(source_files, root)
    deadline = time.monotonic() + _budget_seconds()

    findings: list[dict] = []
    failures = 0
    for index, batch in enumerate(batches):
        if time.monotonic() >= deadline:
            break
        try:
            content = call_inference(inference_api, api_key, render_batch(batch), deadline)
        except RuntimeError:
            failures += 1
            # Never mask a total inference outage as a clean empty report.
            if not findings and index == len(batches) - 1:
                raise
            continue
        findings.extend(normalize_findings(extract_json_object(content), source_files))
        if len(findings) >= MAX_FINDINGS:
            break

    if not findings and failures and failures == len(batches):
        raise RuntimeError("All inference requests failed; no report produced.")

    findings = dedupe_findings(findings)[:MAX_FINDINGS]
    return {
        "project": root.name,
        "files_analyzed": len(source_files),
        "total_vulnerabilities": len(findings),
        "vulnerabilities": findings,
    }
