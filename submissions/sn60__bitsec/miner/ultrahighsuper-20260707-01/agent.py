from __future__ import annotations

"""SN60 bitsec miner agent — budget-aware smart-contract auditor.

Strategy, given the fixed per-problem budget (3 model calls / 24k tokens):

1. Read the target sources from the project directory, keeping only the
   project's own contracts (test / mock / example / dependency folders are
   dropped so the token budget is spent on code that can actually be scored).
2. Pack the sources into at most three token-bounded batches and run one
   inference call per batch through the pinned endpoint, asking for strict
   JSON findings.
3. Normalise every finding into the bitsec Vulnerability schema, keep only
   high/critical exploitable issues, dedupe, and cap the list so precision
   (the tie-breaker) stays high.

The agent never raises: any failure degrades to an empty report so the run
stays valid instead of crashing the replica.
"""

import json
import os
import re
import urllib.error
import urllib.request
from pathlib import Path

DEFAULT_PROJECT_DIR = "/app/project_code"
INFERENCE_ROUTE = "/inference"

MAX_MODEL_CALLS = 3
MAX_TOTAL_TOKENS = 24_000
OUTPUT_TOKEN_RESERVE = 1_500  # per call, left for the model's JSON answer
PER_CALL_INPUT_TOKEN_CAP = 6_400
CHARS_PER_TOKEN = 4  # coarse estimate for stdlib-only token budgeting
REQUEST_TIMEOUT_SECONDS = 240

SOURCE_GLOBS = ("**/*.sol", "**/*.vy", "**/*.cairo", "**/*.rs", "**/*.move")
# Path fragments that mark non-scored code: unit tests, mocks, samples, and
# vendored dependencies. Kept lowercase for case-insensitive matching.
SKIP_DIR_FRAGMENTS = (
    "test",
    "tests",
    "mock",
    "mocks",
    "example",
    "examples",
    "node_modules",
    ".git",
    "out",
    "cache",
    "artifacts",
    "forge-std",
    "node-modules",
)
DEPENDENCY_FRAGMENTS = ("lib/", "libs/", "dependencies/", "vendor/", "third_party/")

MAX_FILES = 24
MAX_FINDINGS = 8
MIN_CONFIDENCE = 0.5

SEVERITY_VALUES = {
    "critical": "99_critical",
    "high": "85_high",
    "medium": "50_medium",
    "low": "25_low",
    "informational": "10_informational",
    "info": "10_informational",
}
SCORED_SEVERITIES = {"99_critical", "85_high"}

CATEGORY_VALUES = (
    "weak access control",
    "governance attacks",
    "reentrancy",
    "frontrunning",
    "arithmetic overflow and underflow vulnerability",
    "self destruct",
    "uninitialized proxy",
    "incorrect calculation",
    "rounding error",
    "improper input validation",
    "bad randomness vulnerability",
    "replay attacks/signature malleability",
    "oracle/price manipulation",
)
DEFAULT_CATEGORY = "improper input validation"
# Keyword hints mapping loose model wording onto a canonical category value.
CATEGORY_HINTS = (
    ("reentr", "reentrancy"),
    ("access control", "weak access control"),
    ("authoriz", "weak access control"),
    ("only owner", "weak access control"),
    ("permission", "weak access control"),
    ("governance", "governance attacks"),
    ("front", "frontrunning"),
    ("overflow", "arithmetic overflow and underflow vulnerability"),
    ("underflow", "arithmetic overflow and underflow vulnerability"),
    ("selfdestruct", "self destruct"),
    ("self-destruct", "self destruct"),
    ("self destruct", "self destruct"),
    ("uninitialized", "uninitialized proxy"),
    ("proxy", "uninitialized proxy"),
    ("round", "rounding error"),
    ("calcul", "incorrect calculation"),
    ("random", "bad randomness vulnerability"),
    ("replay", "replay attacks/signature malleability"),
    ("signature", "replay attacks/signature malleability"),
    ("malleab", "replay attacks/signature malleability"),
    ("oracle", "oracle/price manipulation"),
    ("price manip", "oracle/price manipulation"),
    ("validation", "improper input validation"),
    ("input", "improper input validation"),
)

SYSTEM_PROMPT = (
    "You are an elite smart-contract security auditor. You review the provided "
    "source and report only CRITICAL or HIGH severity, genuinely exploitable "
    "vulnerabilities that a professional audit would confirm as real. Do not "
    "report style issues, gas optimisations, informational notes, or "
    "speculative concerns — false findings are penalised. Every finding must "
    "point to specific code. Respond with a single JSON object only."
)

RESPONSE_SCHEMA_HINT = (
    'Return JSON of the form: {"vulnerabilities": [{'
    '"title": str, "category": str, "severity": "critical"|"high", '
    '"file": str, "line_start": int, "line_end": int, '
    '"description": str, "vulnerable_code": str, "exploit": str, '
    '"fix": str, "confidence": number between 0 and 1}]}. '
    "Use an empty list if the code has no critical or high severity "
    "exploitable vulnerability."
)


def agent_main(
    project_dir: str | None = None,
    inference_api: str | None = None,
) -> dict:
    """Entry point invoked by the sandbox runner (also callable with no args)."""
    try:
        return {"vulnerabilities": _run(project_dir, inference_api)}
    except Exception:
        # A crash would invalidate the replica; degrade to an empty report.
        return {"vulnerabilities": []}


def _run(project_dir: str | None, inference_api: str | None) -> list[dict]:
    endpoint = _resolve_endpoint(inference_api)
    if not endpoint:
        return []
    sources = _collect_sources(project_dir)
    if not sources:
        return []

    batches = _batch_sources(sources)
    api_key = os.environ.get("INFERENCE_API_KEY", "")
    headers = _build_headers(api_key)

    raw_findings: list[dict] = []
    tokens_used = 0
    for index, batch in enumerate(batches):
        if index >= MAX_MODEL_CALLS:
            break
        if tokens_used + OUTPUT_TOKEN_RESERVE >= MAX_TOTAL_TOKENS:
            break
        content, spent = _call_model(endpoint, headers, batch)
        tokens_used += spent
        if content:
            raw_findings.extend(_parse_findings(content))

    return _finalise(raw_findings)


# --- configuration -----------------------------------------------------------


def _resolve_endpoint(inference_api: str | None) -> str:
    base = (inference_api or os.environ.get("INFERENCE_API") or "").strip()
    if not base:
        return ""
    base = base.rstrip("/")
    if base.endswith(INFERENCE_ROUTE):
        return base
    return base + INFERENCE_ROUTE


def _build_headers(api_key: str) -> dict:
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["x-inference-api-key"] = api_key
    agent_id = os.environ.get("AGENT_ID")
    if agent_id:
        headers["x-agent-id"] = agent_id
    job_run_id = os.environ.get("JOB_RUN_ID")
    if job_run_id:
        headers["x-job-run-id"] = job_run_id
    headers["x-request-phase"] = "execution"
    return headers


def _model_name() -> str:
    # The endpoint pins the served model regardless of this value; send a sane
    # default so the request body is well formed.
    return os.environ.get("INFERENCE_MODEL", "qwen/qwen3.6-35b-a3b")


# --- source collection -------------------------------------------------------


def _candidate_roots(project_dir: str | None) -> list[Path]:
    roots: list[Path] = []
    for value in (project_dir, os.environ.get("PROJECT_DIR"), DEFAULT_PROJECT_DIR, os.getcwd()):
        if not value:
            continue
        path = Path(value)
        if path.is_dir() and path not in roots:
            roots.append(path)
    return roots


def _collect_sources(project_dir: str | None) -> list[tuple[str, str]]:
    for root in _candidate_roots(project_dir):
        files = _discover_files(root)
        if files:
            return files
    return []


def _discover_files(root: Path) -> list[tuple[str, str]]:
    found: dict[str, tuple[str, str]] = {}
    for pattern in SOURCE_GLOBS:
        for path in root.glob(pattern):
            if not path.is_file():
                continue
            rel = _relative(path, root)
            lowered = rel.lower()
            if _is_skipped(lowered):
                continue
            if rel in found:
                continue
            text = _read_text(path)
            if text:
                found[rel] = (rel, text)
    ordered = sorted(
        found.values(),
        key=lambda item: (_is_dependency(item[0].lower()), -len(item[1]), item[0]),
    )
    return ordered[:MAX_FILES]


def _relative(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.name


def _is_skipped(lowered: str) -> bool:
    parts = lowered.split("/")
    return any(fragment in parts for fragment in SKIP_DIR_FRAGMENTS)


def _is_dependency(lowered: str) -> bool:
    return any(fragment in lowered for fragment in DEPENDENCY_FRAGMENTS)


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


# --- batching ----------------------------------------------------------------


def _batch_sources(sources: list[tuple[str, str]]) -> list[list[tuple[str, str]]]:
    """Pack numbered sources into at most MAX_MODEL_CALLS token-bounded batches."""
    input_budget = MAX_TOTAL_TOKENS - MAX_MODEL_CALLS * OUTPUT_TOKEN_RESERVE
    per_call_cap = min(PER_CALL_INPUT_TOKEN_CAP, max(1, input_budget // MAX_MODEL_CALLS))

    batches: list[list[tuple[str, str]]] = []
    current: list[tuple[str, str]] = []
    current_tokens = 0
    remaining_budget = input_budget

    for rel, text in sources:
        block = _render_source(rel, text)
        block = _truncate_to_tokens(block, per_call_cap)
        block_tokens = _estimate_tokens(block)
        if remaining_budget - block_tokens < 0:
            break
        if current and current_tokens + block_tokens > per_call_cap:
            batches.append(current)
            current = []
            current_tokens = 0
            if len(batches) >= MAX_MODEL_CALLS:
                break
        current.append((rel, block))
        current_tokens += block_tokens
        remaining_budget -= block_tokens

    if current and len(batches) < MAX_MODEL_CALLS:
        batches.append(current)
    return batches


def _render_source(rel: str, text: str) -> str:
    numbered = "\n".join(
        f"{number:>4} {line}" for number, line in enumerate(text.splitlines(), start=1)
    )
    return f"// FILE: {rel}\n{numbered}\n"


def _estimate_tokens(text: str) -> int:
    return max(1, len(text) // CHARS_PER_TOKEN)


def _truncate_to_tokens(text: str, token_cap: int) -> str:
    char_cap = token_cap * CHARS_PER_TOKEN
    if len(text) <= char_cap:
        return text
    head = text[: int(char_cap * 0.7)]
    tail = text[-int(char_cap * 0.25) :]
    return head + "\n// ... truncated ...\n" + tail


# --- inference ---------------------------------------------------------------


def _call_model(
    endpoint: str, headers: dict, batch: list[tuple[str, str]]
) -> tuple[str, int]:
    corpus = "\n\n".join(block for _rel, block in batch)
    user_prompt = (
        "Audit the following smart-contract source for critical and high "
        "severity exploitable vulnerabilities. Line numbers are prefixed on "
        "each line; cite them in line_start / line_end.\n\n"
        f"{RESPONSE_SCHEMA_HINT}\n\n=== SOURCE ===\n{corpus}"
    )
    body = json.dumps(
        {
            "model": _model_name(),
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            "response_format": {"type": "json_object"},
        }
    ).encode("utf-8")

    request = urllib.request.Request(endpoint, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            payload = response.read()
    except (urllib.error.URLError, OSError, ValueError):
        return "", 0

    return _read_completion(payload)


def _read_completion(payload: bytes) -> tuple[str, int]:
    try:
        data = json.loads(payload)
    except (ValueError, TypeError):
        return "", 0
    if not isinstance(data, dict):
        return "", 0

    tokens = _read_usage(data)
    content = ""
    choices = data.get("choices")
    if isinstance(choices, list) and choices:
        message = choices[0].get("message") if isinstance(choices[0], dict) else None
        if isinstance(message, dict):
            content = message.get("content") or ""
    if not content:
        # Some proxies flatten the answer onto the top level.
        content = data.get("content") or data.get("output") or ""
    if not tokens and content:
        tokens = _estimate_tokens(content)
    return (content if isinstance(content, str) else ""), tokens


def _read_usage(data: dict) -> int:
    usage = data.get("usage")
    if isinstance(usage, dict):
        total = usage.get("total_tokens")
        if isinstance(total, int) and total > 0:
            return total
        prompt = usage.get("prompt_tokens") or 0
        completion = usage.get("completion_tokens") or 0
        if isinstance(prompt, int) and isinstance(completion, int) and (prompt or completion):
            return prompt + completion
    flat = (data.get("input_tokens") or 0) + (data.get("output_tokens") or 0)
    return flat if isinstance(flat, int) else 0


# --- finding normalisation ---------------------------------------------------


def _parse_findings(content: str) -> list[dict]:
    payload = _extract_json_object(content)
    if payload is None:
        return []
    items = payload.get("vulnerabilities")
    if not isinstance(items, list):
        return []
    return [item for item in items if isinstance(item, dict)]


def _extract_json_object(content: str) -> dict | None:
    content = content.strip()
    try:
        parsed = json.loads(content)
        if isinstance(parsed, dict):
            return parsed
    except (ValueError, TypeError):
        pass
    # Fall back to the first balanced {...} block in free-form text.
    match = re.search(r"\{.*\}", content, re.DOTALL)
    if not match:
        return None
    try:
        parsed = json.loads(match.group(0))
    except (ValueError, TypeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _finalise(raw_findings: list[dict]) -> list[dict]:
    normalised: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for item in raw_findings:
        vuln = _normalise_finding(item)
        if vuln is None:
            continue
        key = (vuln["_file"].lower(), vuln["_title_key"])
        if key in seen:
            continue
        seen.add(key)
        normalised.append(vuln)

    normalised.sort(key=lambda v: (v["_severity_rank"], v["_confidence"]), reverse=True)
    return [_strip_internal(v) for v in normalised[:MAX_FINDINGS]]


def _normalise_finding(item: dict) -> dict | None:
    title = _clean_str(item.get("title"))
    description = _clean_str(item.get("description"))
    if not title or not description:
        return None

    severity = _map_severity(item.get("severity"))
    if severity not in SCORED_SEVERITIES:
        return None

    confidence = _coerce_confidence(item.get("confidence"))
    if confidence < MIN_CONFIDENCE:
        return None

    file_hint = _clean_str(item.get("file")) or _clean_str(item.get("location"))
    vuln = {
        "title": title,
        "severity": severity,
        "category": _map_category(item),
        "description": description,
        "vulnerable_code": _clean_str(item.get("vulnerable_code"))
        or _clean_str(item.get("code"))
        or "See referenced lines.",
        "code_to_exploit": _clean_str(item.get("exploit"))
        or _clean_str(item.get("code_to_exploit"))
        or "Exploitable via the described path.",
        "rewritten_code_to_fix_vulnerability": _clean_str(item.get("fix"))
        or _clean_str(item.get("rewritten_code_to_fix_vulnerability"))
        or "Apply the described mitigation.",
        "_file": file_hint,
        "_title_key": title.lower(),
        "_severity_rank": 1 if severity == "99_critical" else 0,
        "_confidence": confidence,
    }
    line_ranges = _map_line_ranges(item)
    if line_ranges:
        vuln["line_ranges"] = line_ranges
    return vuln


def _strip_internal(vuln: dict) -> dict:
    return {key: value for key, value in vuln.items() if not key.startswith("_")}


def _map_severity(value: object) -> str:
    text = _clean_str(value).lower()
    if not text:
        return "85_high"
    if text in SEVERITY_VALUES.values():
        return text
    for name, mapped in SEVERITY_VALUES.items():
        if name in text:
            return mapped
    return "85_high"


def _map_category(item: dict) -> str:
    raw = f"{_clean_str(item.get('category'))} {_clean_str(item.get('title'))}".lower()
    if not raw.strip():
        return DEFAULT_CATEGORY
    for value in CATEGORY_VALUES:
        if value in raw:
            return value
    for hint, value in CATEGORY_HINTS:
        if hint in raw:
            return value
    return DEFAULT_CATEGORY


def _map_line_ranges(item: dict) -> list[dict]:
    start = _coerce_int(item.get("line_start"))
    end = _coerce_int(item.get("line_end"))
    if start is None and end is None:
        ranges = item.get("line_ranges")
        if isinstance(ranges, list):
            cleaned = []
            for entry in ranges:
                if not isinstance(entry, dict):
                    continue
                lo = _coerce_int(entry.get("start"))
                hi = _coerce_int(entry.get("end"))
                if lo is not None:
                    cleaned.append({"start": lo, "end": hi if hi is not None else lo})
            return cleaned
        return []
    if start is None:
        start = end
    if end is None or end < start:
        end = start
    return [{"start": start, "end": end}]


# --- small coercion helpers --------------------------------------------------


def _clean_str(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    return str(value).strip()


def _coerce_confidence(value: object) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.7  # unlabelled findings keep a moderate default confidence
    if number > 1:
        number = number / 100 if number <= 100 else 1.0
    return max(0.0, min(1.0, number))


def _coerce_int(value: object) -> int | None:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


if __name__ == "__main__":
    print(json.dumps(agent_main(), indent=2))
