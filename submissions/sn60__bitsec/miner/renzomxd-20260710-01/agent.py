from __future__ import annotations

"""SN60 Bitsec miner: heuristic source ranking plus LLM-assisted audits."""

import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

CODE_EXTENSIONS = (".sol", ".vy", ".rs")
IGNORED_DIRECTORY_NAMES = {
    ".git", ".github", "node_modules", "lib", "libs", "vendor", "vendors",
    "test", "tests", "mock", "mocks", "script", "scripts", "docs", "artifacts",
    "cache", "out", "build", "dist", "coverage", "broadcast", "examples", "example",
    "interfaces", "generated",
}
MAX_SOURCE_BYTES = 240_000
MAX_FILES_CONSIDERED = 60
MAX_FILES_PER_BATCH = 3
MAX_BATCHES = 2
MAX_BATCH_CHARACTERS = 26_000
MAX_FINDINGS_RETURNED = 8
MAX_RUNTIME_SECONDS = 200
REQUEST_TIMEOUT_SECONDS = 140

CONTRACT_DECL_RE = re.compile(
    r"^\s*(?:abstract\s+contract|contract|library|interface)\s+([A-Za-z_]\w*)",
    re.MULTILINE,
)
RUST_DECL_RE = re.compile(r"^\s*(?:pub\s+)?(?:struct|enum|trait|impl)\s+([A-Za-z_]\w*)", re.MULTILINE)

# Weighted regex risk signals. These are generic smart-contract security
# vocabulary (reentrancy, access control, oracle/price handling, signature
# replay, unchecked arithmetic) - not tied to any specific project.
RISK_SIGNALS: tuple[tuple[str, int], ...] = (
    (r"\.call\{", 12),
    (r"\.call\(", 7),
    (r"\.delegatecall\(", 14),
    (r"\.staticcall\(", 4),
    (r"\.send\(", 6),
    (r"\.transfer\(", 4),
    (r"selfdestruct", 10),
    (r"unchecked\s*\{", 9),
    (r"assembly\s*\{", 6),
    (r"ecrecover", 8),
    (r"permit\s*\(", 7),
    (r"tx\.origin", 8),
    (r"block\.timestamp", 3),
    (r"block\.number", 2),
    (r"nonReentrant", -3),
    (r"onlyOwner", -2),
    (r"onlyRole", -2),
    (r"whenNotPaused", -2),
    (r"initialize\s*\(", 6),
    (r"upgradeTo", 8),
    (r"setImplementation", 8),
    (r"withdraw", 5),
    (r"deposit", 3),
    (r"redeem", 5),
    (r"liquidat", 7),
    (r"borrow", 5),
    (r"repay", 4),
    (r"flashLoan", 8),
    (r"swap", 4),
    (r"oracle", 6),
    (r"getPrice", 6),
    (r"totalSupply", 3),
    (r"balanceOf", 2),
    (r"allowance", 4),
    (r"transferFrom", 4),
    (r"nonce", 4),
    (r"signature", 5),
    (r"slash", 6),
    (r"claim", 4),
    (r"vest", 4),
    (r"checked_add|checked_sub|checked_mul|checked_div", 6),
    (r"saturating_", 4),
    (r"wrapping_", 8),
    (r"as u128|as u64|as u32", 5),
)

SPECULATIVE_HEDGE_RE = re.compile(
    r"\b(if the admin|if an? external (?:dependency|contract)|if the token is malicious|"
    r"malicious erc20|non-?standard erc20|could potentially|might allow|may allow)\b",
    re.IGNORECASE,
)

AUDIT_SYSTEM_PROMPT = (
    "You are a precise smart-contract security auditor reviewing unfamiliar source code. "
    "Report only concrete, high-confidence high or critical severity vulnerabilities with a "
    "clear exploit path grounded in the exact code shown. Do not speculate about malicious "
    "external actors, malicious tokens, or hypothetical future changes. Do not report style, "
    "gas, or informational issues. Respond with strict JSON only."
)


def _stderr(message: str) -> None:
    print(f"[sn60-fresh-agent] {message}", file=sys.stderr)


def _resolve_project_root(project_dir: str | None) -> Path | None:
    guesses = []
    if project_dir:
        guesses.append(project_dir)
    for env_name in ("PROJECT_DIR", "PROJECT_PATH", "PROJECT_ROOT", "PROJECT_CODE"):
        env_value = os.environ.get(env_name)
        if env_value:
            guesses.append(env_value)
    guesses.extend(["/app/project_code", "/app/project", "/project", "/code", "."])
    for guess in guesses:
        try:
            candidate = Path(guess).expanduser().resolve()
        except (OSError, RuntimeError):
            continue
        if candidate.is_dir() and _contains_source(candidate):
            return candidate
    return None


def _contains_source(root: Path) -> bool:
    try:
        return any(path.suffix.lower() in CODE_EXTENSIONS for path in root.rglob("*") if path.is_file())
    except OSError:
        return False


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _collect_source_files(root: Path) -> list[dict[str, Any]]:
    collected: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in CODE_EXTENSIONS:
            continue
        try:
            relative = path.relative_to(root)
        except ValueError:
            continue
        if any(part.lower() in IGNORED_DIRECTORY_NAMES for part in relative.parts[:-1]):
            continue
        try:
            if path.stat().st_size > MAX_SOURCE_BYTES:
                continue
        except OSError:
            continue
        text = _read_text(path)
        if not text.strip():
            continue
        collected.append(
            {
                "relative_path": relative.as_posix(),
                "suffix": path.suffix.lower(),
                "text": text,
            }
        )
    return collected[:MAX_FILES_CONSIDERED]


def _declared_names(text: str, suffix: str) -> list[str]:
    if suffix == ".rs":
        return RUST_DECL_RE.findall(text)[:8]
    return CONTRACT_DECL_RE.findall(text)[:8]


def _risk_score(relative_path: str, text: str) -> int:
    lowered_path = relative_path.lower()
    score = 0
    for pattern, weight in RISK_SIGNALS:
        hits = len(re.findall(pattern, text, re.IGNORECASE))
        if hits:
            score += min(hits, 6) * weight
    if any(term in lowered_path for term in ("vault", "pool", "market", "router", "staking", "escrow", "auction")):
        score += 10
    if any(term in lowered_path for term in ("mock", "helper", "faucet", "deployer")):
        score -= 20
    function_count = len(re.findall(r"\bfunction\s+\w+\s*\(", text)) + len(re.findall(r"^\s*(?:pub\s+)?fn\s+\w+", text, re.MULTILINE))
    score += min(function_count, 30)
    return score


def _rank_files(files: list[dict[str, Any]]) -> list[dict[str, Any]]:
    for entry in files:
        entry["score"] = _risk_score(entry["relative_path"], entry["text"])
        entry["names"] = _declared_names(entry["text"], entry["suffix"])
    return sorted(files, key=lambda entry: (-entry["score"], entry["relative_path"]))


def _build_batches(ranked_files: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    batches: list[list[dict[str, Any]]] = []
    current: list[dict[str, Any]] = []
    current_chars = 0
    for entry in ranked_files:
        if len(batches) >= MAX_BATCHES:
            break
        entry_chars = len(entry["text"])
        if current and (
            len(current) >= MAX_FILES_PER_BATCH or current_chars + entry_chars > MAX_BATCH_CHARACTERS
        ):
            batches.append(current)
            current = []
            current_chars = 0
            if len(batches) >= MAX_BATCHES:
                break
        current.append(entry)
        current_chars += entry_chars
    if current and len(batches) < MAX_BATCHES:
        batches.append(current)
    return batches


def _resolve_endpoint(inference_api: str | None) -> str:
    return (
        inference_api
        or os.environ.get("INFERENCE_API")
        or os.environ.get("KATA_SN60_INFERENCE_API")
        or "http://bitsec_proxy:8000"
    ).rstrip("/")


def _call_model(inference_api: str | None, prompt: str, max_tokens: int) -> str:
    endpoint = _resolve_endpoint(inference_api)
    body = json.dumps(
        {
            "messages": [
                {"role": "system", "content": AUDIT_SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "max_tokens": max_tokens,
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        endpoint + "/inference",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "x-inference-api-key": os.environ.get("INFERENCE_API_KEY", ""),
        },
    )
    last_error: Exception | None = None
    for attempt in range(2):
        try:
            with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
                parsed_response = json.loads(response.read().decode("utf-8", "replace"))
            return _extract_message_content(parsed_response)
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                raise
            last_error = exc
            _stderr(f"inference HTTP {exc.code} on attempt {attempt + 1}")
        except (OSError, ValueError, TimeoutError) as exc:
            last_error = exc
            _stderr(f"inference error on attempt {attempt + 1}: {exc}")
        if attempt == 0:
            time.sleep(1.5)
    raise RuntimeError(f"inference call failed: {last_error}")


def _extract_message_content(payload: dict[str, Any]) -> str:
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        return ""
    message = choices[0].get("message") if isinstance(choices[0], dict) else None
    if not isinstance(message, dict):
        return ""
    content = message.get("content")
    return content if isinstance(content, str) else ""


def _extract_json_object(text: str) -> dict[str, Any]:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```[a-zA-Z]*\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned)
    try:
        parsed = json.loads(cleaned)
        return parsed if isinstance(parsed, dict) else {}
    except json.JSONDecodeError:
        pass
    start = cleaned.find("{")
    if start < 0:
        return {}
    depth = 0
    in_string = False
    escape_next = False
    for index in range(start, len(cleaned)):
        char = cleaned[index]
        if in_string:
            if escape_next:
                escape_next = False
            elif char == "\\":
                escape_next = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                try:
                    parsed = json.loads(cleaned[start : index + 1])
                except json.JSONDecodeError:
                    return {}
                return parsed if isinstance(parsed, dict) else {}
    return {}


def _batch_prompt(batch: list[dict[str, Any]]) -> str:
    instructions = (
        "Review the source files below for real, exploitable high or critical severity "
        "vulnerabilities. Focus on state-changing bugs: incorrect access control, unsafe "
        "external calls before state updates, unchecked arithmetic, oracle or price misuse, "
        "signature or allowance replay, and accounting errors that let value be stolen, "
        "duplicated, or permanently locked. Every finding must name the exact file, the "
        "function it lives in, and quote or closely paraphrase the specific lines that cause "
        "the bug. Skip anything you are not confident about.\n\n"
        'Respond with strict JSON only: {"findings":[{"file":"path","function":"name",'
        '"line":123,"severity":"high|critical","title":"short bug summary",'
        '"description":"2-4 sentences: the flaw, how it is triggered, and the impact"}]}\n'
        "Return at most 4 findings.\n\n"
    )
    sections = []
    for entry in batch:
        header = f"===== FILE: {entry['relative_path']} =====\n"
        if entry["names"]:
            header += f"Declared: {', '.join(entry['names'])}\n"
        sections.append(header + entry["text"])
    return instructions + "\n\n".join(sections)


def _audit_batch(inference_api: str | None, batch: list[dict[str, Any]]) -> list[dict[str, Any]]:
    try:
        raw_text = _call_model(inference_api, _batch_prompt(batch), max_tokens=6500)
    except Exception as exc:
        _stderr(f"batch audit failed: {exc}")
        return []
    parsed = _extract_json_object(raw_text)
    findings = parsed.get("findings")
    if not isinstance(findings, list):
        return []
    return [item for item in findings if isinstance(item, dict)]


def _is_speculative(description: str, title: str) -> bool:
    combined = f"{title} {description}"
    if SPECULATIVE_HEDGE_RE.search(combined):
        return True
    hedge_words = ("if ", "could ", "may ", "might ", "potentially ")
    lowered = f" {combined.lower()} "
    return sum(lowered.count(word) for word in hedge_words) >= 4


def _match_file(raw_path: str, known_paths: list[str]) -> str | None:
    raw_path = raw_path.strip()
    if not raw_path:
        return None
    for known in known_paths:
        if raw_path == known or known.endswith(raw_path) or raw_path.endswith(known):
            return known
    return None


def _finalize_finding(raw: dict[str, Any], known_paths: list[str]) -> dict[str, Any] | None:
    file_value = _match_file(str(raw.get("file") or ""), known_paths)
    if file_value is None:
        return None
    severity = str(raw.get("severity") or "").strip().lower()
    if severity not in {"high", "critical"}:
        return None
    title = str(raw.get("title") or "").strip()
    description = str(raw.get("description") or "").strip()
    if len(description) < 40:
        return None
    if _is_speculative(description, title):
        return None
    function_name = str(raw.get("function") or "").strip()
    if not title:
        title = f"{file_value} - {function_name or 'high-impact vulnerability'}"
    line_value = raw.get("line")
    return {
        "title": title[:200],
        "description": description[:2500],
        "severity": severity,
        "file": file_value,
        "function": function_name,
        "line": line_value if isinstance(line_value, int) else None,
    }


def _dedupe(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen_keys: set[tuple[str, str]] = set()
    unique: list[dict[str, Any]] = []
    for finding in findings:
        key = (str(finding.get("file", "")).lower(), str(finding.get("title", "")).lower()[:100])
        if key in seen_keys:
            continue
        seen_keys.add(key)
        unique.append(finding)
        if len(unique) >= MAX_FINDINGS_RETURNED:
            break
    return unique


def _empty_report() -> dict[str, list[dict[str, Any]]]:
    return {"vulnerabilities": []}


def agent_main(project_dir: str | None = None, inference_api: str | None = None) -> dict:
    started_at = time.monotonic()
    root = _resolve_project_root(project_dir)
    if root is None:
        return _empty_report()

    files = _collect_source_files(root)
    if not files:
        return _empty_report()

    ranked_files = _rank_files(files)
    known_paths = [entry["relative_path"] for entry in ranked_files]
    batches = _build_batches(ranked_files)

    raw_findings: list[dict[str, Any]] = []
    for batch in batches:
        if time.monotonic() - started_at >= MAX_RUNTIME_SECONDS:
            break
        raw_findings.extend(_audit_batch(inference_api, batch))

    finalized = []
    for raw in raw_findings:
        finding = _finalize_finding(raw, known_paths)
        if finding is not None:
            finalized.append(finding)
    return {"vulnerabilities": _dedupe(finalized)}


if __name__ == "__main__":
    project_argument = sys.argv[1] if len(sys.argv) > 1 else None
    print(json.dumps(agent_main(project_argument), indent=2))
