from __future__ import annotations

"""SN60 / Bitsec miner — multi-pass specialist depth-first auditor.

Inspired by the merged king in PR #47 (matcher-shaped findings, whole-contract
context) and multi-pass challengers that ranked higher but still lost on recall.
This agent keeps the scorer-aligned title/description shape while running three
narrow specialist passes per top-ranked contract (access control, value flow,
oracle/accounting) concurrently across targets so more code is covered inside the
sandbox budget. Findings are normalized to name file, contract, function,
mechanism, and impact — the fields the semantic matcher checks.

Self-contained (stdlib only). Uses the validator inference proxy only.
"""

import json
import os
import re
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

SOL_SUFFIXES = (".sol", ".vy")
SKIP_DIRS = {
    "test", "tests", "mock", "mocks", "example", "examples", "script", "scripts",
    "broadcast", "node_modules", "vendor", "out", "artifacts", "cache",
    "forge-std", "openzeppelin-contracts", "openzeppelin",
}
SKIP_DIRS_UNDER_SRC = {"test", "tests", "mock", "mocks"}
RISK_TERMS = (
    "vault", "router", "bridge", "proxy", "upgrade", "oracle", "govern", "pool",
    "staking", "market", "lend", "borrow", "collateral", "controller", "strategy",
    "auction", "treasury", "manager", "reserve", "token", "admin", "owner", "swap",
)
RISK_PATTERNS = (
    r"\bdelegatecall\b", r"\.call\s*\{", r"\bselfdestruct\b", r"\btx\.origin\b",
    r"\bassembly\b", r"\bonlyOwner\b", r"\bupgradeTo\b", r"\bwithdraw\b",
    r"\bredeem\b", r"\bliquidat", r"\bflash", r"\bgetPrice\b", r"\blatestAnswer\b",
    r"\bunchecked\b", r"\breentran", r"\bpermit\b", r"\becrecover\b",
)
CONTRACT_RE = re.compile(r"\b(?:contract|library)\s+([A-Za-z_][A-Za-z0-9_]*)")
FUNCTION_RE = re.compile(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
IMPORT_RE = re.compile(r'^\s*import\b[^;]*?["\']([^"\']+)["\']', re.MULTILINE)
INHERIT_RE = re.compile(r"\bis\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{")

MAX_FILE_BYTES = 220_000
MAX_CONTRACT_CHARS = 18_000
MAX_CONTEXT_CHARS = 6_000
TOP_TARGETS = 5
MAX_WORKERS = 3
MAX_FINDINGS = 8
MAX_RUNTIME = 195.0
REQUEST_TIMEOUT = 140
MAX_RETRIES = 2

SYSTEM = (
    "You are an elite smart-contract auditor. Report only exploitable HIGH or "
    "CRITICAL issues with a concrete attack path. Ignore style, gas, and vague "
    "warnings. Be exact about contract, function, file, mechanism, and impact."
)

SPECIALIST_PROMPTS = {
    "access": (
        "Focus on missing or bypassable access control, privilege escalation, "
        "initializer/front-running, unsafe external calls from unprotected entrypoints, "
        "and role/owner confusion."
    ),
    "value": (
        "Focus on incorrect fund accounting, share/asset conversion bugs, donation "
        "attacks, reentrancy draining value, unsafe transfers, and balance desync."
    ),
    "oracle": (
        "Focus on stale/manipulable oracle usage, rounding that bricks solvency, "
        "precision loss, unchecked math, and iteration limits causing DoS or theft."
    ),
}


def agent_main(
    project_dir: str | None = None,
    inference_api: str | None = None,
) -> dict:
    findings: list[dict[str, object]] = []
    root = _project_root(project_dir)
    if root is None:
        return {"vulnerabilities": findings}

    deadline = time.monotonic() + MAX_RUNTIME
    ranked = _rank_sources(root)
    if not ranked:
        return {"vulnerabilities": findings}

    by_rel = {str(r["rel"]): r for r in ranked}
    collected: list[dict[str, object]] = []
    targets = ranked[:TOP_TARGETS]

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = [
            pool.submit(_analyze_target, target, by_rel, inference_api, deadline)
            for target in targets
        ]
        for fut in as_completed(futures):
            if time.monotonic() > deadline:
                break
            try:
                collected.extend(fut.result())
            except Exception:
                continue

    findings = _dedupe(collected)[:MAX_FINDINGS]
    return {"vulnerabilities": findings}


def _project_root(project_dir: str | None) -> Path | None:
    candidates: list[str] = []
    if project_dir:
        candidates.append(project_dir)
    for key in ("PROJECT_DIR", "PROJECT_PATH", "PROJECT_ROOT", "PROJECT_CODE"):
        val = os.environ.get(key)
        if val:
            candidates.append(val)
    candidates.extend(["/app/project_code", "/app/project", "/project", "/code", "."])
    for cand in candidates:
        try:
            path = Path(cand).expanduser().resolve()
        except (OSError, RuntimeError):
            continue
        if path.is_dir() and any(path.rglob("*.sol")):
            return path
    return None


def _should_skip(rel_parts: tuple[str, ...]) -> bool:
    if not rel_parts:
        return False
    in_src = "src" in {p.lower() for p in rel_parts[:-1]}
    for part in rel_parts[:-1]:
        low = part.lower()
        if in_src:
            if low in SKIP_DIRS_UNDER_SRC:
                return True
        elif low in SKIP_DIRS:
            return True
    return False


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _score(path: Path, text: str) -> int:
    score = 0
    name = path.name.lower()
    posix = path.as_posix().lower()
    for term in RISK_TERMS:
        if term in name:
            score += 7
        elif term in posix:
            score += 2
    for pat in RISK_PATTERNS:
        score += min(len(re.findall(pat, text, flags=re.IGNORECASE)), 5) * 3
    score += min(text.count("function "), 24)
    if "constructor" in text:
        score += 3
    if "external" in text:
        score += 2
    return score


def _rank_sources(root: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in SOL_SUFFIXES:
            continue
        rel_parts = path.relative_to(root).parts
        if _should_skip(rel_parts):
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        text = _read(path)
        if "function" not in text:
            continue
        contracts = CONTRACT_RE.findall(text)
        if not contracts:
            continue
        rows.append(
            {
                "path": path,
                "rel": path.relative_to(root).as_posix(),
                "text": text,
                "contracts": contracts,
                "score": _score(path, text),
            }
        )
    rows.sort(key=lambda r: (-int(r["score"]), str(r["rel"])))
    return rows


def _context_block(target: dict[str, object], by_rel: dict[str, dict[str, object]]) -> str:
    chunks: list[str] = []
    text = str(target["text"])
    rel = str(target["rel"])
    seen: set[str] = {rel}

    for match in IMPORT_RE.finditer(text):
        imp = match.group(1)
        if not imp:
            continue
        base = imp.rsplit("/", 1)[-1]
        for other_rel, rec in by_rel.items():
            if other_rel in seen:
                continue
            if other_rel.endswith(base) or other_rel.endswith(base + ".sol"):
                seen.add(other_rel)
                snippet = str(rec["text"])[:MAX_CONTEXT_CHARS // 2]
                chunks.append(f"// import context: {other_rel}\n{snippet}")
                break

    for match in INHERIT_RE.finditer(text):
        parent = match.group(1)
        for other_rel, rec in by_rel.items():
            if other_rel in seen:
                continue
            if parent in str(rec["contracts"]):
                seen.add(other_rel)
                snippet = str(rec["text"])[:MAX_CONTEXT_CHARS // 2]
                chunks.append(f"// inheritance context: {other_rel}\n{snippet}")
                break

    joined = "\n\n".join(chunks)
    return joined[:MAX_CONTEXT_CHARS]


def _analyze_target(
    target: dict[str, object],
    by_rel: dict[str, dict[str, object]],
    inference_api: str | None,
    deadline: float,
) -> list[dict[str, object]]:
    if time.monotonic() > deadline:
        return []
    rel = str(target["rel"])
    body = str(target["text"])[:MAX_CONTRACT_CHARS]
    context = _context_block(target, by_rel)
    valid_fns = set(FUNCTION_RE.findall(str(target["text"])))
    out: list[dict[str, object]] = []

    for kind, focus in SPECIALIST_PROMPTS.items():
        if time.monotonic() > deadline:
            break
        prompt = _build_prompt(rel, target, body, context, focus)
        try:
            raw_text = _infer(
                inference_api,
                [
                    {"role": "system", "content": SYSTEM},
                    {"role": "user", "content": prompt},
                ],
            )
        except (RuntimeError, ValueError):
            continue
        for raw in _parse_json_findings(raw_text):
            norm = _normalize_finding(raw, target, valid_fns)
            if norm is not None:
                norm["pass"] = kind
                out.append(norm)
    return out


def _build_prompt(
    rel: str,
    target: dict[str, object],
    body: str,
    context: str,
    focus: str,
) -> str:
    contracts = ", ".join(target["contracts"][:8]) or "(unknown)"
    truncated = " (truncated)" if len(str(target["text"])) > MAX_CONTRACT_CHARS else ""
    return "\n".join(
        [
            f"Audit file `{rel}` ({focus})",
            f"Contracts: {contracts}",
            "Return STRICT JSON only:",
            '{"findings": [{"title": "<Contract>.<function> — <specific bug>", '
            '"contract": "<Name>", "function": "<fn>", "file": "' + rel + '", '
            '"line": <int|null>, "severity": "high|critical", '
            '"mechanism": "<precondition -> action -> effect>", '
            '"impact": "<concrete loss/privilege/DoS>", '
            '"description": "<2-4 sentences with file, contract, function, mechanism, impact>"}]}',
            "At most 1 finding. If nothing exploitable, return {\"findings\": []}. "
            "Only cite functions that exist in the source.",
            f"----- PRIMARY SOURCE{truncated} -----\n{body}",
            f"----- CROSS-FILE CONTEXT -----\n{context}" if context else "",
        ]
    )


def _infer(inference_api: str | None, messages: list[dict[str, str]]) -> str:
    endpoint = (inference_api or os.environ.get("INFERENCE_API") or "").rstrip("/")
    if not endpoint:
        raise ValueError("INFERENCE_API is not configured.")
    api_key = os.environ.get("INFERENCE_API_KEY", "").strip()
    payload = json.dumps(
        {"messages": messages, "response_format": {"type": "json_object"}, "max_tokens": 6000}
    ).encode("utf-8")
    headers = {"Content-Type": "application/json", "x-inference-api-key": api_key}
    last: Exception | None = None
    for attempt in range(MAX_RETRIES + 1):
        try:
            req = urllib.request.Request(
                endpoint + "/inference", data=payload, method="POST", headers=headers
            )
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            return _content_from_response(data)
        except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
            last = exc
            if attempt < MAX_RETRIES:
                time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"inference failed: {last}")


def _content_from_response(data: dict) -> str:
    choices = data.get("choices")
    if not isinstance(choices, list) or not choices:
        return ""
    message = choices[0].get("message") if isinstance(choices[0], dict) else None
    if not isinstance(message, dict):
        return ""
    content = message.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(
            part.get("text", "")
            for part in content
            if isinstance(part, dict) and part.get("type") == "text"
        )
    return ""


def _parse_json_findings(text: str) -> list[dict[str, object]]:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```[a-zA-Z]*\n?", "", cleaned)
        cleaned = re.sub(r"\n?```$", "", cleaned).strip()
    obj = None
    try:
        obj = json.loads(cleaned)
    except json.JSONDecodeError:
        start = cleaned.find("{")
        if start != -1:
            depth = 0
            for idx in range(start, len(cleaned)):
                ch = cleaned[idx]
                depth += 1 if ch == "{" else -1 if ch == "}" else 0
                if depth == 0:
                    try:
                        obj = json.loads(cleaned[start : idx + 1])
                    except json.JSONDecodeError:
                        obj = None
                    break
    if not isinstance(obj, dict):
        return []
    items = obj.get("findings") or obj.get("vulnerabilities") or []
    return [it for it in items if isinstance(it, dict)] if isinstance(items, list) else []


def _normalize_finding(
    raw: dict[str, object],
    target: dict[str, object],
    valid_fns: set[str],
) -> dict[str, object] | None:
    severity = str(raw.get("severity") or "").strip().lower()
    if severity not in {"high", "critical"}:
        return None

    contract = str(raw.get("contract") or (target["contracts"][0] if target["contracts"] else "")).strip()
    function = str(raw.get("function") or "").strip().strip("()")
    if function and valid_fns and function not in valid_fns:
        function = function.split(".")[-1]
        if function not in valid_fns:
            function = ""

    file_path = str(raw.get("file") or target["rel"]).strip() or str(target["rel"])
    mechanism = str(raw.get("mechanism") or "").strip()
    impact = str(raw.get("impact") or "").strip()
    description = str(raw.get("description") or "").strip()
    title = str(raw.get("title") or "").strip()

    loc = f"{contract}.{function}" if contract and function else (contract or function or "")
    if not title and loc:
        title = f"{loc} — {severity} severity issue"
    elif loc and loc.lower() not in title.lower():
        title = f"{loc} — {title}"

    if len(description) < 80 or (function and function not in description):
        parts = [f"In `{file_path}`"]
        if contract:
            parts.append(f"contract `{contract}`")
        if function:
            parts.append(f"function `{function}()`")
        sentence = ", ".join(parts) + "."
        if mechanism:
            sentence += f" Mechanism: {mechanism.rstrip('.')}."
        if impact:
            sentence += f" Impact: {impact.rstrip('.')}."
        if len(sentence) > len(description):
            description = sentence

    if len(description) < 80:
        return None

    return {
        "title": title[:200],
        "description": description,
        "severity": severity,
        "file": file_path,
        "function": function,
        "line": raw.get("line") if isinstance(raw.get("line"), int) else None,
        "type": str(raw.get("type") or "logic"),
        "confidence": 0.92 if severity == "critical" else 0.82,
    }


def _dedupe(findings: list[dict[str, object]]) -> list[dict[str, object]]:
    seen: set[tuple[str, str]] = set()
    ordered = sorted(
        findings,
        key=lambda f: (f["severity"] == "critical", float(f["confidence"])),
        reverse=True,
    )
    out: list[dict[str, object]] = []
    for item in ordered:
        key = (
            str(item["file"]).lower(),
            str(item.get("function") or "").lower() or str(item["title"]).lower()[:48],
        )
        if key in seen:
            continue
        seen.add(key)
        clean = {k: v for k, v in item.items() if k != "pass"}
        out.append(clean)
    return out


if __name__ == "__main__":
    import sys

    print(json.dumps(agent_main(sys.argv[1] if len(sys.argv) > 1 else None), indent=2))
