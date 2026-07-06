from __future__ import annotations

"""SN60 / Bitsec miner — two-pass self-critiquing depth-first auditor.

Extends the merged king (PR #47) and recent top challengers with:

  * detect pass + critique pass on each high-value contract (recall + precision);
  * critique always runs, even when detect is empty, to catch missed issues;
  * concurrent target chains under a hard wall-clock budget;
  * src/-aware discovery (first-party code under src/lib/ is not skipped);
  * matcher-shaped findings: file, contract, function, mechanism, impact.

Self-contained (stdlib only). Uses the validator inference proxy only.
"""

import json
import os
import re
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from pathlib import Path

SOL_EXTS = (".sol", ".vy")
SKIP_OUTSIDE_SRC = frozenset({
    "test", "tests", "mock", "mocks", "example", "examples", "script", "scripts",
    "broadcast", "node_modules", "vendor", "vendors", "out", "artifacts", "cache",
    "forge-std", "openzeppelin-contracts", "openzeppelin", "solmate", "coverage",
})
SKIP_UNDER_SRC = frozenset({"test", "tests", "mock", "mocks"})
RISK_NAMES = (
    "vault", "router", "bridge", "proxy", "upgrade", "oracle", "govern", "pool",
    "staking", "market", "lend", "borrow", "collateral", "controller", "strategy",
    "auction", "treasury", "manager", "reserve", "token", "admin", "owner", "swap",
    "escrow", "mint", "sale", "timelock", "wallet", "farm", "distributor",
)
RISK_SIGS = (
    r"\bdelegatecall\b", r"\.call\s*\{", r"\bselfdestruct\b", r"\btx\.origin\b",
    r"\bassembly\b", r"\becrecover\b", r"\bpermit\b", r"\bonlyOwner\b", r"\bonlyRole\b",
    r"\bupgradeTo\b", r"\binitialize\b", r"\bwithdraw\b", r"\bredeem\b",
    r"\bliquidat", r"\bborrow\b", r"\brepay\b", r"\bunchecked\b", r"\breentran",
    r"\bflash", r"\bgetPrice\b", r"\blatestAnswer\b", r"\btransferFrom\b",
    r"\bmsg\.value\b", r"\btransferOwnership\b",
)
CONTRACT_RE = re.compile(r"\b(?:contract|library|abstract\s+contract)\s+([A-Za-z_][A-Za-z0-9_]*)")
FUNCTION_RE = re.compile(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
IMPORT_RE = re.compile(r'^\s*import\b[^;]*?["\']([^"\']+)["\']', re.MULTILINE)
INHERIT_RE = re.compile(r"\bis\s+([A-Za-z_][A-Za-z0-9_]+)")

MAX_BYTES = 230_000
DEEP_COUNT = 5
MAX_WORKERS = 5
MAX_SOURCE_CHARS = 24_000
MAX_CTX_CHARS = 5_000
MAX_CTX_FILES = 3
MAX_PER_TARGET = 4
MAX_TOTAL = 12
WALL_SECONDS = 215.0
DETECT_TIMEOUT = 95
CRITIQUE_TIMEOUT = 85
RETRIES = 1

SYSTEM = (
    "You are a principal smart-contract auditor. Report only REAL exploitable "
    "HIGH or CRITICAL issues with concrete attack paths. Ignore gas, style, and "
    "speculation. Be exact about file, contract, and function."
)

JSON_SHAPE = (
    '{"findings": [{"title": "<Contract>.<function> — <specific bug>", '
    '"contract": "<Name>", "function": "<fn>", "file": "<FILE>", '
    '"line": <int|null>, "severity": "high|critical", '
    '"mechanism": "<precondition -> action -> effect>", '
    '"impact": "<concrete loss>", '
    '"description": "<3-5 sentences with file, contract, function, mechanism, impact>"}]}'
)


def agent_main(
    project_dir: str | None = None,
    inference_api: str | None = None,
) -> dict:
    findings: list[dict[str, object]] = []
    root = _workspace_root(project_dir)
    if root is None:
        return {"vulnerabilities": findings}

    deadline = time.monotonic() + WALL_SECONDS
    catalog = _catalog_sources(root)
    if not catalog:
        return {"vulnerabilities": findings}

    by_rel = {str(r["rel"]): r for r in catalog}
    targets = catalog[:DEEP_COUNT]
    bucket: list[dict[str, object]] = []

    with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(targets))) as pool:
        futures = [
            pool.submit(_audit_two_pass, inference_api, t, by_rel, deadline)
            for t in targets
        ]
        for fut in futures:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                bucket.extend(fut.result(timeout=remaining))
            except (FutureTimeout, Exception):
                continue

    findings = _dedupe_findings(bucket)[:MAX_TOTAL]
    return {"vulnerabilities": findings}


def _workspace_root(project_dir: str | None) -> Path | None:
    opts: list[str] = []
    if project_dir:
        opts.append(project_dir)
    for key in ("PROJECT_DIR", "PROJECT_PATH", "PROJECT_ROOT", "PROJECT_CODE"):
        val = os.environ.get(key)
        if val:
            opts.append(val)
    opts.extend(["/app/project_code", "/app/project", "/project", "/code", "."])
    for raw in opts:
        try:
            p = Path(raw).expanduser().resolve()
        except (OSError, RuntimeError):
            continue
        if p.is_dir() and any(p.rglob("*.sol")):
            return p
    return None


def _skip_parts(parts: tuple[str, ...]) -> bool:
    if not parts:
        return False
    in_src = "src" in {x.lower() for x in parts[:-1]}
    for part in parts[:-1]:
        low = part.lower()
        if in_src:
            if low in SKIP_UNDER_SRC:
                return True
        elif low in SKIP_OUTSIDE_SRC:
            return True
    return False


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _rank(path: Path, text: str) -> int:
    score = 0
    name, posix = path.name.lower(), path.as_posix().lower()
    for term in RISK_NAMES:
        if term in name:
            score += 7
        elif term in posix:
            score += 2
    for sig in RISK_SIGS:
        score += min(len(re.findall(sig, text, flags=re.IGNORECASE)), 5) * 3
    score += min(text.count("function "), 26)
    if "constructor" in text:
        score += 3
    # deprioritize interface-only stubs
    if re.search(r"\binterface\s+", text) and text.count("{") <= 2:
        score -= 8
    return score


def _fn_line_map(text: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for i, line in enumerate(text.splitlines(), start=1):
        for m in FUNCTION_RE.finditer(line):
            out.setdefault(m.group(1), i)
    return out


def _catalog_sources(root: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in SOL_EXTS:
            continue
        rel_parts = path.relative_to(root).parts
        if _skip_parts(rel_parts[:-1]):
            continue
        try:
            if path.stat().st_size > MAX_BYTES:
                continue
        except OSError:
            continue
        text = _read(path)
        if "function" not in text:
            continue
        contracts = CONTRACT_RE.findall(text)
        if not contracts:
            continue
        rows.append({
            "path": path,
            "rel": path.relative_to(root).as_posix(),
            "text": text,
            "contracts": contracts,
            "score": _rank(path, text),
            "fn_lines": _fn_line_map(text),
        })
    rows.sort(key=lambda r: (-int(r["score"]), str(r["rel"])))
    return rows


def _context_bundle(target: dict[str, object], by_rel: dict[str, dict[str, object]]) -> str:
    chunks: list[str] = []
    seen = {str(target["rel"])}
    text, rel = str(target["text"]), str(target["rel"])

    for m in IMPORT_RE.finditer(text):
        base = (m.group(1) or "").rsplit("/", 1)[-1]
        if not base:
            continue
        for other_rel, rec in by_rel.items():
            if other_rel in seen:
                continue
            if other_rel.endswith(base) or other_rel.endswith(base + ".sol"):
                seen.add(other_rel)
                chunks.append(f"// import: {other_rel}\n{str(rec['text'])[:MAX_CTX_CHARS // 2]}")
                break
        if len(chunks) >= MAX_CTX_FILES:
            break

    for parent in INHERIT_RE.findall(text):
        for other_rel, rec in by_rel.items():
            if other_rel in seen:
                continue
            if parent in rec["contracts"]:
                seen.add(other_rel)
                chunks.append(f"// inherits: {other_rel}\n{str(rec['text'])[:MAX_CTX_CHARS // 2]}")
                break
        if len(chunks) >= MAX_CTX_FILES:
            break

    return "\n\n".join(chunks)[:MAX_CTX_CHARS]


def _infer(inference_api: str | None, messages: list[dict[str, str]], timeout: int) -> str:
    endpoint = (inference_api or os.environ.get("INFERENCE_API") or "").rstrip("/")
    if not endpoint:
        raise ValueError("INFERENCE_API missing")
    key = os.environ.get("INFERENCE_API_KEY", "").strip()
    body = json.dumps(
        {"messages": messages, "response_format": {"type": "json_object"}, "max_tokens": 7500}
    ).encode()
    headers = {"Content-Type": "application/json", "x-inference-api-key": key}
    last: Exception | None = None
    for attempt in range(RETRIES + 1):
        try:
            req = urllib.request.Request(endpoint + "/inference", data=body, method="POST", headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode())
            return _message_text(data)
        except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
            last = exc
            if attempt < RETRIES:
                time.sleep(2)
    raise RuntimeError(str(last))


def _message_text(payload: dict) -> str:
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        return ""
    msg = choices[0].get("message") if isinstance(choices[0], dict) else None
    if not isinstance(msg, dict):
        return ""
    content = msg.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(
            p.get("text", "") for p in content if isinstance(p, dict) and p.get("type") == "text"
        )
    return ""


def _parse_obj(text: str) -> dict | None:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```[a-zA-Z]*\n?", "", cleaned)
        cleaned = re.sub(r"\n?```$", "", cleaned).strip()
    try:
        obj = json.loads(cleaned)
        return obj if isinstance(obj, dict) else None
    except json.JSONDecodeError:
        pass
    start, depth = cleaned.find("{"), 0
    if start < 0:
        return None
    for i in range(start, len(cleaned)):
        depth += 1 if cleaned[i] == "{" else -1 if cleaned[i] == "}" else 0
        if depth == 0:
            try:
                obj = json.loads(cleaned[start : i + 1])
                return obj if isinstance(obj, dict) else None
            except json.JSONDecodeError:
                return None
    return None


def _raw_findings(text: str) -> list[dict[str, object]]:
    obj = _parse_obj(text)
    if not obj:
        return []
    items = obj.get("findings") or obj.get("vulnerabilities") or []
    return [x for x in items if isinstance(x, dict)] if isinstance(items, list) else []


def _detect_prompt(target: dict[str, object], context: str) -> str:
    rel = str(target["rel"])
    contracts = ", ".join(target["contracts"][:8]) or "?"
    body = str(target["text"])[:MAX_SOURCE_CHARS]
    trunc = " (truncated)" if len(str(target["text"])) > MAX_SOURCE_CHARS else ""
    lines = [
        "Audit this Solidity file for ALL distinct HIGH/CRITICAL vulnerabilities.",
        f"File (use exactly as `file`): {rel}",
        f"Contracts: {contracts}",
        "Examine every state-changing function. Report only concrete exploit paths.",
        "Return STRICT JSON:",
        JSON_SHAPE.replace("<FILE>", rel),
        f"Up to {MAX_PER_TARGET} findings. Empty if none: {{\"findings\": []}}",
        f"----- SOURCE{trunc} -----\n{body}",
    ]
    if context:
        lines.append(f"----- CONTEXT -----\n{context}")
    return "\n".join(lines)


def _critique_prompt(target: dict[str, object], prior: list[dict[str, object]]) -> str:
    rel = str(target["rel"])
    body = str(target["text"])[:MAX_SOURCE_CHARS]
    slim = [
        {"title": p.get("title"), "function": p.get("function"), "severity": p.get("severity")}
        for p in prior
    ]
    intro = (
        "You previously flagged these candidates:"
        if prior
        else "No candidates yet — read the source carefully and find every real issue."
    )
    return "\n".join([
        intro,
        json.dumps(slim, ensure_ascii=False) if slim else "(none)",
        "",
        "1. DROP anything not concretely exploitable HIGH/CRITICAL.",
        "2. ADD any additional real issues you missed, function by function.",
        "Return FINAL list as STRICT JSON:",
        JSON_SHAPE.replace("<FILE>", rel),
        f"At most {MAX_PER_TARGET} findings. Real functions only.",
        "----- SOURCE -----",
        body,
    ])


def _valid_fns(text: str) -> set[str]:
    return set(FUNCTION_RE.findall(text))


def _shape_finding(
    raw: dict[str, object],
    target: dict[str, object],
    valid: set[str],
) -> dict[str, object] | None:
    sev = str(raw.get("severity") or "").lower().strip()
    if sev not in {"high", "critical"}:
        return None

    contract = str(raw.get("contract") or (target["contracts"][0] if target["contracts"] else "")).strip()
    function = str(raw.get("function") or "").strip().strip("()")
    if function and valid and function not in valid:
        function = function.split(".")[-1]
        if function not in valid:
            function = ""

    file_path = str(raw.get("file") or target["rel"]).strip()
    mechanism = str(raw.get("mechanism") or "").strip()
    impact = str(raw.get("impact") or "").strip()
    description = str(raw.get("description") or "").strip()
    title = str(raw.get("title") or "").strip()

    loc = f"{contract}.{function}" if contract and function else (contract or function)
    if not title:
        title = f"{loc} — {sev} issue" if loc else f"{sev} issue"
    elif loc and loc.lower() not in title.lower():
        title = f"{loc} — {title}"

    if len(description) < 80 or (function and function not in description):
        parts = [f"In `{file_path}`"]
        if contract:
            parts.append(f"contract `{contract}`")
        if function:
            parts.append(f"function `{function}()`")
        blob = ", ".join(parts) + "."
        if mechanism:
            blob += f" Mechanism: {mechanism.rstrip('.')}."
        if impact:
            blob += f" Impact: {impact.rstrip('.')}."
        if len(blob) > len(description):
            description = blob

    if len(description) < 80:
        return None

    line = raw.get("line")
    if not isinstance(line, int):
        fn_lines = target.get("fn_lines")
        if function and isinstance(fn_lines, dict):
            line = fn_lines.get(function)

    return {
        "title": title[:200],
        "description": description,
        "severity": sev,
        "file": file_path,
        "function": function,
        "line": line if isinstance(line, int) else None,
        "type": str(raw.get("type") or "logic"),
        "confidence": 0.91 if sev == "critical" else 0.82,
    }


def _audit_two_pass(
    inference_api: str | None,
    target: dict[str, object],
    by_rel: dict[str, dict[str, object]],
    deadline: float,
) -> list[dict[str, object]]:
    if time.monotonic() > deadline:
        return []

    context = _context_bundle(target, by_rel)
    text = str(target["text"])
    valid = _valid_fns(text)

    detect_hits: list[dict[str, object]] = []
    try:
        detect_raw = _infer(
            inference_api,
            [{"role": "system", "content": SYSTEM}, {"role": "user", "content": _detect_prompt(target, context)}],
            DETECT_TIMEOUT,
        )
        detect_hits = [
            f for f in (_shape_finding(r, target, valid) for r in _raw_findings(detect_raw)) if f
        ][:MAX_PER_TARGET]
    except (RuntimeError, ValueError):
        detect_hits = []

    if time.monotonic() > deadline - 12:
        return detect_hits

    try:
        critique_raw = _infer(
            inference_api,
            [
                {"role": "system", "content": SYSTEM},
                {"role": "user", "content": _critique_prompt(target, detect_hits)},
            ],
            CRITIQUE_TIMEOUT,
        )
        refined = [
            f for f in (_shape_finding(r, target, valid) for r in _raw_findings(critique_raw)) if f
        ][:MAX_PER_TARGET]
        return refined if refined else detect_hits
    except (RuntimeError, ValueError):
        return detect_hits


def _title_key(title: str) -> str:
    core = title.split("—", 1)[-1] if "—" in title else title
    return re.sub(r"\s+", " ", core).strip().lower()[:64]


def _dedupe_findings(items: list[dict[str, object]]) -> list[dict[str, object]]:
    seen_fn: set[tuple[str, str]] = set()
    seen_title: set[tuple[str, str]] = set()
    ordered = sorted(
        items,
        key=lambda f: (f["severity"] == "critical", float(f["confidence"])),
        reverse=True,
    )
    out: list[dict[str, object]] = []
    for f in ordered:
        file_k = str(f["file"]).lower()
        fn = str(f.get("function") or "").lower()
        tkey = (file_k, _title_key(str(f["title"])))
        if fn and (file_k, fn) in seen_fn:
            continue
        if tkey in seen_title:
            continue
        if fn:
            seen_fn.add((file_k, fn))
        seen_title.add(tkey)
        out.append(f)
    return out


if __name__ == "__main__":
    import sys

    print(json.dumps(agent_main(sys.argv[1] if len(sys.argv) > 1 else None), indent=2))
