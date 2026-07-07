from __future__ import annotations

"""SN60 / Bitsec miner — three-call budget-optimized depth-first matcher.

Round rules: **3 model calls and 24,000 output tokens per problem** (enforced at
the proxy). The current king (PR #47) still loops over 4 targets, so its 4th call
is refused — this agent spends exactly three deliberate calls on the three
highest-ranked contracts.

  * call 1 — deepest pass on #1 (whole file + related context, up to 3 findings);
  * call 2 — full audit on #2;
  * call 3 — full audit on #3, or a recall pass on #1 if calls 1–2 found <2 bugs.

Every finding is matcher-shaped (file, contract, function, mechanism, impact).
Handles HTTP 429 by returning findings collected so far (never crashes the run).

Self-contained (stdlib only). Validator inference proxy only.
"""

import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path

SOL_SUFFIXES = (".sol", ".vy")
SKIP_OUTSIDE_SRC = frozenset({
    "test", "tests", "mock", "mocks", "example", "examples", "script", "scripts",
    "broadcast", "node_modules", "vendor", "vendors", "out", "artifacts", "cache",
    "forge-std", "openzeppelin-contracts", "openzeppelin", "interfaces", "interface",
})
SKIP_UNDER_SRC = frozenset({"test", "tests", "mock", "mocks"})
RISK_TERMS = (
    "vault", "router", "bridge", "proxy", "upgrade", "oracle", "govern", "treasury",
    "manager", "pool", "reward", "staking", "market", "reserve", "lend", "borrow",
    "collateral", "controller", "strategy", "auction", "token", "admin", "owner",
    "swap", "escrow", "mint", "wallet",
)
RISK_PATTERNS = (
    r"\bdelegatecall\b", r"\.call\s*\{", r"\bselfdestruct\b", r"\btx\.origin\b",
    r"\bassembly\b", r"\becrecover\b", r"\bpermit\b", r"\bonlyOwner\b", r"\bonlyRole\b",
    r"\bupgradeTo\b", r"\binitialize\b", r"\bwithdraw\b", r"\bredeem\b",
    r"\bliquidat", r"\bborrow\b", r"\brepay\b", r"\bunchecked\b", r"\breentran",
    r"\bflash", r"\bgetPrice\b", r"\blatestAnswer\b", r"\btransferFrom\b",
    r"\bmsg\.value\b",
)
CONTRACT_RE = re.compile(r"\b(?:contract|library|abstract\s+contract)\s+([A-Za-z_][A-Za-z0-9_]*)")
FUNCTION_RE = re.compile(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
IMPORT_RE = re.compile(r'^\s*import\b[^;]*?["\']([^"\']+)["\']', re.MULTILINE)

MAX_FILE_BYTES = 220_000
MAX_CALLS = 3
TOP_TARGETS = 3
MAX_CONTRACT_CHARS = 20_000
MAX_RELATED_CHARS = 5_000
MAX_FINDINGS = 8
MAX_PER_CALL = 3
MAX_RUNTIME = 190.0
REQUEST_TIMEOUT = 120
MAX_OUTPUT_TOKENS = 7500
RETRIES = 1

SYSTEM = (
    "You are a principal smart-contract auditor. Report only REAL exploitable "
    "HIGH or CRITICAL issues with concrete attack paths. Ignore gas and style. "
    "Be exact about file, contract, and function."
)


class BudgetExhausted(Exception):
    """Proxy returned 429 — no more calls allowed for this problem."""


def agent_main(
    project_dir: str | None = None,
    inference_api: str | None = None,
) -> dict:
    findings: list[dict[str, object]] = []
    root = _project_root(project_dir)
    if root is None:
        return {"vulnerabilities": findings}

    records = _discover(root)
    if not records:
        return {"vulnerabilities": findings}

    by_rel = {str(r["rel"]): r for r in records}
    targets = records[:TOP_TARGETS]
    calls_used = 0
    deadline = time.monotonic() + MAX_RUNTIME

    def _spend_call(target: dict[str, object], prompt: str) -> list[dict[str, object]]:
        nonlocal calls_used
        if calls_used >= MAX_CALLS or time.monotonic() > deadline:
            return []
        try:
            text = _infer(inference_api, prompt)
            calls_used += 1
        except BudgetExhausted:
            raise
        except (RuntimeError, ValueError):
            return []
        valid = _valid_functions(str(target["content"]))
        return [
            f for f in (_normalize(raw, target, valid) for raw in _parse_findings(text)) if f
        ]

    collected: list[dict[str, object]] = []
    try:
        # Call 1 — deepest on best target
        t0 = targets[0]
        related0 = _related_source(t0, by_rel)
        collected.extend(
            _spend_call(t0, _audit_prompt(t0, related0, max_findings=MAX_PER_CALL, deep=True))
        )

        if len(targets) > 1 and calls_used < MAX_CALLS:
            t1 = targets[1]
            collected.extend(
                _spend_call(
                    t1,
                    _audit_prompt(t1, _related_source(t1, by_rel), max_findings=MAX_PER_CALL),
                )
            )

        if calls_used < MAX_CALLS and time.monotonic() < deadline:
            if len(collected) < 2 and len(targets) > 0:
                # Recall pass on #1 when thin — hunt missed issues
                collected.extend(
                    _spend_call(
                        t0,
                        _recall_prompt(t0, collected),
                    )
                )
            elif len(targets) > 2:
                t2 = targets[2]
                collected.extend(
                    _spend_call(
                        t2,
                        _audit_prompt(t2, _related_source(t2, by_rel), max_findings=MAX_PER_CALL),
                    )
                )
    except BudgetExhausted:
        pass

    findings = _dedupe(collected)[:MAX_FINDINGS]
    return {"vulnerabilities": findings}


def _project_root(project_dir: str | None) -> Path | None:
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
        if p.is_dir() and _has_sources(p):
            return p
    return None


def _has_sources(root: Path) -> bool:
    try:
        for path in root.rglob("*"):
            if path.is_file() and path.suffix.lower() in SOL_SUFFIXES:
                return True
    except OSError:
        return False
    return False


def _skip_dir(parts: tuple[str, ...]) -> bool:
    if not parts:
        return False
    in_src = "src" in {p.lower() for p in parts}
    for part in parts:
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


def _score(path: Path, content: str) -> int:
    score = 0
    name, posix = path.name.lower(), path.as_posix().lower()
    for term in RISK_TERMS:
        if term in name:
            score += 7
        elif term in posix:
            score += 2
    for pat in RISK_PATTERNS:
        score += min(len(re.findall(pat, content, flags=re.IGNORECASE)), 5) * 3
    score += min(content.count("function "), 24)
    if "constructor" in content:
        score += 3
    return score


def _discover(project_root: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for path in sorted(project_root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in SOL_SUFFIXES:
            continue
        rel_parts = path.relative_to(project_root).parts[:-1]
        if _skip_dir(rel_parts):
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        content = _read(path)
        if "function" not in content:
            continue
        contracts = CONTRACT_RE.findall(content)
        if not contracts:
            continue
        rows.append({
            "path": path,
            "rel": path.relative_to(project_root).as_posix(),
            "content": content,
            "contracts": contracts,
            "score": _score(path, content),
        })
    rows.sort(key=lambda r: (-int(r["score"]), str(r["rel"])))
    return rows


def _related_source(target: dict[str, object], by_rel: dict[str, dict[str, object]]) -> str | None:
    chunks: list[str] = []
    for match in IMPORT_RE.finditer(str(target["content"])):
        imp = match.group(1)
        if not imp or not (imp.startswith(".") or imp.endswith(".sol")):
            continue
        base = imp.rsplit("/", 1)[-1]
        for rel, rec in by_rel.items():
            if rel == target["rel"]:
                continue
            if rel.endswith(base) or rel.endswith(base + ".sol"):
                chunks.append(f"// related: {rel}\n{str(rec['content'])[:MAX_RELATED_CHARS]}")
                break
        if len(chunks) >= 2:
            break
    return "\n\n".join(chunks) if chunks else None


def _json_shape(rel: str) -> str:
    return (
        '{"findings": [{"title": "<Contract>.<function> — <specific bug>", '
        f'"contract": "<Name>", "function": "<fn>", "file": "{rel}", '
        '"line": <int|null>, "severity": "high|critical", '
        '"mechanism": "<precondition -> action -> effect>", '
        '"impact": "<concrete loss>", '
        '"description": "<3-4 sentences: file, contract, function, mechanism, impact>"}]}'
    )


def _audit_prompt(
    target: dict[str, object],
    related: str | None,
    *,
    max_findings: int,
    deep: bool = False,
) -> str:
    rel = str(target["rel"])
    contracts = ", ".join(target["contracts"][:6]) or "?"
    cap = MAX_CONTRACT_CHARS if deep else min(MAX_CONTRACT_CHARS, 16_000)
    body = str(target["content"])[:cap]
    trunc = " (truncated)" if len(str(target["content"])) > cap else ""
    lines = [
        "Audit this Solidity file for ALL distinct HIGH/CRITICAL vulnerabilities.",
        f"File (use exactly as `file`): {rel}",
        f"Contracts: {contracts}",
        "Examine every state-changing function. Only concrete exploit paths.",
        "Return STRICT JSON:",
        _json_shape(rel),
        f"Up to {max_findings} findings. Empty if none: {{\"findings\": []}}",
        f"----- SOURCE{trunc} -----",
        body,
    ]
    if related:
        lines += ["----- RELATED -----", related[:MAX_RELATED_CHARS]]
    return "\n".join(lines)


def _recall_prompt(target: dict[str, object], prior: list[dict[str, object]]) -> str:
    rel = str(target["rel"])
    body = str(target["content"])[:MAX_CONTRACT_CHARS]
    slim = [{"title": p.get("title"), "function": p.get("function")} for p in prior[:4]]
    return "\n".join([
        f"Re-read `{rel}` carefully. Prior candidates:",
        json.dumps(slim, ensure_ascii=False),
        "",
        "Find ANY additional real HIGH/CRITICAL issues missed before. "
        "Drop anything speculative from the prior list if you include it again.",
        "Return STRICT JSON:",
        _json_shape(rel),
        f"Up to {MAX_PER_CALL} findings.",
        "----- SOURCE -----",
        body,
    ])


def _infer(inference_api: str | None, user_prompt: str) -> str:
    endpoint = (inference_api or os.environ.get("INFERENCE_API") or "").rstrip("/")
    if not endpoint:
        raise ValueError("INFERENCE_API missing")
    key = os.environ.get("INFERENCE_API_KEY", "").strip()
    payload = json.dumps({
        "messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": user_prompt},
        ],
        "response_format": {"type": "json_object"},
        "max_tokens": MAX_OUTPUT_TOKENS,
    }).encode()
    headers = {"Content-Type": "application/json", "x-inference-api-key": key}
    last: Exception | None = None
    for attempt in range(RETRIES + 1):
        try:
            req = urllib.request.Request(
                endpoint + "/inference", data=payload, method="POST", headers=headers
            )
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                data = json.loads(resp.read().decode())
            return _extract_content(data)
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                raise BudgetExhausted("inference budget exhausted") from exc
            last = exc
        except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
            last = exc
        if attempt < RETRIES:
            time.sleep(2)
    raise RuntimeError(f"inference failed: {last}")


def _extract_content(payload: dict) -> str:
    choices = payload.get("choices")
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
            p.get("text", "") for p in content if isinstance(p, dict) and p.get("type") == "text"
        )
    return ""


def _parse_findings(content: str) -> list[dict[str, object]]:
    text = content.strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\n?", "", text)
        text = re.sub(r"\n?```$", "", text).strip()
    obj = None
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        start, depth = text.find("{"), 0
        if start != -1:
            for i in range(start, len(text)):
                depth += 1 if text[i] == "{" else -1 if text[i] == "}" else 0
                if depth == 0:
                    try:
                        obj = json.loads(text[start : i + 1])
                    except json.JSONDecodeError:
                        obj = None
                    break
    if not isinstance(obj, dict):
        return []
    items = obj.get("findings") or obj.get("vulnerabilities") or obj.get("candidates")
    return [it for it in items if isinstance(it, dict)] if isinstance(items, list) else []


def _valid_functions(content: str) -> set[str]:
    return set(FUNCTION_RE.findall(content))


def _normalize(
    raw: dict[str, object], target: dict[str, object], valid_fns: set[str]
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
    loc = f"{contract}.{function}" if contract and function else (contract or function)
    if not title:
        title = f"{loc} — {severity} issue" if loc else f"{severity} issue"
    elif loc and loc.lower() not in title.lower():
        title = f"{loc} — {title}"
    if len(description) < 80 or (function and function not in description):
        segs = [f"In `{file_path}`"]
        if contract:
            segs.append(f"contract `{contract}`")
        if function:
            segs.append(f"function `{function}()`")
        blob = ", ".join(segs) + "."
        if mechanism:
            blob += f" Mechanism: {mechanism.rstrip('.')}."
        if impact:
            blob += f" Impact: {impact.rstrip('.')}."
        if len(blob) > len(description):
            description = blob
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
        "confidence": 0.9 if severity == "critical" else 0.82,
    }


def _dedupe(findings: list[dict[str, object]]) -> list[dict[str, object]]:
    seen: set[tuple[str, str]] = set()
    out: list[dict[str, object]] = []
    for f in sorted(findings, key=lambda x: (x["severity"] == "critical", float(x["confidence"])), reverse=True):
        key = (str(f["file"]).lower(), str(f.get("function") or "").lower() or str(f["title"]).lower()[:40])
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


if __name__ == "__main__":
    import sys

    print(json.dumps(agent_main(sys.argv[1] if len(sys.argv) > 1 else None), indent=2))
