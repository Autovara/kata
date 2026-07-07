from __future__ import annotations

"""SN60 Bitsec miner — 3-call budget-optimized depth-first matcher.

Competition budget: exactly 3 model calls and 24k output tokens per problem.
Strategy (proven by king PR #47, adapted for the cap):
  * static ranking picks the three highest-yield contracts — no triage LLM call;
  * one deep whole-contract audit per call with inlined related-import context;
  * matcher-shaped findings (file, contract, function, mechanism, impact);
  * zero retries and no polish pass — every call counts.
"""

import json
import os
import re
import urllib.error
import urllib.request
from pathlib import Path

SOL_EXTS = (".sol", ".vy")
SKIP_DIRS = frozenset({
    "test", "tests", "mock", "mocks", "example", "examples", "script",
    "scripts", "broadcast", "node_modules", "vendor", "vendors", "lib",
    "out", "artifacts", "cache", "interfaces", "interface",
})
NAME_SIGNALS = (
    "vault", "router", "bridge", "proxy", "upgrade", "oracle", "govern",
    "treasury", "manager", "pool", "reward", "staking", "market", "reserve",
    "lend", "borrow", "collateral", "controller", "strategy", "auction",
    "token", "admin", "owner",
)
CODE_SIGNALS = (
    r"\bdelegatecall\b", r"\.call\s*\{", r"\bselfdestruct\b", r"\btx\.origin\b",
    r"\bassembly\b", r"\becrecover\b", r"\bpermit\b", r"\bupgradeTo\b",
    r"\binitialize\b", r"\bonlyOwner\b", r"\bonlyRole\b",
    r"\bwithdraw\b", r"\bredeem\b", r"\bliquidat", r"\bborrow\b", r"\brepay\b",
    r"\btransferFrom\b", r"\bunchecked\b", r"\breentran", r"\bflash",
    r"\bgetPrice\b", r"\blatestAnswer\b", r"\bslot0\b",
)
CONTRACT_RE = re.compile(
    r"\b(?:contract|library|abstract\s+contract)\s+([A-Za-z_][A-Za-z0-9_]*)"
)
FN_RE = re.compile(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
IMPORT_RE = re.compile(r'^\s*import\b[^;]*?["\']([^"\']+)["\']', re.MULTILINE)

MAX_BYTES = 200_000
CALL_BUDGET = 3
MAX_CHARS = 15_000
RELATED_CHARS = 3_500
MAX_FINDINGS = 6
HTTP_SEC = 140

SYSTEM = (
    "You are a senior smart-contract security auditor. Find only REAL exploitable "
    "HIGH or CRITICAL vulnerabilities with a concrete attack path. Ignore gas, "
    "style, and hypotheticals. Be precise about file, contract, and function names. "
    "Respond with compact JSON only."
)


def find_root(project_dir: str | None) -> Path | None:
    opts: list[str] = []
    if project_dir:
        opts.append(project_dir)
    for key in ("PROJECT_DIR", "PROJECT_PATH", "PROJECT_ROOT", "PROJECT_CODE"):
        v = os.environ.get(key)
        if v:
            opts.append(v)
    opts += ["/app/project_code", "/app/project", "/project", "/code", "."]
    for raw in opts:
        try:
            root = Path(raw).expanduser().resolve()
        except (OSError, RuntimeError):
            continue
        if root.is_dir() and _has_sol(root):
            return root
    return None


def _has_sol(root: Path) -> bool:
    try:
        for p in root.rglob("*"):
            if p.is_file() and p.suffix.lower() in SOL_EXTS:
                return True
    except OSError:
        return False
    return False


def load_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def rank_file(path: Path, text: str) -> int:
    s = 0
    nm, px = path.name.lower(), path.as_posix().lower()
    for t in NAME_SIGNALS:
        if t in nm:
            s += 7
        elif t in px:
            s += 3
    for pat in CODE_SIGNALS:
        s += min(len(re.findall(pat, text, flags=re.IGNORECASE)), 5) * 2
    s += min(text.count("function "), 22)
    if re.search(r"\b(constructor|receive|fallback)\b", text):
        s += 5
    if re.search(r"\binitialize\b", text, re.I):
        s += 8
    if "proxy" in nm or "upgrade" in nm:
        s += 10
    return s


def hot_functions(text: str, limit: int = 5) -> list[str]:
    scores: list[tuple[int, str]] = []
    cur, buf = "", []
    for line in text.splitlines():
        m = FN_RE.search(line)
        if m:
            if cur and buf:
                body = "\n".join(buf)
                sc = sum(1 for p in (r"\.call", r"delegatecall", r"transfer", r"withdraw", r"mint")
                         if re.search(p, body, re.I))
                if "only" not in body[:100]:
                    sc += 2
                scores.append((sc, cur))
            cur, buf = m.group(1), [line]
        elif cur:
            buf.append(line)
    if cur and buf:
        body = "\n".join(buf)
        sc = sum(1 for p in (r"\.call", r"delegatecall", r"transfer", r"withdraw", r"mint")
                 if re.search(p, body, re.I))
        scores.append((sc, cur))
    scores.sort(key=lambda x: (-x[0], x[1]))
    return [fn for sc, fn in scores if sc > 0][:limit]


def scan_project(root: Path) -> list[dict]:
    out: list[dict] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in SOL_EXTS:
            continue
        if any(p.lower() in SKIP_DIRS for p in path.relative_to(root).parts[:-1]):
            continue
        try:
            if path.stat().st_size > MAX_BYTES:
                continue
        except OSError:
            continue
        text = load_text(path)
        if "function" not in text:
            continue
        contracts = CONTRACT_RE.findall(text)
        if not contracts:
            continue
        out.append({
            "rel": path.relative_to(root).as_posix(),
            "text": text,
            "contracts": contracts,
            "score": rank_file(path, text),
            "hot": hot_functions(text),
        })
    out.sort(key=lambda r: (-r["score"], r["rel"]))
    return out


def related_snippet(target: dict, catalog: dict[str, dict]) -> str | None:
    rel = target["rel"]
    for m in IMPORT_RE.finditer(target["text"]):
        base = m.group(1).rsplit("/", 1)[-1]
        for other, rec in catalog.items():
            if other != rel and other.endswith(base):
                return f"// related: {other}\n{rec['text'][:RELATED_CHARS]}"
    return None


def llm(inference_api: str | None, messages: list[dict[str, str]]) -> str:
    base = (inference_api or os.environ.get("INFERENCE_API") or "").rstrip("/")
    if not base:
        raise ValueError("INFERENCE_API missing")
    key = os.environ.get("INFERENCE_API_KEY", "").strip()
    body = json.dumps({
        "messages": messages,
        "response_format": {"type": "json_object"},
    }).encode()
    hdrs = {"Content-Type": "application/json", "x-inference-api-key": key}
    req = urllib.request.Request(
        f"{base}/inference", data=body, method="POST", headers=hdrs,
    )
    with urllib.request.urlopen(req, timeout=HTTP_SEC) as resp:
        data = json.loads(resp.read().decode())
    choices = data.get("choices")
    if not isinstance(choices, list) or not choices:
        return ""
    msg = choices[0].get("message") if isinstance(choices[0], dict) else None
    if not isinstance(msg, dict):
        return ""
    c = msg.get("content")
    return c if isinstance(c, str) else ""


def parse_json(text: str) -> dict | None:
    t = text.strip()
    if t.startswith("```"):
        t = re.sub(r"^```[a-zA-Z]*\n?", "", t)
        t = re.sub(r"\n?```$", "", t).strip()
    try:
        o = json.loads(t)
        return o if isinstance(o, dict) else None
    except json.JSONDecodeError:
        start = t.find("{")
        if start < 0:
            return None
        depth = 0
        for i in range(start, len(t)):
            if t[i] == "{":
                depth += 1
            elif t[i] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        o = json.loads(t[start : i + 1])
                        return o if isinstance(o, dict) else None
                    except json.JSONDecodeError:
                        return None
    return None


def parse_items(obj: dict | None) -> list[dict]:
    if not obj:
        return []
    for k in ("findings", "vulnerabilities"):
        v = obj.get(k)
        if isinstance(v, list):
            return [x for x in v if isinstance(x, dict)]
    return []


def audit_prompt(target: dict, related: str | None) -> str:
    rel = target["rel"]
    contracts = ", ".join(target["contracts"][:6])
    body = target["text"][:MAX_CHARS]
    trunc = len(target["text"]) > MAX_CHARS
    hot = target.get("hot") or []
    parts = [
        f"Audit `{rel}` for exploitable HIGH/CRITICAL bugs.\n",
        f"File (use EXACTLY as `file`): {rel}",
        f"Contracts: {contracts}",
    ]
    if hot:
        parts.append(f"Prioritize: {', '.join(hot)}")
    parts += [
        "\nReport only issues with a concrete exploit path. Return strict JSON:",
        '{"findings": [{'
        '"title": "<Contract>.<function> — <specific bug>", '
        '"contract": "<name>", "function": "<name>", '
        f'"file": "{rel}", "line": <int|null>, '
        '"severity": "high|critical", '
        '"mechanism": "<precondition -> action -> effect>", '
        '"impact": "<concrete harm>", '
        '"description": "<2-4 sentences: file, contract, function, mechanism, impact>"'
        "}]}",
        "Max 2 findings. Empty list if none. No invented symbols.\n",
        f"----- SOURCE{' (truncated)' if trunc else ''} -----",
        body,
    ]
    if related:
        parts += ["\n----- RELATED -----", related]
    return "\n".join(parts)


def format_finding(raw: dict, target: dict, valid: set[str]) -> dict | None:
    sev = str(raw.get("severity", "")).lower().strip()
    if sev not in {"high", "critical"}:
        return None

    contract = str(
        raw.get("contract") or (target["contracts"][0] if target["contracts"] else "")
    ).strip()
    function = str(raw.get("function", "")).strip().strip("()")
    if function and valid and function not in valid:
        function = function.split(".")[-1]
        if function not in valid:
            function = ""

    fpath = str(raw.get("file") or target["rel"]).strip()
    mechanism = str(raw.get("mechanism", "")).strip()
    impact = str(raw.get("impact", "")).strip()
    description = str(raw.get("description", "")).strip()
    title = str(raw.get("title", "")).strip()

    loc = f"{contract}.{function}" if contract and function else (contract or function)
    if not title:
        title = f"{loc} — {sev} vulnerability" if loc else f"{sev} vulnerability"
    elif loc and loc.lower() not in title.lower():
        title = f"{loc} — {title}"

    if len(description) < 80 or (function and function not in description):
        where = f"In `{fpath}`"
        if contract:
            where += f", contract `{contract}`"
        if function:
            where += f", function `{function}()`"
        segs = [where + "."]
        if mechanism:
            segs.append(f"Mechanism: {mechanism.rstrip('.')}.")
        if impact:
            segs.append(f"Impact: {impact.rstrip('.')}.")
        rebuilt = " ".join(segs)
        if len(rebuilt) > len(description):
            description = rebuilt

    if len(description) < 80:
        return None

    out: dict = {
        "title": title[:200],
        "description": description,
        "severity": sev,
        "file": fpath,
        "function": function,
        "type": str(raw.get("type") or "logic"),
        "confidence": 0.9 if sev == "critical" else 0.85,
    }
    line = raw.get("line")
    if isinstance(line, int):
        out["line"] = line
    return out


def unique(findings: list[dict]) -> list[dict]:
    seen: set[tuple[str, str]] = set()
    ranked = sorted(
        findings,
        key=lambda f: (f.get("severity") == "critical", float(f.get("confidence", 0))),
        reverse=True,
    )
    out: list[dict] = []
    for f in ranked:
        key = (
            str(f.get("file", "")).lower(),
            str(f.get("function", "")).lower() or str(f.get("title", ""))[:40].lower(),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def agent_main(
    project_dir: str | None = None,
    inference_api: str | None = None,
) -> dict:
    findings: list[dict] = []
    root = find_root(project_dir)
    if root is None:
        return {"vulnerabilities": findings}

    records = scan_project(root)
    if not records:
        return {"vulnerabilities": findings}

    catalog = {r["rel"]: r for r in records}
    collected: list[dict] = []
    calls_used = 0

    for target in records[:CALL_BUDGET]:
        if calls_used >= CALL_BUDGET:
            break
        related = related_snippet(target, catalog)
        try:
            raw_text = llm(
                inference_api,
                [
                    {"role": "system", "content": SYSTEM},
                    {"role": "user", "content": audit_prompt(target, related)},
                ],
            )
            calls_used += 1
        except (RuntimeError, ValueError, urllib.error.URLError, TimeoutError, OSError):
            continue

        valid = set(FN_RE.findall(target["text"]))
        for item in parse_items(parse_json(raw_text)):
            shaped = format_finding(item, target, valid)
            if shaped:
                collected.append(shaped)

    findings = unique(collected)[:MAX_FINDINGS]
    return {"vulnerabilities": findings}


if __name__ == "__main__":
    import sys
    print(json.dumps(agent_main(sys.argv[1] if len(sys.argv) > 1 else None), indent=2))
