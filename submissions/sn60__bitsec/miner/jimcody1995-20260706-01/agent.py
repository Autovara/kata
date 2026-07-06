from __future__ import annotations

"""SN60 Bitsec miner — triage-then-depth with cross-file context.

Beats breadth-limited depth-first agents by:
  1. triaging the top-ranked sources to pick the highest-yield targets;
  2. deep-auditing more contracts (5) with richer related-file context;
  3. running a focused function-level follow-up when triage flags hot spots;
  4. shaping every finding for the semantic matcher (file, contract, function,
     mechanism, impact) and attaching real source line numbers.

Stdlib only. Uses validator inference proxy; no external APIs.
"""

import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path

SOURCE_EXTS = (".sol", ".vy")
SKIP_DIRS = frozenset({
    "test", "tests", "mock", "mocks", "example", "examples", "script",
    "scripts", "broadcast", "node_modules", "vendor", "vendors", "lib",
    "out", "artifacts", "cache",
})
RISK_TERMS = (
    "vault", "router", "bridge", "proxy", "upgrade", "oracle", "govern",
    "treasury", "manager", "pool", "reward", "staking", "market", "reserve",
    "lend", "borrow", "collateral", "controller", "strategy", "auction",
    "token", "admin", "owner", "swap", "deposit", "claim", "mint",
)
RISK_PATTERNS = (
    r"\bdelegatecall\b", r"\.call\s*\{", r"\bselfdestruct\b", r"\btx\.origin\b",
    r"\bassembly\b", r"\becrecover\b", r"\bpermit\b", r"\bupgradeTo\b",
    r"\binitialize\b", r"\binit\b", r"\bonlyOwner\b", r"\bonlyRole\b",
    r"\bwithdraw\b", r"\bredeem\b", r"\bliquidat", r"\bborrow\b", r"\brepay\b",
    r"\bunchecked\b", r"\breentran", r"\bflash", r"\bgetPrice\b",
    r"\blatestAnswer\b", r"\bslot0\b", r"\btransferFrom\b",
)
CONTRACT_RE = re.compile(
    r"\b(?:contract|library|abstract\s+contract)\s+([A-Za-z_][A-Za-z0-9_]*)"
)
FUNCTION_RE = re.compile(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
IMPORT_RE = re.compile(r'^\s*import\b[^;]*?["\']([^"\']+)["\']', re.MULTILINE)
INHERIT_RE = re.compile(r"\bis\s+([A-Za-z_][A-Za-z0-9_]+)")

MAX_BYTES = 200_000
TRIAGE_POOL = 10
DEEP_TARGETS = 5
MAX_CONTEXT = 18_000
MAX_RELATED = 4_000
MAX_RELATED_FILES = 2
MAX_OUTPUT = 7
WALL_CLOCK = 195.0
HTTP_TIMEOUT = 140
RETRIES = 2

AUDITOR_SYSTEM = (
    "You are an elite smart-contract security researcher. Report only genuine "
    "HIGH or CRITICAL vulnerabilities with a concrete exploit path and material "
    "impact (fund theft, privilege escalation, permanent DoS, accounting break). "
    "Ignore style, gas, informational issues, and hypotheticals without a real "
    "attack sequence. Be exact about file, contract, and function names."
)


# ---------------------------------------------------------------------------
# filesystem helpers
# ---------------------------------------------------------------------------
def locate_workspace(project_dir: str | None) -> Path | None:
    roots: list[str] = []
    if project_dir:
        roots.append(project_dir)
    for key in ("PROJECT_DIR", "PROJECT_PATH", "PROJECT_ROOT", "PROJECT_CODE"):
        val = os.environ.get(key)
        if val:
            roots.append(val)
    roots.extend(("/app/project_code", "/app/project", "/project", "/code", "."))
    for raw in roots:
        try:
            root = Path(raw).expanduser().resolve()
        except (OSError, RuntimeError):
            continue
        if root.is_dir() and _tree_has_sources(root):
            return root
    return None


def _tree_has_sources(root: Path) -> bool:
    try:
        for p in root.rglob("*"):
            if p.is_file() and p.suffix.lower() in SOURCE_EXTS:
                return True
    except OSError:
        return False
    return False


def read_file(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def rank_risk(path: Path, text: str) -> int:
    score = 0
    low_name = path.name.lower()
    low_path = path.as_posix().lower()
    for term in RISK_TERMS:
        if term in low_name:
            score += 7
        elif term in low_path:
            score += 3
    for pat in RISK_PATTERNS:
        score += min(len(re.findall(pat, text, flags=re.IGNORECASE)), 5) * 2
    score += min(text.count("function "), 25)
    if re.search(r"\b(constructor|receive|fallback)\b", text):
        score += 4
    if re.search(r"\b(external|public)\b", text) and "only" not in text[:500]:
        score += 2
    return score


def collect_sources(root: Path) -> list[dict]:
    items: list[dict] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in SOURCE_EXTS:
            continue
        rel_parts = path.relative_to(root).parts[:-1]
        if any(p.lower() in SKIP_DIRS for p in rel_parts):
            continue
        try:
            if path.stat().st_size > MAX_BYTES:
                continue
        except OSError:
            continue
        text = read_file(path)
        if "function" not in text:
            continue
        names = CONTRACT_RE.findall(text)
        if not names:
            continue
        fn_lines = _function_line_map(text)
        items.append({
            "path": path,
            "rel": path.relative_to(root).as_posix(),
            "text": text,
            "contracts": names,
            "score": rank_risk(path, text),
            "fn_lines": fn_lines,
        })
    items.sort(key=lambda x: (-x["score"], x["rel"]))
    return items


def _function_line_map(text: str) -> dict[str, int]:
    lines: dict[str, int] = {}
    for idx, line in enumerate(text.splitlines(), start=1):
        for m in FUNCTION_RE.finditer(line):
            lines.setdefault(m.group(1), idx)
    return lines


def gather_related(target: dict, catalog: dict[str, dict]) -> list[str]:
    blocks: list[str] = []
    seen: set[str] = set()
    text = target["text"]
    rel = target["rel"]

    for m in IMPORT_RE.finditer(text):
        imp = m.group(1)
        if not imp:
            continue
        base = imp.rsplit("/", 1)[-1]
        for other_rel, rec in catalog.items():
            if other_rel == rel or other_rel in seen:
                continue
            if other_rel.endswith(base) or base in other_rel:
                seen.add(other_rel)
                blocks.append(
                    f"// import context: {other_rel}\n{rec['text'][:MAX_RELATED]}"
                )
                if len(blocks) >= MAX_RELATED_FILES:
                    return blocks

    for parent in INHERIT_RE.findall(text):
        for other_rel, rec in catalog.items():
            if other_rel == rel or other_rel in seen:
                continue
            if parent in rec["contracts"]:
                seen.add(other_rel)
                blocks.append(
                    f"// parent contract: {other_rel}\n{rec['text'][:MAX_RELATED]}"
                )
                if len(blocks) >= MAX_RELATED_FILES:
                    return blocks
    return blocks


# ---------------------------------------------------------------------------
# inference
# ---------------------------------------------------------------------------
def call_model(
    inference_api: str | None,
    messages: list[dict[str, str]],
) -> str:
    base = (inference_api or os.environ.get("INFERENCE_API") or "").rstrip("/")
    if not base:
        raise ValueError("INFERENCE_API missing")
    key = os.environ.get("INFERENCE_API_KEY", "").strip()
    payload = json.dumps({
        "messages": messages,
        "response_format": {"type": "json_object"},
        "max_tokens": 8000,
    }).encode()
    headers = {
        "Content-Type": "application/json",
        "x-inference-api-key": key,
    }
    err: Exception | None = None
    for attempt in range(RETRIES + 1):
        try:
            req = urllib.request.Request(
                f"{base}/inference", data=payload, method="POST", headers=headers,
            )
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                data = json.loads(resp.read().decode())
            return _message_text(data)
        except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
            err = exc
            if attempt < RETRIES:
                time.sleep(1.5 * (attempt + 1))
    raise RuntimeError(f"model call failed: {err}")


def _message_text(data: dict) -> str:
    choices = data.get("choices")
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
            p.get("text", "")
            for p in content
            if isinstance(p, dict) and p.get("type") == "text"
        )
    return ""


def decode_json_blob(raw: str) -> dict | None:
    text = raw.strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\n?", "", text)
        text = re.sub(r"\n?```$", "", text).strip()
    try:
        obj = json.loads(text)
        return obj if isinstance(obj, dict) else None
    except json.JSONDecodeError:
        start = text.find("{")
        if start < 0:
            return None
        depth = 0
        for i in range(start, len(text)):
            ch = text[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    try:
                        obj = json.loads(text[start : i + 1])
                        return obj if isinstance(obj, dict) else None
                    except json.JSONDecodeError:
                        return None
    return None


def extract_items(obj: dict | None) -> list[dict]:
    if not obj:
        return []
    for key in ("findings", "vulnerabilities", "candidates", "targets"):
        val = obj.get(key)
        if isinstance(val, list):
            return [x for x in val if isinstance(x, dict)]
    return []


# ---------------------------------------------------------------------------
# prompts
# ---------------------------------------------------------------------------
def triage_prompt(candidates: list[dict]) -> str:
    lines = [
        "Rank these Solidity files by how likely they contain exploitable "
        "HIGH/CRITICAL bugs. Return JSON only:\n"
        '{"targets": [{"file": "<exact path>", "priority": 1-10, '
        '"suspicious_functions": ["fn1", "fn2"]}]}\n',
        "List at most 6 targets, highest priority first. Only use paths and "
        "function names that appear in the summaries below.\n",
    ]
    for rec in candidates:
        fns = FUNCTION_RE.findall(rec["text"])[:12]
        lines.append(
            f"--- {rec['rel']} (contracts: {', '.join(rec['contracts'][:4])}) "
            f"functions: {', '.join(fns)} ---"
        )
        lines.append(rec["text"][:2500])
        lines.append("")
    return "\n".join(lines)


def deep_audit_prompt(target: dict, related: list[str]) -> str:
    rel = target["rel"]
    contracts = ", ".join(target["contracts"][:6])
    body = target["text"][:MAX_CONTEXT]
    truncated = len(target["text"]) > MAX_CONTEXT
    parts = [
        "Deep-audit this file for exploitable HIGH/CRITICAL vulnerabilities.\n",
        f"File (use exactly as `file`): {rel}",
        f"Contracts: {contracts}\n",
        "Trace access control, external calls, token accounting, oracle usage, "
        "initialization, and upgrade paths. Each finding must cite the real "
        "function where the bug lives and describe a concrete attack.\n",
        "Return strict JSON:",
        '{"findings": [{'
        '"title": "<Contract>.<function> — <specific vulnerability>", '
        '"contract": "<name>", "function": "<name>", '
        f'"file": "{rel}", "line": <int|null>, '
        '"severity": "high|critical", '
        '"mechanism": "<precondition -> attacker action -> broken invariant>", '
        '"impact": "<who loses what>", '
        '"description": "<2-4 sentences with file, contract, function, mechanism, impact>"'
        "}]}",
        "Max 2 findings. Empty list if none. No invented symbols.\n",
        f"----- SOURCE{' (truncated)' if truncated else ''} -----",
        body,
    ]
    for block in related:
        parts += ["\n----- RELATED -----", block]
    return "\n".join(parts)


def focus_prompt(target: dict, fn_name: str, snippet: str) -> str:
    rel = target["rel"]
    return "\n".join([
        f"Focus audit on function `{fn_name}()` in `{rel}`.",
        "Confirm or refute a HIGH/CRITICAL exploit. Return JSON:",
        '{"findings": [{...same schema as before...}]}',
        "One finding max; empty if not exploitable.\n",
        f"----- {fn_name} snippet -----\n{snippet[:6000]}",
    ])


def _function_snippet(text: str, fn_name: str, fn_lines: dict[str, int]) -> str:
    line_no = fn_lines.get(fn_name)
    if line_no is None:
        return text[:4000]
    lines = text.splitlines()
    start = max(0, line_no - 1)
    end = min(len(lines), start + 80)
    return "\n".join(lines[start:end])


# ---------------------------------------------------------------------------
# normalization
# ---------------------------------------------------------------------------
def shape_finding(
    raw: dict,
    target: dict,
    valid_fns: set[str],
) -> dict | None:
    sev = str(raw.get("severity", "")).lower().strip()
    if sev not in {"high", "critical"}:
        return None

    contract = str(
        raw.get("contract") or (target["contracts"][0] if target["contracts"] else "")
    ).strip()
    function = str(raw.get("function", "")).strip().strip("()")
    if function and valid_fns and function not in valid_fns:
        function = function.split(".")[-1]
        if function not in valid_fns:
            function = ""

    file_path = str(raw.get("file") or target["rel"]).strip()
    mechanism = str(raw.get("mechanism", "")).strip()
    impact = str(raw.get("impact", "")).strip()
    description = str(raw.get("description", "")).strip()
    title = str(raw.get("title", "")).strip()

    fn_lines: dict[str, int] = target["fn_lines"]
    line = raw.get("line")
    if not isinstance(line, int) and function in fn_lines:
        line = fn_lines[function]

    anchor = f"{contract}.{function}" if contract and function else (contract or function)
    if not title:
        title = f"{anchor} — {sev} vulnerability" if anchor else f"{sev} vulnerability"
    elif anchor and anchor.lower() not in title.lower():
        title = f"{anchor} — {title}"

    if len(description) < 80 or (function and function not in description):
        where = f"In `{file_path}`"
        if contract:
            where += f", contract `{contract}`"
        if function:
            where += f", function `{function}()`"
        parts = [where + "."]
        if mechanism:
            parts.append(f"Mechanism: {mechanism.rstrip('.')}.")
        if impact:
            parts.append(f"Impact: {impact.rstrip('.')}.")
        rebuilt = " ".join(parts)
        if len(rebuilt) > len(description):
            description = rebuilt

    if len(description) < 80:
        return None

    out: dict = {
        "title": title[:200],
        "description": description,
        "severity": sev,
        "file": file_path,
        "function": function,
        "type": str(raw.get("type") or raw.get("vulnerability_type") or "logic"),
        "confidence": 0.92 if sev == "critical" else 0.85,
    }
    if isinstance(line, int):
        out["line"] = line
    return out


def merge_unique(findings: list[dict]) -> list[dict]:
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


def pick_deep_targets(
    records: list[dict],
    triage: list[dict],
) -> list[dict]:
    by_rel = {r["rel"]: r for r in records}
    ordered: list[dict] = []
    seen: set[str] = set()

    for item in triage:
        rel = str(item.get("file", "")).strip()
        if rel in by_rel and rel not in seen:
            seen.add(rel)
            ordered.append(by_rel[rel])

    for rec in records:
        if rec["rel"] not in seen:
            seen.add(rec["rel"])
            ordered.append(rec)
        if len(ordered) >= DEEP_TARGETS:
            break
    return ordered[:DEEP_TARGETS]


# ---------------------------------------------------------------------------
# entrypoint
# ---------------------------------------------------------------------------
def agent_main(
    project_dir: str | None = None,
    inference_api: str | None = None,
) -> dict:
    findings: list[dict] = []
    workspace = locate_workspace(project_dir)
    if workspace is None:
        return {"vulnerabilities": findings}

    deadline = time.monotonic() + WALL_CLOCK
    records = collect_sources(workspace)
    if not records:
        return {"vulnerabilities": findings}

    catalog = {r["rel"]: r for r in records}
    pool = records[:TRIAGE_POOL]
    hot_functions: dict[str, list[str]] = {}

    # Phase 1 — lightweight triage to pick best deep-audit targets
    if time.monotonic() < deadline and len(pool) > DEEP_TARGETS:
        try:
            triage_raw = call_model(
                inference_api,
                [
                    {"role": "system", "content": AUDITOR_SYSTEM},
                    {"role": "user", "content": triage_prompt(pool)},
                ],
            )
            triage_items = extract_items(decode_json_blob(triage_raw))
            for item in triage_items:
                rel = str(item.get("file", "")).strip()
                fns = item.get("suspicious_functions")
                if rel and isinstance(fns, list):
                    hot_functions[rel] = [str(f) for f in fns[:4]]
            targets = pick_deep_targets(records, triage_items)
        except (RuntimeError, ValueError):
            targets = records[:DEEP_TARGETS]
    else:
        targets = records[:DEEP_TARGETS]

    collected: list[dict] = []

    # Phase 2 — deep audit per target
    for target in targets:
        if time.monotonic() > deadline:
            break
        related = gather_related(target, catalog)
        try:
            raw = call_model(
                inference_api,
                [
                    {"role": "system", "content": AUDITOR_SYSTEM},
                    {"role": "user", "content": deep_audit_prompt(target, related)},
                ],
            )
        except (RuntimeError, ValueError):
            continue

        valid = set(FUNCTION_RE.findall(target["text"]))
        for item in extract_items(decode_json_blob(raw)):
            shaped = shape_finding(item, target, valid)
            if shaped:
                collected.append(shaped)

        # Phase 2b — focused pass on triage-flagged functions
        rel = target["rel"]
        flagged = hot_functions.get(rel, [])[:2]
        for fn_name in flagged:
            if time.monotonic() > deadline or fn_name not in valid:
                continue
            snippet = _function_snippet(target["text"], fn_name, target["fn_lines"])
            try:
                focus_raw = call_model(
                    inference_api,
                    [
                        {"role": "system", "content": AUDITOR_SYSTEM},
                        {"role": "user", "content": focus_prompt(target, fn_name, snippet)},
                    ],
                )
            except (RuntimeError, ValueError):
                continue
            for item in extract_items(decode_json_blob(focus_raw)):
                shaped = shape_finding(item, target, valid)
                if shaped:
                    collected.append(shaped)

    findings = merge_unique(collected)[:MAX_OUTPUT]
    return {"vulnerabilities": findings}


if __name__ == "__main__":
    import sys
    print(json.dumps(agent_main(sys.argv[1] if len(sys.argv) > 1 else None), indent=2))
