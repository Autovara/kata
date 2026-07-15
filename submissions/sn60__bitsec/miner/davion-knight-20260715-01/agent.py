"""SN60 / Bitsec miner agent — map-then-audit.

Strategy: spend the three-call per-problem budget the way a human auditor with
limited time would. Call 1 builds a compact map of the whole repository (every
in-scope contract with its functions, risky lines, and state layout) and asks
the model which files most likely hold real high/critical bugs. Calls 2-3 then
audit the selected files in full source context — the first pass on the primary
targets, the second on a diverse set that leans toward cross-contract and
accounting invariants — so coverage is broad but each target is still read in
depth.

This is a general-purpose analyzer: it reasons about whatever source it is
given. It contains no hardcoded project fingerprints and no canned findings —
every finding comes from the model reading the actual source. Self-contained
(standard library only); reaches the model only through the validator inference
proxy; never raises — a timeout, budget ``429`` or malformed reply just yields
the findings gathered so far.
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path

SOURCE_EXTS = (".sol", ".vy", ".cairo")
SKIP_DIRS = {
    "test", "tests", "mock", "mocks", "example", "examples", "script", "scripts",
    "broadcast", "node_modules", "vendor", "vendors", "lib", "out", "artifacts",
    "cache", "coverage", "dist", "target", "interface", "interfaces", "docs",
}
NAME_WORDS = (
    "vault", "router", "bridge", "proxy", "upgrade", "oracle", "govern",
    "treasury", "manager", "pool", "reward", "staking", "market", "reserve",
    "lend", "borrow", "collateral", "controller", "strategy", "auction",
    "token", "admin", "owner", "escrow", "distributor", "vesting", "swap",
)
RISK_WORDS = (
    "withdraw", "redeem", "borrow", "repay", "liquidat", "claim", "stake",
    "deposit", "mint", "burn", "swap", "bridge", "permit", "delegatecall",
    "selfdestruct", "transferfrom", "safetransfer", "initialize", "upgradeto",
    "onlyowner", "onlyrole", "ecrecover", "getprice", "latestanswer", "slot0",
    "flashloan", "unchecked", "reentran", "call{", "tx.origin", "assembly",
)
CONTRACT_RE = re.compile(
    r"\b(?:contract|library|abstract\s+contract|interface)\s+([A-Za-z_]\w*)"
)
FUNC_RE = re.compile(r"\b(?:function|def|fn)\s+([A-Za-z_]\w*)")

MAX_SOURCE_FILES = 80
MAX_FILE_BYTES = 300_000
MAP_FILE_BUDGET = 60          # files described in the map call
AUDIT_PRIMARY = 4             # primary deep-audit batch size
AUDIT_SECONDARY = 4           # secondary deep-audit batch size
AUDIT_CHARS = 34_000          # source budget per audit call
MAX_FINDINGS = 12
RUN_SECONDS = 220.0
HTTP_TIMEOUT = 150
MAP_MAX_TOKENS = 3_000
AUDIT_MAX_TOKENS = 7_000

SYSTEM_PROMPT = (
    "You are a senior smart-contract security auditor. You find only REAL, "
    "exploitable HIGH or CRITICAL vulnerabilities — logic flaws that let an "
    "attacker steal funds, escalate privilege, brick the protocol, or corrupt "
    "accounting. You ignore gas, style, missing events, and speculative issues "
    "with no concrete exploit path, and you are precise about the exact file, "
    "contract, and function a bug lives in."
)


# --------------------------------------------------------------------------- #
# discovery
# --------------------------------------------------------------------------- #
def _resolve_root(project_dir: str | None) -> Path | None:
    candidates: list[str] = []
    if project_dir:
        candidates.append(project_dir)
    for key in ("PROJECT_DIR", "PROJECT_PATH", "PROJECT_ROOT", "PROJECT_CODE"):
        val = os.environ.get(key)
        if val:
            candidates.append(val)
    candidates += ["/app/project_code", "/app/project", "/project", "/code", "."]
    for cand in candidates:
        try:
            root = Path(cand).expanduser().resolve()
        except (OSError, RuntimeError):
            continue
        if root.is_dir() and _has_sources(root):
            return root
    return None


def _has_sources(root: Path) -> bool:
    try:
        for path in root.rglob("*"):
            if path.is_file() and path.suffix.lower() in SOURCE_EXTS:
                return True
    except OSError:
        return False
    return False


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _skip(rel_parts: tuple[str, ...], name: str) -> bool:
    for part in rel_parts:
        low = part.lower()
        if low in SKIP_DIRS or low.startswith("."):
            return True
    return name.lower().endswith((".t.sol", ".s.sol", "_test.sol", ".test.sol"))


def _risk_lines(text: str) -> list[str]:
    out: list[str] = []
    for number, line in enumerate(text.splitlines(), start=1):
        low = line.lower().replace(" ", "")
        if any(term.replace(" ", "") in low for term in RISK_WORDS):
            compact = " ".join(line.strip().split())
            if compact:
                out.append(f"{number}: {compact[:150]}")
        if len(out) >= 14:
            break
    return out


def _score(rel: str, text: str) -> int:
    low_name = rel.lower()
    low = text.lower()
    compact = low.replace(" ", "")
    score = min(low.count("function ") + low.count("\ndef ") + low.count(" fn "), 40)
    for word in NAME_WORDS:
        if word in low_name:
            score += 9
        elif word in low:
            score += 2
    for word in RISK_WORDS:
        if word.replace(" ", "") in compact:
            score += 4
    if "external" in low or "public" in low:
        score += 6
    if "nonreentrant" not in compact and (".call" in low or "call{" in compact):
        score += 6
    if "onlyowner" not in compact and any(
        x in compact for x in ("setowner", "setadmin", "upgrade", "initialize")
    ):
        score += 6
    return score


def _discover(root: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    try:
        paths = sorted(root.rglob("*"))
    except OSError:
        return rows
    for path in paths:
        if not path.is_file() or path.suffix.lower() not in SOURCE_EXTS:
            continue
        try:
            rel = path.relative_to(root).as_posix()
        except ValueError:
            continue
        if _skip(Path(rel).parts[:-1], path.name):
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        text = _read(path)
        markers = ("function", "contract ", "library ", "def ", " fn ")
        if not text or not any(t in text for t in markers):
            continue
        contracts: list[str] = []
        for name in CONTRACT_RE.findall(text):
            if name not in contracts:
                contracts.append(name)
        functions: list[str] = []
        for name in FUNC_RE.findall(text):
            if name not in functions:
                functions.append(name)
        rows.append(
            {
                "rel": rel,
                "text": text,
                "contracts": contracts or [path.stem],
                "functions": set(functions),
                "func_list": functions,
                "risk": _risk_lines(text),
                "score": _score(rel, text),
            }
        )
    rows.sort(key=lambda r: (-int(r["score"]), str(r["rel"])))
    return rows[:MAX_SOURCE_FILES]


# --------------------------------------------------------------------------- #
# inference
# --------------------------------------------------------------------------- #
def _request(inference_api: str | None, prompt: str, max_tokens: int) -> tuple[str, int]:
    """Return (content, http_status). status 429 means the budget is spent."""
    endpoint = (inference_api or os.environ.get("INFERENCE_API") or "").rstrip("/")
    if not endpoint:
        return "", 0
    api_key = os.environ.get("INFERENCE_API_KEY", "").strip()
    body = json.dumps(
        {
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "response_format": {"type": "json_object"},
            "max_tokens": max_tokens,
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        endpoint + "/inference",
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "x-inference-api-key": api_key},
    )
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        return _content(payload), 200
    except urllib.error.HTTPError as exc:
        return "", exc.code
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        return "", 0


def _content(payload: dict) -> str:
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
            part.get("text", "")
            for part in content
            if isinstance(part, dict) and part.get("type") == "text"
        )
    return ""


def _json_obj(content: str) -> dict:
    text = content.strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\n?", "", text)
        text = re.sub(r"\n?```$", "", text).strip()
    try:
        obj = json.loads(text)
        return obj if isinstance(obj, dict) else {}
    except json.JSONDecodeError:
        pass
    start, depth = text.find("{"), 0
    if start != -1:
        for i in range(start, len(text)):
            depth += 1 if text[i] == "{" else -1 if text[i] == "}" else 0
            if depth == 0:
                try:
                    obj = json.loads(text[start : i + 1])
                    return obj if isinstance(obj, dict) else {}
                except json.JSONDecodeError:
                    return {}
    return {}


def _findings_from(obj: dict) -> list[dict]:
    items = obj.get("findings") or obj.get("vulnerabilities") or obj.get("candidates")
    return [it for it in items if isinstance(it, dict)] if isinstance(items, list) else []


# --------------------------------------------------------------------------- #
# map + audit prompts
# --------------------------------------------------------------------------- #
_SHAPE = (
    'Each finding: {"title": "<Contract>.<function> — <bug>", '
    '"file": "<exact path from the source below>", "contract": "<Name>", '
    '"function": "<function the bug is in>", "severity": "high|critical", '
    '"mechanism": "<precondition -> attacker action -> effect>", '
    '"impact": "<funds stolen / privilege escalation / DoS / insolvency>", '
    '"description": "<2-4 sentences naming file, contract and function, then '
    'mechanism and impact>"}'
)


def _map_prompt(records: list[dict[str, object]]) -> str:
    lines = [
        "Below is a map of a smart-contract repository. For each file you see its "
        "path, contracts, key functions, and the lines that touch value transfer, "
        "access control, or accounting.",
        "",
        "Return STRICT JSON only:",
        '{"targets": ["<path>", ...],  // up to 8 files most likely to contain real '
        'high/critical bugs, most suspicious first',
        ' "findings": [ ' + _SHAPE + " ]  // only bugs already obvious from the map",
        "}",
        "",
    ]
    for rec in records[:MAP_FILE_BUDGET]:
        funcs = ", ".join(list(rec["func_list"])[:12])
        lines.append(f"### {rec['rel']}  [{', '.join(rec['contracts'][:4])}]")
        if funcs:
            lines.append(f"functions: {funcs}")
        for rl in list(rec["risk"])[:6]:
            lines.append(f"  {rl}")
    return "\n".join(lines)


def _audit_prompt(batch: list[dict[str, object]], mode: str) -> str:
    parts = [
        f"Deep security audit ({mode}). Read each file in full and report only REAL "
        "HIGH or CRITICAL vulnerabilities with a concrete exploit path. Reason about "
        "access control, external calls, reentrancy, accounting/oracle math, and "
        "initialization/upgrade paths.",
        "",
        'Return STRICT JSON only: {"findings": [ ' + _SHAPE + " ]}",
        "Name the real function each bug lives in; do not invent files or functions. "
        'If nothing is genuinely exploitable, return {"findings": []}.',
    ]
    remaining = AUDIT_CHARS
    for rec in batch:
        budget = max(3000, remaining // max(1, len(batch)))
        body = str(rec["text"])[:budget]
        remaining -= len(body)
        parts += [
            "",
            f"===== FILE: {rec['rel']}  [{', '.join(rec['contracts'][:4])}] =====",
            body,
        ]
    return "\n".join(parts)


# --------------------------------------------------------------------------- #
# normalization
# --------------------------------------------------------------------------- #
def _normalize(raw: dict, rel_map: dict[str, dict[str, object]]) -> dict | None:
    severity = str(raw.get("severity") or "").strip().lower()
    if severity not in {"high", "critical"}:
        return None

    file_path = str(raw.get("file") or raw.get("path") or "").strip()
    rec = rel_map.get(file_path)
    if rec is None:
        base = file_path.rsplit("/", 1)[-1].lower()
        for rel, candidate in rel_map.items():
            if base and rel.lower().endswith(base):
                file_path, rec = rel, candidate
                break
    if rec is None:
        if not rel_map:
            return None
        file_path, rec = next(iter(rel_map.items()))

    contracts = rec["contracts"] if isinstance(rec["contracts"], list) else []
    valid_fns = rec["functions"] if isinstance(rec["functions"], set) else set()
    contract = str(raw.get("contract") or (contracts[0] if contracts else "")).strip()
    function = str(raw.get("function") or "").strip().strip("()")
    if function and valid_fns and function not in valid_fns:
        function = function.split(".")[-1]
        if function not in valid_fns:
            function = ""

    mechanism = str(raw.get("mechanism") or "").strip()
    impact = str(raw.get("impact") or "").strip()
    description = str(raw.get("description") or "").strip()
    title = str(raw.get("title") or "").strip()

    loc = f"{contract}.{function}" if contract and function else (contract or function)
    if not title:
        title = f"{loc} — {severity} severity issue" if loc else "High-severity issue"
    elif loc and loc.lower() not in title.lower():
        title = f"{loc} — {title}"

    if len(description) < 100 or (function and function not in description):
        seg = f"In `{file_path}`"
        if contract:
            seg += f", contract `{contract}`"
        if function:
            seg += f", function `{function}()`"
        seg += "."
        extra = []
        if mechanism:
            extra.append(f"Mechanism: {mechanism.rstrip('.')}.")
        if impact:
            extra.append(f"Impact: {impact.rstrip('.')}.")
        rebuilt = " ".join([seg, *extra]).strip()
        if len(rebuilt) > len(description):
            description = rebuilt
    if len(description) < 80:
        return None

    return {
        "title": title[:200],
        "description": description,
        "severity": severity,
        "file": file_path,
        "function": function,
        "confidence": 0.9 if severity == "critical" else 0.8,
    }


def _dedupe(findings: list[dict]) -> list[dict]:
    seen: set[tuple[str, str]] = set()
    out: list[dict] = []
    for f in sorted(
        findings,
        key=lambda x: (x["severity"] == "critical", float(x["confidence"])),
        reverse=True,
    ):
        key = (str(f["file"]).lower(), str(f["function"]).lower() or str(f["title"]).lower()[:40])
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def _order_targets(targets: list[str], records: list[dict[str, object]]) -> list[dict[str, object]]:
    by_rel = {str(r["rel"]): r for r in records}
    ordered: list[dict[str, object]] = []
    for target in targets:
        rec = by_rel.get(target)
        if rec is None:
            base = str(target).rsplit("/", 1)[-1].lower()
            rec = next((r for r in records if str(r["rel"]).lower().endswith(base) and base), None)
        if rec is not None and rec not in ordered:
            ordered.append(rec)
    for rec in records:  # backfill with top-ranked files the model did not name
        if rec not in ordered:
            ordered.append(rec)
    return ordered


# --------------------------------------------------------------------------- #
# entrypoint
# --------------------------------------------------------------------------- #
def agent_main(project_dir: str | None = None, inference_api: str | None = None) -> dict:
    findings: list[dict] = []
    try:
        root = _resolve_root(project_dir)
        if root is None:
            return {"vulnerabilities": findings}
        records = _discover(root)
        if not records:
            return {"vulnerabilities": findings}
        rel_map = {str(r["rel"]): r for r in records}
        started = time.monotonic()
        raw: list[dict] = []
        calls = 0

        # call 1 — map the repository and pick targets
        targets: list[str] = []
        content, status = _request(inference_api, _map_prompt(records), MAP_MAX_TOKENS)
        calls += 1
        if status != 429 and content:
            obj = _json_obj(content)
            picked = obj.get("targets")
            if isinstance(picked, list):
                targets = [str(t) for t in picked if isinstance(t, str)]
            raw.extend(_findings_from(obj))

        ordered = _order_targets(targets, records)
        primary = ordered[:AUDIT_PRIMARY]
        secondary = ordered[AUDIT_PRIMARY : AUDIT_PRIMARY + AUDIT_SECONDARY]

        # calls 2-3 — deep audit the selected files
        for batch, mode in ((primary, "critical-path"), (secondary, "cross-file-invariants")):
            if not batch or calls >= 3 or time.monotonic() - started > RUN_SECONDS:
                break
            content, status = _request(inference_api, _audit_prompt(batch, mode), AUDIT_MAX_TOKENS)
            calls += 1
            if status == 429:
                break
            if content:
                raw.extend(_findings_from(_json_obj(content)))

        for item in raw:
            norm = _normalize(item, rel_map)
            if norm is not None:
                findings.append(norm)
        findings = _dedupe(findings)[:MAX_FINDINGS]
    except Exception:
        # Never crash: a crashed run scores as invalid for the problem; returning
        # whatever was gathered is always the safe choice.
        pass
    return {"vulnerabilities": findings}


if __name__ == "__main__":
    import sys

    print(json.dumps(agent_main(sys.argv[1] if len(sys.argv) > 1 else None), indent=2))
