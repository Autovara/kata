from __future__ import annotations

"""SN60 Bitsec challenger: precision-first multi-language depth auditor.

Designed to beat a high-TP / mid-precision king under TEE limits (~840s process,
~180s/gateway call). Pipeline: risk-ranked discovery → map triage (targets +
early findings) → contiguous deep audit of top files → cross-module second pass
with risk-window compaction. No static finding emitters (those tanked precision
in prior rounds). All findings come from the model and are gated on real file /
function anchors plus a confidence floor.
"""

import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

EXTS = (".sol", ".vy", ".rs", ".move", ".cairo")
MAX_FILES = 88
MAX_BYTES = 280_000
MAP_CHARS = 28_000
DEEP_CHARS = 48_000
FOCUS_CHARS = 52_000
RELATED_CHARS = 3_000
PER_FILE_DEEP = 16_000
PER_FILE_FOCUS = 9_000
MAX_FINDINGS = 14
RUN_CAP = 780.0
HTTP_TIMEOUT = 195
MAX_CALLS = 3
MIN_CONF = 0.72
MIN_DESC = 110
MODEL = os.environ.get("KATA_MINER_MODEL", "deepseek-ai/DeepSeek-V3.2-TEE")

SKIP_DIRS = frozenset({
    ".git", ".github", ".venv", "artifacts", "broadcast", "cache", "coverage",
    "dist", "docs", "example", "examples", "lib", "libs", "node_modules", "out",
    "script", "scripts", "target", "test", "tests", "vendor", "vendors", "mock",
    "mocks", "fixtures", "fixture", "deps", "build", "interfaces", "interface",
    "generated", "bindings", "sim",
})

NAME_WORDS = (
    "vault", "pool", "router", "manager", "controller", "strategy", "market",
    "lend", "borrow", "oracle", "price", "stak", "reward", "treasury", "bridge",
    "factory", "proxy", "govern", "token", "escrow", "auction", "liquidat",
    "swap", "stable", "collateral", "vesting", "distributor", "minter", "gauge",
    "farm", "perp", "position", "margin", "settle", "clearing", "account",
    "program", "amm", "pair", "adapter", "engine",
)

RISK_WORDS = (
    "delegatecall", ".call{", ".call.value", "selfdestruct", "tx.origin",
    "assembly", "ecrecover", "permit", "signature", "nonce", "initialize",
    "upgradeto", "onlyowner", "onlyrole", "_mint", "_burn", "mint(", "burn(",
    "withdraw", "redeem", "deposit", "borrow", "repay", "liquidat", "collateral",
    "share", "totalsupply", "balanceof", "oracle", "getprice", "latestround",
    "slot0", "flash", "swap", "reward", "claim", "unchecked", "safetransfer",
    "transferfrom", "approve", "settle", "rebalance", "liquidity", "reserve",
    "invariant", "signer", "authority", "lamports", "invoke", "cpi", "checked_",
    "unwrap", "close_account", "realloc", "try_borrow", "deserialize",
    "next_account", "owner", "is_signer", "msg.sender", "info.sender",
    "transfer", "acquires", "borrow_global", "move_to", "move_from",
    "capability", "get_caller_address", "felt", "starknet",
)

SOL_CONTRACT = re.compile(
    r"\b(?:abstract\s+contract|contract|library|interface)\s+([A-Za-z_][A-Za-z0-9_]*)"
)
SOL_FUNC = re.compile(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)([^{};]*)")
SOL_SPECIAL = re.compile(r"\b(constructor|receive|fallback)\b\s*\(")
VY_FUNC = re.compile(r"(?m)^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)")
RS_FUNC = re.compile(
    r"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)"
)
RS_MOD = re.compile(r"(?m)^\s*(?:pub\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{")
MOVE_FUNC = re.compile(
    r"(?m)^\s*(?:public\s*(?:\([^)]*\))?\s+)?(?:entry\s+)?(?:native\s+)?fun\s+([A-Za-z_][A-Za-z0-9_]*)"
)
MOVE_MOD = re.compile(r"(?m)^\s*module\s+(?:[A-Za-z_0-9]+::)?([A-Za-z_][A-Za-z0-9_]*)")
CAIRO_FUNC = re.compile(r"(?m)^\s*(?:pub\s+)?(?:fn|func)\s+([A-Za-z_][A-Za-z0-9_]*)")
CAIRO_MOD = re.compile(r"(?m)^\s*(?:pub\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{")
IMPORT_RE = re.compile(r'(?m)^\s*(?:import|use)\b[^;\n]*?["\']?([A-Za-z0-9_./]+)["\']?')
DEF_LINE = re.compile(
    r"\bfunction\b|\bdef\b|\bfn\b|\bfun\b|\bmodifier\b|\bconstructor\b|\bmodule\b|\bmapping\b"
)

SYSTEM = (
    "You are an elite smart-contract / on-chain program auditor (Solidity, Vyper, "
    "Rust/Solana, Move, Cairo). Report ONLY real exploitable HIGH or CRITICAL bugs "
    "with a concrete attacker path and material fund/control impact. Skip gas, "
    "style, missing events, centralization-by-design, and speculation. Prefer fewer "
    "high-confidence findings over many weak ones. Return strict JSON only."
)

SCHEMA = (
    '{"findings":[{"title":"Contract.fn - bug","file":"path","contract":"Name",'
    '"function":"fn","severity":"high|critical","confidence":0.0,'
    '"mechanism":"precondition -> attack -> effect",'
    '"impact":"funds stolen / privilege / insolvency",'
    '"description":"2-4 sentences with exploit path"}]}'
)

FOCUS = (
    "Prioritize: value movement, share/supply/reserve accounting, first-depositor "
    "and rounding theft, oracle/price manipulation in value math, missing auth on "
    "privileged writes, reentrancy / callback ordering, signature replay, unsafe "
    "init/upgrade, liquidation / withdrawal edge cases. For Rust/Solana, Move, "
    "Cairo also check missing signer/authority, account ownership confusion, and "
    "unchecked arithmetic."
)

TRANSIENT = frozenset({408, 409, 425, 429, 500, 502, 503, 504, 520, 522, 524, 529})


def agent_main(project_dir: str | None = None, inference_api: str | None = None) -> dict:
    started = time.monotonic()
    findings: list[dict[str, Any]] = []
    try:
        root = resolve_root(project_dir)
        if root is None:
            return {"vulnerabilities": findings}
        records = discover(root)
        if not records:
            return {"vulnerabilities": findings}

        rel_map = {r["rel"]: r for r in records}
        by_base: dict[str, dict[str, Any]] = {}
        for rec in records:
            by_base.setdefault(str(rec["base"]), rec)

        raw: list[dict[str, Any]] = []
        ordered = records
        calls = 0

        if time_left(started, 220) and calls < MAX_CALLS:
            targets, hits = triage(inference_api, records, started)
            raw.extend(hits)
            ordered = reorder(records, targets)
            calls += 1

        deep = ordered[:3]
        if time_left(started, 220) and calls < MAX_CALLS and deep:
            raw.extend(audit(
                inference_api, deep, by_base, started,
                mode="value-path-depth",
                per_file=PER_FILE_DEEP,
                budget=DEEP_CHARS,
                compact=False,
            ))
            calls += 1

        focus = diversify(ordered, deep, limit=5)
        if time_left(started, 220) and calls < MAX_CALLS and focus:
            raw.extend(audit(
                inference_api, focus, by_base, started,
                mode="cross-module-accounting",
                per_file=PER_FILE_FOCUS,
                budget=FOCUS_CHARS,
                compact=True,
            ))
            calls += 1

        for item in raw:
            norm = normalize(item, rel_map)
            if norm is not None:
                findings.append(norm)
    except Exception:
        pass
    return {"vulnerabilities": dedupe(findings)}


def time_left(started: float, need: float = 0.0) -> bool:
    return time.monotonic() - started < RUN_CAP - need


def resolve_root(project_dir: str | None) -> Path | None:
    opts: list[str] = []
    if project_dir:
        opts.append(project_dir)
    for key in ("PROJECT_DIR", "PROJECT_PATH", "PROJECT_ROOT", "PROJECT_CODE"):
        val = os.environ.get(key)
        if val:
            opts.append(val)
    opts.extend(("/app/project_code", "/app/project", "/project", "/code", "."))
    for raw in opts:
        try:
            path = Path(raw).expanduser().resolve()
        except (OSError, RuntimeError):
            continue
        if path.is_dir() and has_sources(path):
            return path
    return None


def has_sources(root: Path) -> bool:
    try:
        for path in root.rglob("*"):
            if path.is_file() and path.suffix.lower() in EXTS:
                return True
    except OSError:
        return False
    return False


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def looks_like(text: str, ext: str) -> bool:
    if ext == ".sol":
        return any(x in text for x in ("contract ", "library ", "function "))
    if ext == ".vy":
        return "def " in text or "@external" in text
    if ext == ".rs":
        return "fn " in text
    if ext == ".move":
        return "fun " in text or "module " in text
    if ext == ".cairo":
        return "fn " in text or "func " in text or "mod " in text
    return False


def structure(text: str, ext: str, stem: str) -> tuple[list[str], list[dict[str, Any]]]:
    funcs: list[dict[str, Any]] = []
    contracts: list[str] = []
    if ext == ".sol":
        contracts = SOL_CONTRACT.findall(text)
        for match in SOL_FUNC.finditer(text):
            tail = " ".join(match.group(3).split())
            funcs.append({
                "name": match.group(1),
                "line": text.count("\n", 0, match.start()) + 1,
                "sig": f"{match.group(1)}({match.group(2).strip()}) {tail}".strip()[:180],
            })
        for match in SOL_SPECIAL.finditer(text):
            funcs.append({
                "name": match.group(1),
                "line": text.count("\n", 0, match.start()) + 1,
                "sig": match.group(1),
            })
    elif ext == ".vy":
        for match in VY_FUNC.finditer(text):
            funcs.append({
                "name": match.group(1),
                "line": text.count("\n", 0, match.start()) + 1,
                "sig": f"{match.group(1)}({match.group(2).strip()})"[:180],
            })
    elif ext == ".rs":
        contracts = RS_MOD.findall(text)
        for match in RS_FUNC.finditer(text):
            funcs.append({
                "name": match.group(1),
                "line": text.count("\n", 0, match.start()) + 1,
                "sig": match.group(0).strip()[:180],
            })
    elif ext == ".move":
        contracts = MOVE_MOD.findall(text)
        for match in MOVE_FUNC.finditer(text):
            funcs.append({
                "name": match.group(1),
                "line": text.count("\n", 0, match.start()) + 1,
                "sig": match.group(0).strip()[:180],
            })
    elif ext == ".cairo":
        contracts = CAIRO_MOD.findall(text)
        for match in CAIRO_FUNC.finditer(text):
            funcs.append({
                "name": match.group(1),
                "line": text.count("\n", 0, match.start()) + 1,
                "sig": match.group(0).strip()[:180],
            })
    if not contracts:
        contracts = [stem]
    return contracts, funcs


def score_file(rel: str, text: str, ext: str, nfuncs: int) -> float:
    low = text.lower()
    compact = low.replace(" ", "")
    score = float(min(nfuncs, 32))
    for word in NAME_WORDS:
        if word in rel.lower():
            score += 9
        elif word in low:
            score += 2
    for word in RISK_WORDS:
        score += min(compact.count(word.lower().replace(" ", "")), 4) * 2.5
    if any(x in low for x in ("external", "public", "@external", "pub fn", "entry fun")):
        score += 6
    if any(x in low for x in ("balances", "totalsupply", "total_supply", "reserve", "invariant")):
        score += 7
    if "nonreentrant" not in low and any(x in low for x in ("withdraw", "redeem", ".call{")):
        score += 6
    if ext == ".sol" and "contract " not in low and "library " not in low:
        score *= 0.25
    parts = [p.lower() for p in Path(rel).parts]
    stem = Path(rel).stem.lower()
    if (
        stem.startswith("test_")
        or stem.endswith(("_test", ".t"))
        or "test" in parts
        or any(p in ("mock", "mocks", "generated") for p in parts)
    ):
        score *= 0.12
    if "interface" in stem or (ext == ".sol" and "interface " in low[:300] and "contract " not in low):
        score *= 0.35
    return score


def discover(root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        paths = sorted(root.rglob("*"))
    except OSError:
        return rows
    for path in paths:
        if not path.is_file():
            continue
        ext = path.suffix.lower()
        if ext not in EXTS:
            continue
        try:
            rel = path.relative_to(root)
            if any(part.lower() in SKIP_DIRS for part in rel.parts[:-1]):
                continue
            if path.stat().st_size > MAX_BYTES:
                continue
        except OSError:
            continue
        name = rel.name.lower()
        if name.endswith((".t.sol", ".s.sol", "_test.sol", ".test.sol")):
            continue
        text = read_text(path)
        if not looks_like(text, ext):
            continue
        contracts, funcs = structure(text, ext, path.stem)
        if not funcs and ext == ".sol":
            continue
        rel_s = rel.as_posix()
        rows.append({
            "rel": rel_s,
            "base": path.name,
            "text": text,
            "ext": ext,
            "contracts": contracts,
            "functions": funcs,
            "fnames": {str(f["name"]) for f in funcs},
            "score": score_file(rel_s, text, ext, len(funcs)),
            "risk": risk_lines(text),
        })
    rows.sort(key=lambda r: (-float(r["score"]), str(r["rel"])))
    return rows[:MAX_FILES]


def risk_lines(text: str, limit: int = 14) -> list[str]:
    out: list[str] = []
    terms = tuple(w.lower() for w in RISK_WORDS)
    for num, line in enumerate(text.splitlines(), start=1):
        low = line.lower()
        if any(t in low for t in terms):
            compact = " ".join(line.split())
            if compact:
                out.append(f"{num}: {compact[:170]}")
        if len(out) >= limit:
            break
    return out


def compact_source(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    lines = text.splitlines()
    important: set[int] = set()
    for idx, line in enumerate(lines):
        low = line.lower()
        if DEF_LINE.search(line) or any(t in low for t in RISK_WORDS):
            for j in range(max(0, idx - 4), min(len(lines), idx + 16)):
                important.add(j)
    chunks: list[str] = []
    last = -8
    size = 0
    for idx in sorted(important):
        if idx > last + 1:
            gap = f"\n/* ... {idx - last - 1} lines ... */\n"
            chunks.append(gap)
            size += len(gap)
        entry = f"{idx + 1}: {lines[idx]}"
        chunks.append(entry)
        size += len(entry) + 1
        last = idx
        if size >= limit:
            break
    out = "\n".join(chunks)
    if len(out) < limit // 2:
        out += "\n\n/* prefix */\n" + text[: max(0, limit - len(out) - 20)]
    return out[:limit]


def related(rec: dict[str, Any], by_base: dict[str, dict[str, Any]]) -> str:
    chunks: list[str] = []
    seen: set[str] = set()
    for imp in IMPORT_RE.findall(str(rec["text"])):
        base = imp.rsplit("/", 1)[-1]
        stem = base.split(".")[0]
        for cand in (base, stem, base + ".sol", stem + ".sol"):
            other = by_base.get(cand)
            if other and other["rel"] != rec["rel"] and other["rel"] not in seen:
                seen.add(str(other["rel"]))
                chunks.append(
                    f"\n--- RELATED {other['rel']} ---\n{str(other['text'])[:RELATED_CHARS]}"
                )
                break
        if len(chunks) >= 2:
            break
    return "".join(chunks)


def repo_map(records: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    total = 0
    for rec in records:
        chunk = json.dumps({
            "file": rec["rel"],
            "kind": str(rec["ext"]).lstrip("."),
            "score": round(float(rec["score"]), 1),
            "contracts": rec["contracts"][:6],
            "functions": [f"{f['line']}:{f['sig']}" for f in rec["functions"][:22]],
            "risk_lines": rec["risk"][:12],
        }, separators=(",", ":"))
        parts.append(chunk)
        total += len(chunk) + 1
        if total > MAP_CHARS:
            break
    return "\n".join(parts)[:MAP_CHARS]


def pull_text(payload: dict[str, Any]) -> str:
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        return ""
    msg = choices[0].get("message") if isinstance(choices[0], dict) else None
    if not isinstance(msg, dict):
        return ""
    content = msg.get("content")
    if isinstance(content, str) and content.strip():
        return content
    if isinstance(content, list):
        joined = "".join(str(p.get("text") or "") for p in content if isinstance(p, dict))
        if joined.strip():
            return joined
    for key in ("reasoning_content", "reasoning"):
        alt = msg.get(key)
        if isinstance(alt, str) and alt.strip():
            return alt
    return ""


def infer(api: str | None, prompt: str, max_tokens: int, started: float) -> str:
    if not time_left(started, 8):
        return ""
    endpoint = (api or os.environ.get("INFERENCE_API") or "").rstrip("/")
    if not endpoint:
        return ""
    body = json.dumps({
        "model": MODEL,
        "temperature": 0.05,
        "messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": prompt},
        ],
        "max_tokens": max_tokens,
    }).encode()
    headers = {
        "Content-Type": "application/json",
        "x-inference-api-key": os.environ.get("INFERENCE_API_KEY", ""),
    }
    last: Exception | None = None
    for attempt in range(3):
        if not time_left(started, 8):
            return ""
        timeout = min(HTTP_TIMEOUT, max(12.0, RUN_CAP - (time.monotonic() - started) - 5))
        try:
            req = urllib.request.Request(
                endpoint + "/inference", data=body, method="POST", headers=headers,
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return pull_text(json.loads(resp.read().decode("utf-8", "replace")))
        except urllib.error.HTTPError as exc:
            if exc.code not in TRANSIENT:
                return ""
            last = exc
        except (OSError, TimeoutError, ValueError) as exc:
            last = exc
        wait = min(12.0, 1.8 * (attempt + 1))
        if not time_left(started, wait + 25):
            break
        time.sleep(wait)
    return "" if last is None else ""


def load_json(text: str) -> dict[str, Any]:
    s = text.strip()
    if not s:
        return {}
    if s.startswith("```"):
        s = re.sub(r"^```[A-Za-z0-9_-]*\s*", "", s)
        s = re.sub(r"\s*```$", "", s)
    try:
        obj = json.loads(s)
        return obj if isinstance(obj, dict) else {}
    except json.JSONDecodeError:
        pass
    start = s.find("{")
    if start < 0:
        return {}
    depth, in_str, esc = 0, False, False
    for i in range(start, len(s)):
        ch = s[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                try:
                    obj = json.loads(s[start : i + 1])
                    return obj if isinstance(obj, dict) else {}
                except json.JSONDecodeError:
                    return {}
    return {}


def triage(
    api: str | None, records: list[dict[str, Any]], started: float,
) -> tuple[list[str], list[dict[str, Any]]]:
    prompt = (
        "Triage this project map. (1) Pick the highest-value files for a deep audit. "
        "(2) Report only REAL high/critical bugs you can already justify from signatures "
        "and risk lines — do not invent. " + FOCUS + "\n"
        'Return STRICT JSON:\n{"target_files":["path"],"findings":[...per schema...]}\n'
        + SCHEMA + "\n\nProject map:\n" + repo_map(records)
    )
    obj = load_json(infer(api, prompt, 5500, started))
    targets = obj.get("target_files")
    items = obj.get("findings") or obj.get("vulnerabilities") or []
    return (
        [str(x) for x in targets if isinstance(x, str)] if isinstance(targets, list) else [],
        [x for x in items if isinstance(x, dict)] if isinstance(items, list) else [],
    )


def reorder(records: list[dict[str, Any]], targets: list[str]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for target in targets:
        tl = target.lower().strip()
        for rec in records:
            rl = str(rec["rel"]).lower()
            if tl == rl or rl.endswith(tl) or tl.endswith(rl) or Path(tl).name == Path(rl).name:
                if rec not in out:
                    out.append(rec)
                break
    for rec in records:
        if rec not in out:
            out.append(rec)
    return out


def diversify(
    ordered: list[dict[str, Any]], used: list[dict[str, Any]], *, limit: int,
) -> list[dict[str, Any]]:
    chosen: list[dict[str, Any]] = []
    parents = {str(Path(r["rel"]).parent) for r in used}
    for rec in ordered:
        if rec in used:
            continue
        parent = str(Path(rec["rel"]).parent)
        if parent not in parents or len(chosen) < 1:
            chosen.append(rec)
            parents.add(parent)
        if len(chosen) >= limit:
            break
    for rec in ordered:
        if rec not in used and rec not in chosen:
            chosen.append(rec)
        if len(chosen) >= limit:
            break
    return chosen


def audit(
    api: str | None,
    batch: list[dict[str, Any]],
    by_base: dict[str, dict[str, Any]],
    started: float,
    *,
    mode: str,
    per_file: int,
    budget: int,
    compact: bool,
) -> list[dict[str, Any]]:
    if not batch:
        return []
    header = (
        f"Deep audit ({mode}). Max 5 findings. Name exact real functions from source. "
        "Skip anything you cannot exploit. " + FOCUS + "\nReturn STRICT JSON only:\n"
        + SCHEMA + "\n"
    )
    parts: list[str] = [header]
    room = budget - len(header)
    for rec in batch:
        body = str(rec["text"])
        if compact:
            body = compact_source(body, per_file)
        elif len(body) > per_file:
            body = body[:per_file] + "\n/* truncated */\n"
        sigs = [f"{f['line']}:{f['sig']}" for f in rec["functions"][:28]]
        block = (
            f"\n\n=== {rec['rel']} ===\nContracts: {', '.join(rec['contracts'][:6])}\n"
            f"Functions: {json.dumps(sigs)}\nRisk: {json.dumps(rec['risk'][:12])}\n"
            f"{body}\n{related(rec, by_base)}\n"
        )
        if room <= 0:
            break
        if len(block) > room:
            block = block[:room] + "\n/* truncated */\n"
        parts.append(block)
        room -= len(block)
    obj = load_json(infer(api, "".join(parts), 7000, started))
    items = obj.get("findings") or obj.get("vulnerabilities") or []
    return [x for x in items if isinstance(x, dict)] if isinstance(items, list) else []


def match_file(
    file_value: str, rel_map: dict[str, dict[str, Any]],
) -> tuple[str | None, dict[str, Any] | None]:
    low = file_value.lower().strip().strip("`")
    if not low:
        return None, None
    for rel, rec in rel_map.items():
        rl = rel.lower()
        if low == rl or rl.endswith(low) or low.endswith(rl):
            return rel, rec
    base = Path(low).name
    if base:
        hits = [(rel, rec) for rel, rec in rel_map.items() if Path(rel).name.lower() == base]
        if len(hits) == 1:
            return hits[0]
    return None, None


def clean(value: object) -> str:
    return " ".join(str(value or "").strip().split())


def normalize(raw: dict[str, Any], rel_map: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    rel, rec = match_file(str(raw.get("file") or raw.get("path") or ""), rel_map)
    if not rel or not rec:
        return None
    sev = str(raw.get("severity") or "").lower().strip()
    if sev not in {"high", "critical"}:
        return None
    try:
        conf = float(raw.get("confidence") if raw.get("confidence") is not None else 0.8)
    except (TypeError, ValueError):
        conf = 0.8
    if conf < MIN_CONF:
        return None
    fn = str(raw.get("function") or "").strip().strip("`() ")
    if "." in fn:
        fn = fn.split(".")[-1]
    valid = set(rec["fnames"])
    if fn and fn not in valid and fn not in {"receive", "fallback", "constructor"}:
        # Soft drop: keep file-level only if mechanism is strong
        fn = ""
    contract = str(raw.get("contract") or "").strip().strip("`")
    if not contract and rec["contracts"]:
        contract = str(rec["contracts"][0])
    mech = clean(raw.get("mechanism"))
    impact = clean(raw.get("impact"))
    desc = clean(raw.get("description"))
    title = clean(raw.get("title")) or f"{contract}.{fn or 'logic'} - high-impact bug"
    if len(mech) < 28 and len(desc) < MIN_DESC:
        return None
    where = f"In `{rel}`"
    if contract:
        where += f", contract `{contract}`"
    if fn:
        where += f", function `{fn}()`"
    rebuilt = where + ". "
    if mech:
        rebuilt += f"Mechanism: {mech.rstrip('.')}. "
    if impact:
        rebuilt += f"Impact: {impact.rstrip('.')}. "
    if desc:
        rebuilt += desc
    rebuilt = " ".join(rebuilt.split())
    if len(rebuilt) < MIN_DESC:
        return None
    line = raw.get("line")
    if not isinstance(line, int) and fn:
        for needle in (f"function {fn}", f"def {fn}", f"fn {fn}", f"fun {fn}"):
            idx = str(rec["text"]).find(needle)
            if idx >= 0:
                line = str(rec["text"]).count("\n", 0, idx) + 1
                break
    base = rel.rsplit("/", 1)[-1]
    loc = f" Affected location: `{rel}`, `{base}`" + (f", `{fn}()`" if fn else "") + "."
    if loc.strip() not in rebuilt:
        rebuilt += loc
    return {
        "title": title[:220],
        "description": rebuilt[:3000],
        "severity": sev,
        "file": rel,
        "function": fn,
        "line": line if isinstance(line, int) else None,
        "type": str(raw.get("type") or "logic"),
        "confidence": min(0.97, conf if sev == "critical" else conf),
    }


def dedupe(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str]] = set()
    out: list[dict[str, Any]] = []
    for item in sorted(
        items,
        key=lambda f: (
            f.get("severity") == "critical",
            float(f.get("confidence") or 0),
            len(str(f.get("description"))),
        ),
        reverse=True,
    ):
        key = (
            str(item.get("file") or "").lower(),
            str(item.get("function") or "").lower(),
            re.sub(r"[^a-z0-9]+", " ", str(item.get("title") or "").lower())[:70],
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
        if len(out) >= MAX_FINDINGS:
            break
    return out


if __name__ == "__main__":
    import sys

    print(json.dumps(agent_main(sys.argv[1] if len(sys.argv) > 1 else None), indent=2))
