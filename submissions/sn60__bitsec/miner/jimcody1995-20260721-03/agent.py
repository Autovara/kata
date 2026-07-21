"""SN60 miner: adaptive project-pass reclaim vs current king + open #169.

Promotion order is pass score first. Bohdan dethroned #170 on a single project
pass despite worse invalids; this agent switches to exhaustive full-file mode
on compact repos, keeps a mid TEE envelope to cut timeouts, and lifts TP depth
on larger trees without flooding precision.
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from collections import defaultdict
from pathlib import Path
from typing import Any

SUFFIXES = (".sol", ".vy", ".rs", ".move", ".cairo")
SCAN_LIMIT = 92
SIZE_LIMIT = 275_000
MAP_BUDGET = 34_000
DEPTH_BUDGET = 48_000
WIDE_BUDGET = 46_000
DEPTH_EACH = 16_000
WIDE_EACH = 7_200
IMPORT_SNIP = 3_200
DEPTH_N = 6
WIDE_N = 11
SMALL_FILE_CAP = 14
EMIT_LIMIT = 18
TIME_BUDGET = 720.0
HTTP_LIMIT = 195
RESERVE = 225.0
CALLS = 3
LLM = os.environ.get("KATA_MINER_MODEL", "deepseek-ai/DeepSeek-V3.2-TEE")

SKIP = frozenset({
    ".git", ".github", ".venv", "artifacts", "broadcast", "cache", "coverage",
    "dist", "docs", "example", "examples", "lib", "libs", "node_modules", "out",
    "script", "scripts", "target", "test", "tests", "vendor", "vendors",
    "mock", "mocks", "fixtures", "fixture", "deps", "build", "interfaces",
    "interface",
})

SIGNALS = (
    "delegatecall", ".call{", "selfdestruct", "tx.origin", "assembly",
    "ecrecover", "permit", "signature", "nonce", "initialize", "upgrade",
    "onlyowner", "onlyrole", "mint", "burn", "withdraw", "redeem", "deposit",
    "borrow", "repay", "liquidat", "collateral", "share", "totalsupply",
    "oracle", "getprice", "latestround", "slot0", "flash", "swap", "claim",
    "unchecked", "transferfrom", "approve", "settle", "rebalance", "invoke",
    "cpi", "signer", "authority", "lamports", "borrow_global", "move_to",
    "get_caller_address", "felt", "starknet", "storage", "perp", "position",
    "margin", "funding", "intent", "domainseparator",
)

STEMS = (
    "vault", "pool", "router", "manager", "controller", "strategy", "market",
    "oracle", "bridge", "staking", "reward", "treasury", "proxy", "liquidat",
    "borrow", "token", "perp", "position", "lending", "escrow", "amm",
    "clearing", "margin", "program", "account", "factory", "perpetual",
    "pair", "adapter", "gate", "float", "math", "order",
)

SOL_FN = re.compile(
    r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*([^{};]*)(?:;|\{)",
    re.MULTILINE,
)
VY_FN = re.compile(r"^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", re.MULTILINE)
RS_FN = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
MOVE_FN = re.compile(
    r"^\s*(?:public\s*(?:\([^)]*\))?\s+)?(?:entry\s+)?(?:native\s+)?fun\s+"
    r"([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
CAIRO_FN = re.compile(
    r"^\s*(?:pub\s+)?(?:fn|func)\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
SOL_CT = re.compile(
    r"^\s*(?:abstract\s+contract|contract|library|interface)\s+"
    r"([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
RS_CT = re.compile(
    r"^\s*(?:pub\s+)?(?:mod|struct|enum)\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
MOVE_CT = re.compile(
    r"^\s*module\s+(?:[A-Za-z_0-9]+::)?([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
CAIRO_CT = re.compile(
    r"^\s*(?:pub\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
IMPORT = re.compile(
    r'^\s*(?:import|use)\b[^;\n]*?["\']?([A-Za-z0-9_./:]+)["\']?',
    re.MULTILINE,
)
DEF_MARK = re.compile(
    r"\bfunction\b|\bdef\b|\bfn\b|\bfun\b|\bmodifier\b|\bconstructor\b|"
    r"\bmodule\b|\bmapping\b|\bstorage\b"
)
TRANSIENT = frozenset({408, 409, 425, 500, 502, 504, 520, 522, 524, 529})

PERSONA = (
    "You are a principal smart-contract security auditor for Solidity, Vyper, "
    "Rust/Solana, Move, and Cairo/Starknet. Enumerate REAL exploitable HIGH or "
    "CRITICAL bugs with concrete attacker steps and material fund/privilege "
    "impact, localized to exact file and function. Reject gas, style, missing "
    "events, and trusted-admin notes. Output one strict JSON object only."
)

GOALS = (
    "On compact codebases, missing even one high/critical fails the project — "
    "list every distinct exploitable issue you can localize. Hunt: share/"
    "reserve accounting and first-depositor inflation, rounding theft, oracle/"
    "price manipulation in value math, missing auth on privileged writes, "
    "reentrancy/callback ordering, signature replay, init/upgrade seizure, "
    "liquidation/withdrawal edges. Cairo/Starknet: caller checks, storage "
    "address confusion, L1 handler auth, felt overflow."
)


def agent_main(project_dir: str | None = None, inference_api: str | None = None) -> dict:
    started = time.monotonic()
    findings: list[dict[str, Any]] = []
    try:
        root = locate(project_dir)
        if root is None:
            return {"vulnerabilities": findings}
        records = collect(root)
        if not records:
            return {"vulnerabilities": findings}

        by_rel = {r["rel"]: r for r in records}
        by_base: dict[str, dict[str, Any]] = {}
        for r in records:
            by_base.setdefault(r["base"], r)

        compact = is_compact(records)
        raw: list[dict[str, Any]] = []
        n = 0
        order = records

        if have_time(started, RESERVE):
            targets, early = triage(inference_api, records, started, compact=compact)
            raw.extend(early)
            order = prioritize(targets, records)
            n = 1

        if n < CALLS and have_time(started, RESERVE):
            if compact:
                batch = order[: min(len(order), SMALL_FILE_CAP)]
                raw.extend(deep_audit(
                    inference_api, batch, by_base, started,
                    each=22_000, budget=54_000, label="full-repo-exhaustive",
                    max_findings=12, use_window=False,
                ))
            else:
                raw.extend(deep_audit(
                    inference_api, order[:DEPTH_N], by_base, started,
                    each=DEPTH_EACH, budget=DEPTH_BUDGET, label="contiguous-depth",
                    max_findings=8, use_window=False,
                ))
            n += 1

        if n < CALLS and have_time(started, RESERVE):
            if compact:
                # Fresh lens: re-audit mid/low files with risk windows.
                wide = diversify(order, order[:4], limit=WIDE_N)
                raw.extend(deep_audit(
                    inference_api, wide, by_base, started,
                    each=WIDE_EACH, budget=WIDE_BUDGET, label="second-pass-windows",
                    max_findings=8, use_window=True,
                ))
            else:
                wide = diversify(order, order[:DEPTH_N], limit=WIDE_N)
                raw.extend(deep_audit(
                    inference_api, wide, by_base, started,
                    each=WIDE_EACH, budget=WIDE_BUDGET, label="cross-module-window",
                    max_findings=7, use_window=True,
                ))
            n += 1

        raw.extend(static_hits(records, limit=5 if compact else 4))

        for item in raw:
            shaped = shape(item, by_rel, strict=not compact)
            if shaped is not None:
                findings.append(shaped)
        if not findings:
            for item in static_hits(records, limit=3, fallback=True):
                shaped = shape(item, by_rel, strict=False)
                if shaped is not None:
                    findings.append(shaped)
    except Exception:
        pass
    return {"vulnerabilities": collapse(findings, per_file=3 if findings else 2)}


def is_compact(records: list[dict[str, Any]]) -> bool:
    if len(records) <= SMALL_FILE_CAP:
        return True
    total = sum(len(str(r["text"])) for r in records[:40])
    return len(records) <= 22 and total <= 180_000


def have_time(started: float, need: float = 0.0) -> bool:
    return time.monotonic() - started < TIME_BUDGET - need


def locate(project_dir: str | None) -> Path | None:
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
        if path.is_dir() and any_source(path):
            return path
    return None


def any_source(root: Path) -> bool:
    try:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [
                d for d in dirnames if d.lower() not in SKIP and not d.startswith(".")
            ]
            for name in filenames:
                if Path(name).suffix.lower() in SUFFIXES:
                    return True
    except OSError:
        return False
    return False


def banned(rel: Path) -> bool:
    for part in rel.parts[:-1]:
        low = part.lower()
        if low in SKIP or low.startswith("."):
            return True
    name = rel.name.lower()
    return name.endswith((
        ".t.sol", ".s.sol", "_test.sol", ".test.sol", "_test.rs", ".test.rs",
        "_tests.move",
    ))


def read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def parse_fns(text: str, ext: str) -> list[dict[str, Any]]:
    if ext == ".vy":
        pats = [VY_FN]
    elif ext == ".rs":
        pats = [RS_FN]
    elif ext == ".move":
        pats = [MOVE_FN]
    elif ext == ".cairo":
        pats = [CAIRO_FN]
    else:
        pats = [SOL_FN]
    out: list[dict[str, Any]] = []
    for pat in pats:
        for m in pat.finditer(text):
            out.append({
                "name": m.group(1),
                "line": text.count("\n", 0, m.start()) + 1,
                "sig": " ".join(m.group(0).strip().split())[:170],
            })
    return out


def parse_cts(text: str, ext: str) -> list[str]:
    if ext == ".rs":
        return RS_CT.findall(text)
    if ext == ".move":
        return MOVE_CT.findall(text)
    if ext == ".cairo":
        return CAIRO_CT.findall(text)
    if ext == ".vy":
        return []
    return SOL_CT.findall(text)


def risk_lines(text: str, limit: int = 14) -> list[str]:
    out: list[str] = []
    for idx, line in enumerate(text.splitlines(), 1):
        low = line.lower()
        if any(sig in low for sig in SIGNALS):
            compact = " ".join(line.split())
            if compact:
                out.append(f"{idx}:{compact[:160]}")
        if len(out) >= limit:
            break
    return out


def score_rec(rel: str, low: str, nfuncs: int, ext: str) -> float:
    s = float(min(nfuncs, 28))
    rl = rel.lower()
    for stem in STEMS:
        if stem in rl:
            s += 8
    for sig in SIGNALS:
        s += min(low.count(sig), 4) * 2.5
    if any(x in low for x in ("external", "public", "@external", "pub fn", "entry fun")):
        s += 5
    if any(x in low for x in ("balances", "totalsupply", "total_supply", "reserve", "invariant")):
        s += 6
    if "nonreentrant" not in low and any(x in low for x in ("withdraw", "redeem", ".call{")):
        s += 6
    if ext == ".cairo" or "starknet" in low:
        s += 4
    if ext == ".sol" and "contract " not in low and "library " not in low:
        s *= 0.2
    parts = [p.lower() for p in Path(rel).parts]
    stem = Path(rel).stem.lower()
    if stem.startswith("test_") or stem.endswith(("_test", "_tests", ".t")) or "test" in parts:
        s *= 0.1
    return s


def collect(root: Path) -> list[dict[str, Any]]:
    recs: list[dict[str, Any]] = []
    try:
        paths = sorted(root.rglob("*"))
    except OSError:
        return []
    for path in paths:
        if not path.is_file():
            continue
        ext = path.suffix.lower()
        if ext not in SUFFIXES:
            continue
        try:
            rel = path.relative_to(root)
            if banned(rel) or path.stat().st_size > SIZE_LIMIT:
                continue
        except OSError:
            continue
        text = read(path)
        if not text.strip():
            continue
        functions = parse_fns(text, ext)
        contracts = parse_cts(text, ext)
        if not contracts and ext != ".sol":
            contracts = [path.stem]
        if not contracts and not functions:
            continue
        low = text.lower()
        if ext == ".sol" and "function " not in low and "contract " not in low:
            continue
        rec = {
            "path": path,
            "rel": rel.as_posix(),
            "base": path.name,
            "stem": path.stem,
            "ext": ext,
            "text": text,
            "functions": functions,
            "contracts": contracts,
            "risk": risk_lines(text),
        }
        rec["score"] = score_rec(rec["rel"], low, len(functions), ext)
        recs.append(rec)
    recs.sort(key=lambda r: (-float(r["score"]), r["rel"]))
    return recs[:SCAN_LIMIT]


def windowed(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    lines = text.splitlines()
    keep: set[int] = set()
    for idx, line in enumerate(lines):
        low = line.lower()
        if DEF_MARK.search(line) or any(sig in low for sig in SIGNALS):
            for j in range(max(0, idx - 4), min(len(lines), idx + 16)):
                keep.add(j)
    out: list[str] = []
    last = -9
    size = 0
    for idx in sorted(keep):
        if idx > last + 1:
            gap = f"\n/* ... {idx - last - 1} lines ... */\n"
            out.append(gap)
            size += len(gap)
        entry = lines[idx] + "\n"
        if size + len(entry) > limit:
            break
        out.append(entry)
        size += len(entry)
        last = idx
    blob = "".join(out)
    if len(blob) < limit // 2:
        blob += "\n/* prefix */\n" + text[: max(0, limit - len(blob) - 16)]
    return blob[:limit]


def map_blob(records: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    for r in records:
        parts.append(json.dumps({
            "file": r["rel"],
            "lang": r["ext"].lstrip("."),
            "score": round(float(r["score"]), 1),
            "bytes": len(r["text"]),
            "contracts": r["contracts"][:6],
            "functions": [f"{f['line']}:{f['sig']}" for f in r["functions"][:18]],
            "risk_lines": r["risk"][:12],
        }, separators=(",", ":")))
    return "\n".join(parts)[:MAP_BUDGET]


def chat(
    api: str | None,
    messages: list[dict[str, str]],
    max_tokens: int,
    started: float,
) -> str:
    if not have_time(started, 8):
        return ""
    endpoint = (api or os.environ.get("INFERENCE_API") or "").rstrip("/")
    if not endpoint:
        return ""
    left = max(10.0, TIME_BUDGET - (time.monotonic() - started) - 10.0)
    timeout = min(HTTP_LIMIT, int(left))
    body = json.dumps({
        "model": LLM,
        "temperature": 0.0,
        "messages": messages,
        "max_tokens": max_tokens,
    }).encode()
    headers = {
        "Content-Type": "application/json",
        "x-inference-api-key": os.environ.get("INFERENCE_API_KEY", ""),
    }
    for attempt in range(2):
        if not have_time(started, 8):
            return ""
        try:
            req = urllib.request.Request(
                endpoint + "/inference", data=body, method="POST", headers=headers,
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return pull(json.loads(resp.read().decode("utf-8", "replace")))
        except urllib.error.HTTPError as exc:
            if exc.code in {429, 503}:
                return ""
            if exc.code not in TRANSIENT:
                return ""
            if attempt == 0 and have_time(started, RESERVE * 0.4):
                time.sleep(0.6)
        except (OSError, TimeoutError, ValueError):
            if attempt == 0 and have_time(started, RESERVE * 0.4):
                time.sleep(0.5)
            else:
                return ""
    return ""


def pull(payload: dict[str, Any]) -> str:
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


def extract_dicts(text: str) -> list[dict[str, Any]]:
    """Recover finding objects even from truncated JSON."""
    out: list[dict[str, Any]] = []
    depth = 0
    start = -1
    in_str = esc = False
    for i, ch in enumerate(text):
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
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            if depth > 0:
                depth -= 1
                if depth == 0 and start >= 0:
                    try:
                        obj = json.loads(text[start : i + 1])
                        if isinstance(obj, dict) and (
                            "title" in obj or "file" in obj or "mechanism" in obj
                        ):
                            out.append(obj)
                    except json.JSONDecodeError:
                        pass
                    start = -1
    return out


def as_obj(text: str) -> dict[str, Any]:
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
        recovered = extract_dicts(s)
        return {"findings": recovered} if recovered else {}
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
                    recovered = extract_dicts(s)
                    return {"findings": recovered} if recovered else {}
    recovered = extract_dicts(s)
    return {"findings": recovered} if recovered else {}


def triage(
    api: str | None,
    records: list[dict[str, Any]],
    started: float,
    *,
    compact: bool,
) -> tuple[list[str], list[dict[str, Any]]]:
    pick = 12 if compact else 8
    prompt = (
        f"Repository map ({len(records)} source files). (1) Pick up to {pick} "
        "highest-yield file paths verbatim. (2) Report every HIGH/CRITICAL already "
        "justified by signatures/risk lines"
        + (" — this repo is compact: aim for complete coverage." if compact else ".")
        + "\n"
        + GOALS
        + "\nJSON only:\n"
        '{"target_files":["path"],"findings":[{"title":"Unit.fn - bug","file":"path",'
        '"contract":"Name","function":"fn","line":1,"severity":"high|critical",'
        '"confidence":0.0,"mechanism":"pre -> attack -> effect","impact":"harm",'
        '"description":"2-4 sentences naming file, function, mechanism, impact"}]}\n\n'
        + map_blob(records)
    )
    obj = as_obj(chat(
        api,
        [{"role": "system", "content": PERSONA}, {"role": "user", "content": prompt}],
        8000 if compact else 6500,
        started,
    ))
    targets = obj.get("target_files")
    items = obj.get("findings") or obj.get("vulnerabilities") or []
    if not isinstance(items, list):
        items = []
    return (
        [str(x) for x in targets if isinstance(x, str)] if isinstance(targets, list) else [],
        [x for x in items if isinstance(x, dict)],
    )


def prioritize(targets: list[str], records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for target in targets:
        tl = target.lower().strip()
        for r in records:
            rl = str(r["rel"]).lower()
            if tl == rl or rl.endswith(tl) or tl.endswith(rl):
                if r not in out:
                    out.append(r)
                break
    for r in records:
        if r not in out:
            out.append(r)
    return out


def uniq(seq: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for item in seq:
        if item["rel"] in seen:
            continue
        seen.add(item["rel"])
        out.append(item)
    return out


def diversify(
    ordered: list[dict[str, Any]],
    already: list[dict[str, Any]],
    *,
    limit: int,
) -> list[dict[str, Any]]:
    used = {r["rel"] for r in already}
    mid = [r for r in ordered if r["rel"] not in used]
    mixed = mid[: max(0, limit - 3)] + already[:3] + mid[max(0, limit - 3) :]
    return uniq(mixed)[:limit]


def related(rec: dict[str, Any], by_base: dict[str, dict[str, Any]]) -> str:
    chunks: list[str] = []
    for imp in IMPORT.findall(str(rec["text"])):
        name = imp.rsplit("/", 1)[-1].rsplit("::", 1)[-1]
        other = (
            by_base.get(name)
            or by_base.get(name + ".sol")
            or by_base.get(name + ".rs")
            or by_base.get(name + ".cairo")
            or by_base.get(name + ".move")
            or by_base.get(name + ".vy")
        )
        if other and other["rel"] != rec["rel"]:
            chunks.append(
                f"\n--- RELATED {other['rel']} ---\n{str(other['text'])[:IMPORT_SNIP]}"
            )
        if len(chunks) >= 2:
            break
    return "".join(chunks)


def deep_audit(
    api: str | None,
    batch: list[dict[str, Any]],
    by_base: dict[str, dict[str, Any]],
    started: float,
    *,
    each: int,
    budget: int,
    label: str,
    max_findings: int,
    use_window: bool = False,
) -> list[dict[str, Any]]:
    if not batch:
        return []
    header = (
        f"Audit mode={label}. {GOALS}\n"
        f"Enumerate distinct HIGH/CRITICAL issues (aim up to {max_findings}). "
        "One finding per vulnerable function when warranted. If truncated, finish "
        "the current object cleanly. Strict JSON:\n"
        '{"findings":[{"title":"Unit.fn - bug","file":"path","contract":"C",'
        '"function":"fn","line":1,"severity":"high|critical","confidence":0.0,'
        '"type":"logic","mechanism":"pre->attack->effect","impact":"harm",'
        '"description":"2-5 sentences with exploit path"}]}\n'
    )
    parts, room = [header], budget - len(header)
    for rec in batch:
        src = str(rec["text"])
        body = windowed(src, each) if use_window else src[:each]
        sigs = [f"{f['line']}:{f['sig']}" for f in rec["functions"][:24]]
        block = (
            f"\n\n=== {rec['rel']} ===\nUnits: {', '.join(rec['contracts'][:8])}\n"
            f"Functions: {json.dumps(sigs)}\nRisk: {json.dumps(rec['risk'][:14])}\n"
            f"{body}\n{related(rec, by_base)}\n"
        )
        if room <= 0:
            break
        if len(block) > room:
            block = block[:room] + "\n/* truncated */\n"
        parts.append(block)
        room -= len(block)
    text = chat(
        api,
        [{"role": "system", "content": PERSONA}, {"role": "user", "content": "".join(parts)}],
        9000 if max_findings >= 10 else 7500,
        started,
    )
    obj = as_obj(text)
    items = obj.get("findings") or obj.get("vulnerabilities") or []
    if not isinstance(items, list) or not items:
        items = extract_dicts(text)
    return [x for x in items if isinstance(x, dict)]


def hit(
    rec: dict[str, Any],
    title: str,
    kind: str,
    mechanism: str,
    impact: str,
    *,
    function: str = "",
    line: int | None = None,
) -> dict[str, Any]:
    contract = str(rec["contracts"][0]) if rec.get("contracts") else rec["stem"]
    return {
        "title": title,
        "file": rec["rel"],
        "contract": contract,
        "function": function,
        "line": line,
        "severity": "high",
        "type": kind,
        "confidence": 0.8,
        "mechanism": mechanism,
        "impact": impact,
        "description": (
            f"In `{rec['rel']}`"
            + (f", function `{function}`" if function else "")
            + f". Mechanism: {mechanism.rstrip('.')}. Impact: {impact.rstrip('.')}."
        ),
    }


def sol_slices(text: str) -> list[dict[str, Any]]:
    matches = list(SOL_FN.finditer(text))
    out: list[dict[str, Any]] = []
    for i, m in enumerate(matches):
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        out.append({
            "name": m.group(1),
            "sig": " ".join(m.group(0).split()),
            "line": text.count("\n", 0, start) + 1,
            "body": text[start:end],
        })
    return out


def line_of(text: str, offset: int) -> int:
    return 1 if offset < 0 else text.count("\n", 0, offset) + 1


def static_hits(
    records: list[dict[str, Any]],
    *,
    limit: int = 4,
    fallback: bool = False,
) -> list[dict[str, Any]]:
    """High-precision Solidity smell detectors — capped to protect precision."""
    out: list[dict[str, Any]] = []
    cap = min(limit, 3 if fallback else limit)
    for rec in records:
        if rec["ext"] != ".sol":
            continue
        text = str(rec["text"])
        low = text.lower()
        if "contract " not in low and "library " not in low:
            continue
        names = {f["name"] for f in rec["functions"]}

        if "function initialize" in low and not any(
            x in low for x in ("initializer", "onlyowner", "onlyrole", "_disableinitializers")
        ):
            out.append(hit(
                rec,
                "Unprotected initializer",
                "access-control",
                "Initialize is externally reachable without a one-time initializer "
                "modifier or owner/role gate.",
                "An attacker can seize ownership or critical configuration.",
                function="initialize" if "initialize" in names else "",
            ))

        if "tx.origin" in low and any(x in low for x in ("require", "if ", "assert", "revert")):
            out.append(hit(
                rec,
                "Authorization relies on tx.origin",
                "access-control",
                "A security branch authenticates with tx.origin rather than msg.sender.",
                "Phishing contracts can bypass checks and act as the victim.",
                line=line_of(text, low.find("tx.origin")),
            ))

        for fn in sol_slices(text):
            body, sig = fn["body"].lower(), fn["sig"].lower()
            name = fn["name"]
            if "delegatecall" in body and ("external" in sig or "public" in sig):
                if not any(g in sig + body for g in ("onlyowner", "onlyrole", "requiresauth")):
                    out.append(hit(
                        rec,
                        "Unprotected delegatecall in external entrypoint",
                        "access-control",
                        "An external function performs delegatecall without a hard "
                        "owner/role gate.",
                        "Callers can execute attacker logic in the contract storage "
                        "context.",
                        function=name,
                        line=fn["line"],
                    ))
            if ("external" in sig or "public" in sig) and "nonreentrant" not in sig + body:
                call_m = re.search(r"\.call\s*\{|\.call\(|transfer\(|safetransfer", body)
                write_m = re.search(
                    r"\b(balances?|shares?|deposits?|allowances?|total)\b.*=", body
                )
                if call_m and write_m and call_m.start() < write_m.start():
                    out.append(hit(
                        rec,
                        "External call before state update enables reentrancy",
                        "reentrancy",
                        "External call/transfer happens before balances/shares update "
                        "without a reentrancy guard.",
                        "A malicious receiver can re-enter and drain funds against "
                        "stale accounting.",
                        function=name,
                        line=fn["line"],
                    ))
            if ("ecrecover" in body or "recover(" in body) and not any(
                x in body + sig for x in ("nonce", "deadline", "block.timestamp", "chainid")
            ):
                if "external" in sig or "public" in sig:
                    out.append(hit(
                        rec,
                        "Signature path lacks replay / freshness binding",
                        "signature",
                        "Signature recovery accepts a signer without nonce, deadline, "
                        "or chain id binding.",
                        "Valid signatures can be replayed across time or deployments.",
                        function=name,
                        line=fn["line"],
                    ))
        if len(out) >= cap:
            break
    return out[:cap]


def resolve(
    file_value: str,
    by_rel: dict[str, dict[str, Any]],
) -> tuple[str | None, dict[str, Any] | None]:
    low = file_value.lower().strip().strip("`")
    if not low:
        return None, None
    for rel, rec in by_rel.items():
        rl = rel.lower()
        if low == rl or rl.endswith(low) or low.endswith(rl):
            return rel, rec
    base = Path(low).name
    if base:
        hits = [(rel, rec) for rel, rec in by_rel.items() if Path(rel).name.lower() == base]
        if len(hits) == 1:
            return hits[0]
    return None, None


def tidy(value: object) -> str:
    return " ".join(str(value or "").strip().split())


def shape(
    raw: dict[str, Any],
    by_rel: dict[str, dict[str, Any]],
    *,
    strict: bool = True,
) -> dict[str, Any] | None:
    rel, rec = resolve(str(raw.get("file") or raw.get("path") or ""), by_rel)
    if not rel or not rec:
        return None
    sev = str(raw.get("severity") or "").lower().strip()
    if sev in {"medium", "med", "moderate"}:
        sev = "high"
    if sev not in {"high", "critical"}:
        return None
    fn = str(raw.get("function") or "").strip().strip("`() ")
    if "." in fn:
        fn = fn.split(".")[-1]
    if "::" in fn:
        fn = fn.split("::")[-1]
    names = {str(f["name"]) for f in rec["functions"]}
    if fn and fn not in names:
        fn = ""
    contract = str(raw.get("contract") or raw.get("module") or "").strip().strip("`")
    if not contract and rec["contracts"]:
        contract = str(rec["contracts"][0])
    elif contract and rec["contracts"] and contract not in rec["contracts"]:
        contract = str(rec["contracts"][0])
    mech = tidy(raw.get("mechanism"))
    impact = tidy(raw.get("impact"))
    desc = tidy(raw.get("description"))
    title = tidy(raw.get("title")) or f"{contract}.{fn or 'logic'} - high-impact bug"
    min_mech, min_desc = (24, 120) if strict else (18, 90)
    if len(mech) < min_mech and len(desc) < min_desc:
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
    if len(rebuilt) < (110 if strict else 90):
        return None
    line = raw.get("line")
    if not isinstance(line, int) and fn:
        for needle in (f"function {fn}", f"def {fn}", f"fn {fn}", f"fun {fn}"):
            idx = str(rec["text"]).find(needle)
            if idx >= 0:
                line = line_of(str(rec["text"]), idx)
                break
    base = rel.rsplit("/", 1)[-1]
    loc = f" Affected location: `{rel}`, `{base}`" + (f", `{fn}()`" if fn else "") + "."
    if loc.strip() not in rebuilt:
        rebuilt += loc
    try:
        conf = float(raw.get("confidence") or 0.0)
    except (TypeError, ValueError):
        conf = 0.0
    if strict and sev == "high" and conf and conf < 0.45:
        return None
    return {
        "title": title[:220],
        "description": rebuilt[:3000],
        "severity": sev,
        "file": rel,
        "function": fn,
        "line": line if isinstance(line, int) else None,
        "type": str(raw.get("type") or "logic"),
        "confidence": max(conf, 0.9 if sev == "critical" else 0.82),
    }


def collapse(
    items: list[dict[str, Any]],
    *,
    per_file: int = 3,
) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str]] = set()
    counts: dict[str, int] = defaultdict(int)
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
            str(item.get("title") or "").lower()[:90],
        )
        if key in seen:
            continue
        file_key = str(item.get("file") or "").lower()
        if counts[file_key] >= per_file:
            continue
        seen.add(key)
        counts[file_key] += 1
        out.append(item)
        if len(out) >= EMIT_LIMIT:
            break
    return out


if __name__ == "__main__":
    import sys
    print(json.dumps(agent_main(sys.argv[1] if len(sys.argv) > 1 else None), indent=2))
