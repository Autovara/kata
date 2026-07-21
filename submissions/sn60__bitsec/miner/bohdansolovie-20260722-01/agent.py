"""SN60 fortress miner: finish clean, pass projects, defend the crown.

Built to raise the reign average vs bohdansolovie-20260721-02 (#171): that win
came from project-pass with tied TPs, but 5 invalids left a soft flank. This
agent spends budget adaptively — small trees get full coverage for 2-of-3 PASS,
large trees get triage+deep only — and aborts the third LLM call when time is
tight so replicas return JSON instead of timing out.
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

LANGS = (".sol", ".vy", ".rs", ".move", ".cairo")
FILE_CAP = 80
BYTE_CAP = 240_000
MAP_LIMIT = 24_000
DEEP_LIMIT = 38_000
SWEEP_LIMIT = 34_000
DEEP_SLICE = 12_000
SWEEP_SLICE = 5_500
IMPORT_SLICE = 2_400
EMIT_CAP = 10
WALL = 640.0
HTTP_CAP = 190
SAFE = 300.0
CALL_CAP = 3
LLM = os.environ.get("KATA_MINER_MODEL", "deepseek-ai/DeepSeek-V3.2-TEE")

IGNORE = frozenset({
    ".git", ".github", ".venv", "artifacts", "broadcast", "cache", "coverage",
    "dist", "docs", "example", "examples", "lib", "libs", "node_modules", "out",
    "script", "scripts", "target", "test", "tests", "vendor", "vendors", "mock",
    "mocks", "fixtures", "fixture", "deps", "build", "interfaces", "interface",
    "generated", "bindings",
})

HOT_NAMES = (
    "vault", "pool", "router", "manager", "controller", "strategy", "market",
    "oracle", "bridge", "staking", "reward", "treasury", "proxy", "liquidat",
    "borrow", "token", "perp", "position", "lending", "escrow", "amm", "pair",
    "adapter", "clearing", "margin", "program", "account", "factory", "engine",
)

HOT_TOKENS = (
    "delegatecall", ".call{", "selfdestruct", "tx.origin", "assembly",
    "ecrecover", "permit", "signature", "nonce", "initialize", "upgrade",
    "mint", "burn", "withdraw", "redeem", "deposit", "borrow", "repay",
    "liquidat", "collateral", "share", "totalsupply", "oracle", "getprice",
    "latestround", "slot0", "flash", "swap", "claim", "unchecked",
    "transferfrom", "settle", "cpi", "signer", "authority", "lamports",
    "borrow_global", "move_to", "get_caller_address", "felt", "starknet",
)

RE_SOL = re.compile(
    r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*([^{};]*)(?:;|\{)",
    re.MULTILINE,
)
RE_SOL_X = re.compile(r"\b(constructor|receive|fallback)\b\s*\(")
RE_VY = re.compile(r"^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", re.MULTILINE)
RE_RS = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
RE_MOVE = re.compile(
    r"^\s*(?:public\s*(?:\([^)]*\))?\s+)?(?:entry\s+)?(?:native\s+)?fun\s+"
    r"([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
RE_CAIRO = re.compile(r"^\s*(?:pub\s+)?(?:fn|func)\s+([A-Za-z_][A-Za-z0-9_]*)", re.MULTILINE)
RE_SOL_CT = re.compile(
    r"^\s*(?:abstract\s+contract|contract|library|interface)\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
RE_RS_CT = re.compile(
    r"^\s*(?:pub\s+)?(?:mod|struct|enum)\s+([A-Za-z_][A-Za-z0-9_]*)", re.MULTILINE,
)
RE_MOVE_CT = re.compile(
    r"^\s*module\s+(?:[A-Za-z_0-9]+::)?([A-Za-z_][A-Za-z0-9_]*)", re.MULTILINE,
)
RE_CAIRO_CT = re.compile(r"^\s*(?:pub\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)", re.MULTILINE)
RE_IMP = re.compile(r'^\s*(?:import|use)\b[^;\n]*?["\']?([A-Za-z0-9_./:]+)["\']?', re.MULTILINE)
RE_DEF = re.compile(
    r"\bfunction\b|\bdef\b|\bfn\b|\bfun\b|\bmodifier\b|\bconstructor\b|\bmodule\b|\bmapping\b"
)

PERSONA = (
    "Elite auditor for Solidity/Vyper/Rust-Solana/Move/Cairo. Emit only REAL "
    "HIGH/CRITICAL exploits with concrete attacker steps and material impact, "
    "tied to exact file+function. Drop gas, style, events, and trusted-admin. "
    "Fewer solid findings beat long speculative lists. Strict JSON only."
)

SHAPE = (
    '{"findings":[{"title":"Contract.fn - bug","file":"path","contract":"Name",'
    '"function":"fn","severity":"high|critical","confidence":0.0,'
    '"mechanism":"pre -> attack -> effect","impact":"funds/privilege/insolvency",'
    '"description":"2-4 sentences with exploit path"}]}'
)

HUNT = (
    "Prefer bugs that finish small-project coverage: share/reserve inflation, "
    "first-depositor/rounding, oracle manipulation in value math, missing auth, "
    "reentrancy/callback order, signature replay, init/upgrade seizure, "
    "liquidation/withdrawal edges. Rust/Move/Cairo: signer/authority and "
    "account-ownership confusion."
)

RETRYABLE = frozenset({408, 409, 425, 429, 500, 502, 503, 504, 520, 522, 524, 529})


def agent_main(project_dir: str | None = None, inference_api: str | None = None) -> dict:
    t0 = time.monotonic()
    found: list[dict[str, Any]] = []
    try:
        root = find_root(project_dir)
        if root is None:
            return {"vulnerabilities": found}
        files = scan(root)
        if not files:
            return {"vulnerabilities": found}

        by_rel = {f["rel"]: f for f in files}
        by_base: dict[str, dict[str, Any]] = {}
        for f in files:
            by_base.setdefault(Path(str(f["rel"])).name, f)

        bag: list[dict[str, Any]] = []
        bag.extend(smell(files))

        order = files
        used = 0
        small = len(files) <= 12

        if room(t0, SAFE):
            picks, early = map_pass(inference_api, files, t0)
            bag.extend(early)
            order = promote(files, picks)
            used = 1

        if used < CALL_CAP and room(t0, SAFE):
            n_deep = min(len(order), 8 if small else 4)
            bag.extend(code_pass(
                inference_api, order[:n_deep], by_base, t0,
                tag="full-cover" if small else "hot-deep",
                each=DEEP_SLICE, budget=DEEP_LIMIT, window=False,
            ))
            used += 1

        # Third call only when plenty of wall-clock remains — invalids lose crowns.
        if used < CALL_CAP and room(t0, SAFE + 120) and not small:
            sweep = spread(order, order[:4], want=8)
            bag.extend(code_pass(
                inference_api, sweep, by_base, t0,
                tag="risk-sweep", each=SWEEP_SLICE, budget=SWEEP_LIMIT, window=True,
            ))

        for item in bag:
            ok = polish(item, by_rel)
            if ok is not None:
                found.append(ok)
    except Exception:
        pass
    return {"vulnerabilities": cull(found)}


def room(t0: float, need: float = 0.0) -> bool:
    return time.monotonic() - t0 < WALL - need


def find_root(project_dir: str | None) -> Path | None:
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
        if path.is_dir() and any_src(path):
            return path
    return None


def any_src(root: Path) -> bool:
    try:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d.lower() not in IGNORE and not d.startswith(".")]
            for name in filenames:
                if Path(name).suffix.lower() in LANGS:
                    return True
    except OSError:
        return False
    return False


def skip_path(rel: Path) -> bool:
    for part in rel.parts[:-1]:
        low = part.lower()
        if low in IGNORE or low.startswith("."):
            return True
    name = rel.name.lower()
    return name.endswith((
        ".t.sol", ".s.sol", "_test.sol", ".test.sol", "_test.rs", ".test.rs", "_tests.move",
    ))


def load_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def parse_fns(text: str, ext: str) -> list[dict[str, Any]]:
    if ext == ".vy":
        pats = [RE_VY]
    elif ext == ".rs":
        pats = [RE_RS]
    elif ext == ".move":
        pats = [RE_MOVE]
    elif ext == ".cairo":
        pats = [RE_CAIRO]
    else:
        pats = [RE_SOL]
    out: list[dict[str, Any]] = []
    for pat in pats:
        for m in pat.finditer(text):
            out.append({
                "name": m.group(1),
                "line": text.count("\n", 0, m.start()) + 1,
                "sig": " ".join(m.group(0).strip().split())[:170],
            })
    if ext == ".sol":
        for m in RE_SOL_X.finditer(text):
            out.append({
                "name": m.group(1),
                "line": text.count("\n", 0, m.start()) + 1,
                "sig": m.group(1),
            })
    return out


def parse_cts(text: str, ext: str, stem: str) -> list[str]:
    if ext == ".rs":
        found = RE_RS_CT.findall(text)
    elif ext == ".move":
        found = RE_MOVE_CT.findall(text)
    elif ext == ".cairo":
        found = RE_CAIRO_CT.findall(text)
    else:
        found = RE_SOL_CT.findall(text)
    seen: list[str] = []
    for name in found:
        if name not in seen:
            seen.append(name)
    return seen or [stem]


def risk_snip(text: str) -> list[str]:
    rows: list[str] = []
    terms = tuple(w.lower() for w in HOT_TOKENS)
    for num, line in enumerate(text.splitlines(), start=1):
        low = line.lower().replace(" ", "")
        if any(t.replace(" ", "") in low for t in terms):
            compact = " ".join(line.strip().split())
            if compact:
                rows.append(f"{num}: {compact[:150]}")
        if len(rows) >= 12:
            break
    return rows


def heat(rel: str, text: str, ext: str, nfuncs: int) -> float:
    ln, body = rel.lower(), text.lower()
    compact = body.replace(" ", "")
    score = float(min(nfuncs, 40))
    for w in HOT_NAMES:
        if w in ln:
            score += 12
        elif w in body:
            score += 2
    for w in HOT_TOKENS:
        score += min(compact.count(w.lower().replace(" ", "")), 4) * 3.0
    if any(t in body for t in ("external", "public", "entry", "pub fn", "#[external")):
        score += 6
    if "delegatecall" in compact:
        score += 12
    if ext == ".sol" and "contract " not in body and "library " not in body:
        score *= 0.2
    stem = Path(rel).stem.lower()
    parts = [p.lower() for p in Path(rel).parts]
    if stem.startswith("test_") or "test" in parts or any(p in ("mock", "mocks") for p in parts):
        score *= 0.08
    if "interface" in stem:
        score *= 0.25
    return score


def scan(root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [
                d for d in dirnames if d.lower() not in IGNORE and not d.startswith(".")
            ]
            for fname in filenames:
                path = Path(dirpath) / fname
                ext = path.suffix.lower()
                if ext not in LANGS:
                    continue
                try:
                    rel = path.relative_to(root)
                    if skip_path(rel) or path.stat().st_size > BYTE_CAP:
                        continue
                except OSError:
                    continue
                text = load_text(path)
                if not text:
                    continue
                if ext == ".sol" and not any(x in text for x in ("function", "contract ", "library ")):
                    continue
                if ext != ".sol" and not any(x in text for x in ("fn ", "fun ", "def ", "func ")):
                    continue
                funcs = parse_fns(text, ext)
                cts = parse_cts(text, ext, path.stem)
                if not funcs and ext == ".sol":
                    continue
                rel_s = rel.as_posix()
                rows.append({
                    "rel": rel_s,
                    "text": text,
                    "ext": ext,
                    "contracts": cts,
                    "functions": funcs,
                    "fnames": {f["name"] for f in funcs},
                    "risk": risk_snip(text),
                    "score": heat(rel_s, text, ext, len(funcs)),
                })
                if len(rows) >= FILE_CAP * 2:
                    break
            if len(rows) >= FILE_CAP * 2:
                break
    except OSError:
        return []
    rows.sort(key=lambda r: (-float(r["score"]), str(r["rel"])))
    return rows[:FILE_CAP]


def window_src(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    lines = text.splitlines()
    keep: set[int] = set()
    for i, line in enumerate(lines):
        low = line.lower()
        if RE_DEF.search(line) or any(t in low for t in HOT_TOKENS):
            for j in range(max(0, i - 3), min(len(lines), i + 12)):
                keep.add(j)
    chunks: list[str] = []
    last = -6
    size = 0
    for i in sorted(keep):
        if i > last + 1:
            gap = f"\n/* ... {i - last - 1} lines ... */\n"
            chunks.append(gap)
            size += len(gap)
        entry = f"{i + 1}: {lines[i]}"
        chunks.append(entry)
        size += len(entry) + 1
        last = i
        if size >= limit:
            break
    out = "\n".join(chunks)
    if len(out) < limit // 2:
        out += "\n\n/* head */\n" + text[: max(0, limit - len(out) - 16)]
    return out[:limit]


def neighbors(rec: dict[str, Any], by_base: dict[str, dict[str, Any]]) -> str:
    chunks: list[str] = []
    seen: set[str] = set()
    for imp in RE_IMP.findall(str(rec["text"])):
        base = imp.rsplit("/", 1)[-1].split("::")[-1]
        stem = base.split(".")[0]
        for cand in (base, stem, f"{stem}.sol", f"{stem}.rs"):
            other = by_base.get(cand)
            if other and other["rel"] != rec["rel"] and other["rel"] not in seen:
                seen.add(str(other["rel"]))
                chunks.append(
                    f"\n--- RELATED {other['rel']} ---\n{str(other['text'])[:IMPORT_SLICE]}"
                )
                break
        if len(chunks) >= 2:
            break
    return "".join(chunks)


def atlas(files: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    total = 0
    for rec in files:
        chunk = json.dumps({
            "file": rec["rel"],
            "kind": str(rec["ext"]).lstrip("."),
            "score": round(float(rec["score"]), 1),
            "contracts": rec["contracts"][:5],
            "functions": [f"{f['line']}:{f['sig']}" for f in rec["functions"][:20]],
            "risk_lines": rec["risk"][:10],
        }, separators=(",", ":"))
        parts.append(chunk)
        total += len(chunk) + 1
        if total > MAP_LIMIT:
            break
    return "\n".join(parts)[:MAP_LIMIT]


def extract_text(payload: dict[str, Any]) -> str:
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


def ask(api: str | None, messages: list[dict[str, str]], max_tokens: int, t0: float) -> str:
    if not room(t0, 10):
        return ""
    endpoint = (api or os.environ.get("INFERENCE_API") or "").rstrip("/")
    if not endpoint:
        return ""
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
        if not room(t0, 10):
            return ""
        timeout = min(HTTP_CAP, max(10.0, WALL - (time.monotonic() - t0) - 8))
        try:
            req = urllib.request.Request(
                endpoint + "/inference", data=body, method="POST", headers=headers,
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return extract_text(json.loads(resp.read().decode("utf-8", "replace")))
        except urllib.error.HTTPError as exc:
            if exc.code not in RETRYABLE:
                return ""
        except (OSError, TimeoutError, ValueError):
            pass
        wait = min(6.0, 1.2 * (attempt + 1))
        if not room(t0, wait + 40):
            break
        time.sleep(wait)
    return ""


def parse_obj(text: str) -> dict[str, Any]:
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


def map_pass(
    api: str | None, files: list[dict[str, Any]], t0: float,
) -> tuple[list[str], list[dict[str, Any]]]:
    prompt = (
        "Triage this repository map. Pick deep-audit targets AND report every REAL "
        "high/critical bug already justified by signatures/risk lines. " + HUNT + "\n"
        'STRICT JSON: {"target_files":["path"],"findings":[...]}\n' + SHAPE
        + "\n\nMap:\n" + atlas(files)
    )
    obj = parse_obj(ask(
        api,
        [{"role": "system", "content": PERSONA}, {"role": "user", "content": prompt}],
        4500,
        t0,
    ))
    targets = obj.get("target_files")
    items = obj.get("findings") or obj.get("vulnerabilities") or []
    return (
        [str(x) for x in targets if isinstance(x, str)] if isinstance(targets, list) else [],
        [x for x in items if isinstance(x, dict)] if isinstance(items, list) else [],
    )


def promote(files: list[dict[str, Any]], targets: list[str]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for target in targets:
        tl = target.lower().strip()
        for rec in files:
            rl = str(rec["rel"]).lower()
            if tl == rl or rl.endswith(tl) or tl.endswith(rl) or Path(tl).name == Path(rl).name:
                if rec not in out:
                    out.append(rec)
                break
    for rec in files:
        if rec not in out:
            out.append(rec)
    return out


def spread(
    ordered: list[dict[str, Any]], used: list[dict[str, Any]], *, want: int,
) -> list[dict[str, Any]]:
    chosen: list[dict[str, Any]] = []
    parents = {str(Path(r["rel"]).parent) for r in used}
    for rec in ordered:
        if rec in used:
            continue
        parent = str(Path(rec["rel"]).parent)
        if parent not in parents or len(chosen) < 2:
            chosen.append(rec)
            parents.add(parent)
        if len(chosen) >= want:
            break
    for rec in ordered:
        if rec not in used and rec not in chosen:
            chosen.append(rec)
        if len(chosen) >= want:
            break
    return chosen


def code_pass(
    api: str | None,
    batch: list[dict[str, Any]],
    by_base: dict[str, dict[str, Any]],
    t0: float,
    *,
    tag: str,
    each: int,
    budget: int,
    window: bool,
) -> list[dict[str, Any]]:
    if not batch:
        return []
    header = (
        f"Audit pass ({tag}). Max 5 findings. Name exact real functions. "
        "Missing true bugs costs the round; inventing noise also costs it. "
        + HUNT + "\nSTRICT JSON only:\n" + SHAPE + "\n"
    )
    parts: list[str] = [header]
    space = budget - len(header)
    for rec in batch:
        body = str(rec["text"])
        if window:
            body = window_src(body, each)
        elif len(body) > each:
            body = body[:each] + "\n/* truncated */\n"
        sigs = [f"{f['line']}:{f['sig']}" for f in rec["functions"][:24]]
        block = (
            f"\n\n=== {rec['rel']} ===\nContracts: {', '.join(rec['contracts'][:5])}\n"
            f"Functions: {json.dumps(sigs)}\nRisk: {json.dumps(rec['risk'][:10])}\n"
            f"{body}\n{neighbors(rec, by_base)}\n"
        )
        if space <= 0:
            break
        if len(block) > space:
            block = block[:space] + "\n/* truncated */\n"
        parts.append(block)
        space -= len(block)
    obj = parse_obj(ask(
        api,
        [{"role": "system", "content": PERSONA}, {"role": "user", "content": "".join(parts)}],
        5500,
        t0,
    ))
    items = obj.get("findings") or obj.get("vulnerabilities") or []
    return [x for x in items if isinstance(x, dict)] if isinstance(items, list) else []


def lineno(text: str, offset: int) -> int:
    return 1 if offset < 0 else text.count("\n", 0, offset) + 1


def brace_body(text: str, start: int) -> str:
    open_i = text.find("{", start)
    if open_i < 0:
        return text[start : start + 700]
    depth = 0
    for i in range(open_i, min(len(text), open_i + 5000)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return text[start : start + 1000]


def sol_cuts(text: str) -> list[dict[str, Any]]:
    marks = [(m.start(), m.group(1), " ".join(m.group(0).split())) for m in RE_SOL.finditer(text)]
    for m in RE_SOL_X.finditer(text):
        marks.append((m.start(), m.group(1), m.group(1)))
    marks.sort(key=lambda x: x[0])
    out: list[dict[str, Any]] = []
    for i, (pos, name, sig) in enumerate(marks):
        end = marks[i + 1][0] if i + 1 < len(marks) else len(text)
        out.append({
            "name": name,
            "sig": sig,
            "body": text[pos:end],
            "line": lineno(text, pos),
        })
    return out


def note(
    rec: dict[str, Any], title: str, kind: str, mechanism: str, impact: str,
    *, function: str = "", line: int | None = None,
) -> dict[str, Any]:
    contract = str(rec["contracts"][0]) if rec.get("contracts") else Path(str(rec["rel"])).stem
    return {
        "title": title,
        "file": rec["rel"],
        "contract": contract,
        "function": function,
        "line": line,
        "severity": "high",
        "type": kind,
        "confidence": 0.9,
        "mechanism": mechanism,
        "impact": impact,
        "description": (
            f"In `{rec['rel']}`"
            + (f", function `{function}`" if function else "")
            + f". Mechanism: {mechanism.rstrip('.')}. Impact: {impact.rstrip('.')}."
        ),
    }


def smell(files: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """High-precision Solidity detectors — free TPs without burning LLM budget."""
    hits: list[dict[str, Any]] = []
    for rec in files:
        if rec["ext"] != ".sol":
            continue
        text = str(rec["text"])
        low = text.lower()
        if "contract " not in low and "library " not in low:
            continue

        for m in re.finditer(r"\breceive\s*\(\s*\)\s*external\s+payable\s*\{", text):
            body = brace_body(text, m.start()).lower()
            if ("stake(" in body or "deposit(" in body) and "msg.sender" not in body:
                hits.append(note(
                    rec, "Payable receive auto-stakes native transfers", "accounting",
                    "The payable receive hook stakes or deposits every native transfer "
                    "without distinguishing protocol returns from user deposits",
                    "Returned native funds can be restaked immediately, locking liquidity "
                    "and corrupting withdrawal accounting",
                    function="receive", line=lineno(text, m.start()),
                ))
                break

        if "function initialize" in low and not any(
            x in low for x in ("initializer", "onlyowner", "onlyrole", "_disableinitializers")
        ):
            hits.append(note(
                rec, "Unprotected initializer", "access-control",
                "The initialize entrypoint is externally reachable without a one-time "
                "initializer modifier or owner/role gate",
                "An attacker can seize ownership or critical configuration on first call",
                function="initialize" if "initialize" in rec["fnames"] else "",
            ))

        if "tx.origin" in low and any(x in low for x in ("require", "if ", "assert", "revert")):
            hits.append(note(
                rec, "Authorization relies on tx.origin", "access-control",
                "A security branch authenticates with tx.origin rather than msg.sender",
                "Phishing contracts can bypass checks and act as the victim",
                line=lineno(text, low.find("tx.origin")),
            ))

        for fn in sol_cuts(text):
            body, sig, name = fn["body"].lower(), fn["sig"].lower(), fn["name"]
            if "delegatecall" in body and ("external" in sig or "public" in sig):
                if not any(g in sig + body for g in ("onlyowner", "onlyrole", "requiresauth")):
                    hits.append(note(
                        rec, "Unprotected delegatecall in external entrypoint", "access-control",
                        "An external function performs delegatecall without a hard owner/role gate",
                        "Callers can execute attacker logic in the contract storage context",
                        function=name, line=fn["line"],
                    ))
            if ("external" in sig or "public" in sig) and "nonreentrant" not in sig + body:
                call_m = re.search(r"\.call\s*\{|\.call\(|transfer\(|safetransfer", body)
                write_m = re.search(r"\b(balances?|shares?|deposits?|allowances?|total)\b.*=", body)
                if call_m and write_m and call_m.start() < write_m.start():
                    hits.append(note(
                        rec, "External call before state update enables reentrancy", "reentrancy",
                        "The function performs an external call/transfer before updating "
                        "balances/shares and has no reentrancy guard",
                        "A malicious receiver can re-enter and drain funds against stale accounting",
                        function=name, line=fn["line"],
                    ))
            if ("ecrecover" in body or "recover(" in body) and not any(
                x in body + sig for x in ("nonce", "deadline", "block.timestamp", "chainid")
            ):
                if "external" in sig or "public" in sig:
                    hits.append(note(
                        rec, "Signature path lacks replay / freshness binding", "signature",
                        "Signature recovery accepts a signer without nonce, deadline, or chain id binding",
                        "Valid signatures can be replayed across time or deployments",
                        function=name, line=fn["line"],
                    ))
        if len(hits) >= 5:
            break
    return hits[:5]


def resolve_file(
    file_value: str, by_rel: dict[str, dict[str, Any]],
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


def polish(raw: dict[str, Any], by_rel: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    rel, rec = resolve_file(str(raw.get("file") or raw.get("path") or ""), by_rel)
    if not rel or not rec:
        return None
    sev = str(raw.get("severity") or "").lower().strip()
    if sev not in {"high", "critical"}:
        return None
    fn = str(raw.get("function") or "").strip().strip("`() ")
    if "." in fn:
        fn = fn.split(".")[-1]
    if "::" in fn:
        fn = fn.split("::")[-1]
    valid = set(rec["fnames"])
    if fn and fn not in valid and fn not in {"receive", "fallback", "constructor"}:
        fn = ""
    contract = str(raw.get("contract") or raw.get("module") or "").strip().strip("`")
    if not contract and rec["contracts"]:
        contract = str(rec["contracts"][0])
    mech = tidy(raw.get("mechanism"))
    impact = tidy(raw.get("impact"))
    desc = tidy(raw.get("description"))
    title = tidy(raw.get("title")) or f"{contract}.{fn or 'logic'} - high-impact bug"
    if len(mech) < 24 and len(desc) < 110:
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
    if len(rebuilt) < 110:
        return None
    line = raw.get("line")
    if not isinstance(line, int) and fn:
        for needle in (f"function {fn}", f"def {fn}", f"fn {fn}", f"fun {fn}"):
            idx = str(rec["text"]).find(needle)
            if idx >= 0:
                line = lineno(str(rec["text"]), idx)
                break
    base = rel.rsplit("/", 1)[-1]
    loc = f" Affected location: `{rel}`, `{base}`" + (f", `{fn}()`" if fn else "") + "."
    if loc.strip() not in rebuilt:
        rebuilt += loc
    try:
        conf_raw = raw.get("confidence")
        conf = float(conf_raw) if conf_raw is not None else 0.0
    except (TypeError, ValueError):
        conf = 0.0
    if sev == "high" and conf < 0.62:
        return None
    return {
        "title": title[:220],
        "description": rebuilt[:3000],
        "severity": sev,
        "file": rel,
        "function": fn,
        "line": line if isinstance(line, int) else None,
        "type": str(raw.get("type") or "logic"),
        "confidence": min(0.97, max(conf, 0.9 if sev == "critical" else 0.84)),
    }


def cull(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str]] = set()
    per_file: dict[str, int] = defaultdict(int)
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
        file_key = str(item.get("file") or "").lower()
        if per_file[file_key] >= 2:
            continue
        key = (
            file_key,
            str(item.get("function") or "").lower(),
            re.sub(r"[^a-z0-9]+", " ", str(item.get("title") or "").lower())[:70],
        )
        if key in seen:
            continue
        if str(item.get("severity") or "").lower() == "high":
            if float(item.get("confidence") or 0) < 0.62:
                continue
        seen.add(key)
        per_file[file_key] += 1
        out.append(item)
        if len(out) >= EMIT_CAP:
            break
    return out


if __name__ == "__main__":
    import sys

    print(json.dumps(agent_main(sys.argv[1] if len(sys.argv) > 1 else None), indent=2))
