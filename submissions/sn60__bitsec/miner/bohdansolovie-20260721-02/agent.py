from __future__ import annotations

"""SN60 challenger vs king jimcody1995-20260721-02 (#170).

#170 won on project-pass but still burned 3 invalid runs. This agent keeps the
triage → deep → wide pipeline while tightening the runtime envelope and emit
filters so replicas finish cleanly and precision stays high enough to pass
promotion order against the king's reign average.
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
MAX_BYTES = 270_000
MAP_CHARS = 28_000
DEEP_BUDGET = 44_000
WIDE_BUDGET = 42_000
PER_DEEP = 14_500
PER_WIDE = 6_400
RELATED = 2_800
MAX_FINDINGS = 12
RUN_CAP = 690.0
HTTP_TIMEOUT = 195
RESERVE = 250.0
MAX_CALLS = 3
DEEP_N = 4
WIDE_N = 10
MODEL = os.environ.get("KATA_MINER_MODEL", "deepseek-ai/DeepSeek-V3.2-TEE")

SKIP = frozenset({
    ".git", ".github", ".venv", "artifacts", "broadcast", "cache", "coverage",
    "dist", "docs", "example", "examples", "lib", "libs", "node_modules", "out",
    "script", "scripts", "target", "test", "tests", "vendor", "vendors", "mock",
    "mocks", "fixtures", "fixture", "deps", "build", "interfaces", "interface",
    "generated", "bindings",
})

NAME_HITS = (
    "vault", "pool", "router", "manager", "controller", "strategy", "market",
    "oracle", "bridge", "staking", "reward", "treasury", "govern", "proxy",
    "liquidat", "borrow", "token", "perp", "position", "lending", "escrow",
    "auction", "amm", "pair", "adapter", "clearing", "margin", "program",
    "module", "account", "factory", "engine", "gateway", "portal",
)

RISK_HITS = (
    "delegatecall", ".call{", "selfdestruct", "tx.origin", "assembly",
    "ecrecover", "permit", "signature", "nonce", "initialize", "upgrade",
    "onlyowner", "onlyrole", "mint", "burn", "withdraw", "redeem", "deposit",
    "borrow", "repay", "liquidat", "collateral", "share", "totalsupply",
    "oracle", "getprice", "latestround", "slot0", "flash", "swap", "claim",
    "unchecked", "transferfrom", "approve", "settle", "rebalance", "invoke",
    "cpi", "signer", "authority", "lamports", "borrow_global", "move_to",
    "capability", "get_caller_address", "felt", "starknet", "msg.sender",
)

SOL_FN = re.compile(
    r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*([^{};]*)(?:;|\{)",
    re.MULTILINE,
)
SOL_SPECIAL = re.compile(r"\b(constructor|receive|fallback)\b\s*\(")
VY_FN = re.compile(r"^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", re.MULTILINE)
RS_FN = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
MOVE_FN = re.compile(
    r"^\s*(?:public\s*(?:\([^)]*\))?\s+)?(?:entry\s+)?(?:native\s+)?fun\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
CAIRO_FN = re.compile(r"^\s*(?:pub\s+)?(?:fn|func)\s+([A-Za-z_][A-Za-z0-9_]*)", re.MULTILINE)
SOL_CT = re.compile(
    r"^\s*(?:abstract\s+contract|contract|library|interface)\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
RS_CT = re.compile(r"^\s*(?:pub\s+)?(?:mod|struct|enum)\s+([A-Za-z_][A-Za-z0-9_]*)", re.MULTILINE)
MOVE_CT = re.compile(r"^\s*module\s+(?:[A-Za-z_0-9]+::)?([A-Za-z_][A-Za-z0-9_]*)", re.MULTILINE)
CAIRO_CT = re.compile(r"^\s*(?:pub\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)", re.MULTILINE)
IMPORT_RE = re.compile(r'^\s*(?:import|use)\b[^;\n]*?["\']?([A-Za-z0-9_./:]+)["\']?', re.MULTILINE)
DEF_RE = re.compile(
    r"\bfunction\b|\bdef\b|\bfn\b|\bfun\b|\bmodifier\b|\bconstructor\b|\bmodule\b|\bmapping\b"
)

SYSTEM = (
    "You are a careful smart-contract security auditor (Solidity, Vyper, Rust/"
    "Solana, Move, Cairo). Report only REAL exploitable HIGH/CRITICAL bugs with "
    "concrete attacker steps and material impact, pinned to exact file+function. "
    "Skip gas, style, missing events, and admin-trust-by-design. Prefer fewer "
    "well-evidenced findings over speculative lists. Return strict JSON only."
)

SCHEMA = (
    '{"findings":[{"title":"Contract.fn - bug","file":"path","contract":"Name",'
    '"function":"fn","severity":"high|critical","confidence":0.0,'
    '"mechanism":"pre -> attack -> effect","impact":"funds/privilege/insolvency",'
    '"description":"2-4 sentences with exploit path"}]}'
)

FOCUS = (
    "Hunt: accounting/share inflation, first-depositor/rounding, oracle/price "
    "manipulation in value math, missing auth on privileged writes, reentrancy/"
    "callback ordering, signature replay, init/upgrade seizure, liquidation/"
    "withdrawal edges. Rust/Move/Cairo: missing signer/authority and account "
    "ownership confusion. Prefer bugs that definitely move value or seize control."
)

TRANSIENT = frozenset({408, 409, 425, 429, 500, 502, 503, 504, 520, 522, 524, 529})


def agent_main(project_dir: str | None = None, inference_api: str | None = None) -> dict:
    started = time.monotonic()
    out: list[dict[str, Any]] = []
    try:
        root = resolve_root(project_dir)
        if root is None:
            return {"vulnerabilities": out}
        records = discover(root)
        if not records:
            return {"vulnerabilities": out}

        rel_map = {r["rel"]: r for r in records}
        by_base: dict[str, dict[str, Any]] = {}
        for r in records:
            by_base.setdefault(Path(str(r["rel"])).name, r)

        raw: list[dict[str, Any]] = []
        ordered = records
        calls = 0

        if left(started, RESERVE):
            targets, hits = triage(inference_api, records, started)
            raw.extend(hits)
            ordered = reorder(records, targets)
            calls = 1

        if calls < MAX_CALLS and left(started, RESERVE):
            raw.extend(audit(
                inference_api, ordered[:DEEP_N], by_base, started,
                mode="deep-value-path", per_file=PER_DEEP, budget=DEEP_BUDGET,
                compact=False,
            ))
            calls += 1

        if calls < MAX_CALLS and left(started, RESERVE):
            wide = diversify(ordered, ordered[:DEEP_N], limit=WIDE_N)
            raw.extend(audit(
                inference_api, wide, by_base, started,
                mode="wide-risk-window", per_file=PER_WIDE, budget=WIDE_BUDGET,
                compact=True,
            ))
            calls += 1

        raw.extend(probes(records))

        for item in raw:
            norm = normalize(item, rel_map)
            if norm is not None:
                out.append(norm)
    except Exception:
        pass
    return {"vulnerabilities": dedupe(out)}


def left(started: float, need: float = 0.0) -> bool:
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
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d.lower() not in SKIP and not d.startswith(".")]
            for name in filenames:
                if Path(name).suffix.lower() in EXTS:
                    return True
    except OSError:
        return False
    return False


def skip_rel(rel: Path) -> bool:
    for part in rel.parts[:-1]:
        low = part.lower()
        if low in SKIP or low.startswith("."):
            return True
    name = rel.name.lower()
    return name.endswith((
        ".t.sol", ".s.sol", "_test.sol", ".test.sol", "_test.rs", ".test.rs", "_tests.move",
    ))


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def parse_funcs(text: str, ext: str) -> list[dict[str, Any]]:
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
                "sig": " ".join(m.group(0).strip().split())[:180],
            })
    if ext == ".sol":
        for m in SOL_SPECIAL.finditer(text):
            out.append({
                "name": m.group(1),
                "line": text.count("\n", 0, m.start()) + 1,
                "sig": m.group(1),
            })
    return out


def contracts(text: str, ext: str, stem: str) -> list[str]:
    if ext == ".rs":
        found = RS_CT.findall(text)
    elif ext == ".move":
        found = MOVE_CT.findall(text)
    elif ext == ".cairo":
        found = CAIRO_CT.findall(text)
    else:
        found = SOL_CT.findall(text)
    seen: list[str] = []
    for name in found:
        if name not in seen:
            seen.append(name)
    return seen or [stem]


def risk_lines(text: str) -> list[str]:
    lines: list[str] = []
    terms = tuple(w.lower() for w in RISK_HITS)
    for num, line in enumerate(text.splitlines(), start=1):
        low = line.lower().replace(" ", "")
        if any(t.replace(" ", "") in low for t in terms):
            compact = " ".join(line.strip().split())
            if compact:
                lines.append(f"{num}: {compact[:160]}")
        if len(lines) >= 16:
            break
    return lines


def score_file(rel: str, text: str, ext: str, nfuncs: int) -> float:
    ln, body = rel.lower(), text.lower()
    compact = body.replace(" ", "")
    score = float(min(nfuncs, 48))
    for w in NAME_HITS:
        if w in ln:
            score += 11
        elif w in body:
            score += 2
    for w in RISK_HITS:
        score += min(compact.count(w.lower().replace(" ", "")), 5) * 2.8
    if any(t in body for t in ("external", "public", "entry", "pub fn", "#[external")):
        score += 7
    if "delegatecall" in compact:
        score += 10
    if ext == ".sol" and "contract " not in body and "library " not in body:
        score *= 0.22
    stem = Path(rel).stem.lower()
    parts = [p.lower() for p in Path(rel).parts]
    if stem.startswith("test_") or "test" in parts or any(p in ("mock", "mocks") for p in parts):
        score *= 0.1
    if "interface" in stem:
        score *= 0.3
    return score


def discover(root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d.lower() not in SKIP and not d.startswith(".")]
            for fname in filenames:
                path = Path(dirpath) / fname
                ext = path.suffix.lower()
                if ext not in EXTS:
                    continue
                try:
                    rel = path.relative_to(root)
                    if skip_rel(rel) or path.stat().st_size > MAX_BYTES:
                        continue
                except OSError:
                    continue
                text = read_text(path)
                if not text:
                    continue
                if ext == ".sol" and not any(x in text for x in ("function", "contract ", "library ")):
                    continue
                if ext != ".sol" and not any(x in text for x in ("fn ", "fun ", "def ", "func ")):
                    continue
                funcs = parse_funcs(text, ext)
                cts = contracts(text, ext, path.stem)
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
                    "risk": risk_lines(text),
                    "score": score_file(rel_s, text, ext, len(funcs)),
                })
                if len(rows) >= MAX_FILES * 2:
                    break
            if len(rows) >= MAX_FILES * 2:
                break
    except OSError:
        return []
    rows.sort(key=lambda r: (-float(r["score"]), str(r["rel"])))
    return rows[:MAX_FILES]


def compact_src(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    lines = text.splitlines()
    keep: set[int] = set()
    for i, line in enumerate(lines):
        low = line.lower()
        if DEF_RE.search(line) or any(t in low for t in RISK_HITS):
            for j in range(max(0, i - 4), min(len(lines), i + 15)):
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


def related(rec: dict[str, Any], by_base: dict[str, dict[str, Any]]) -> str:
    chunks: list[str] = []
    seen: set[str] = set()
    for imp in IMPORT_RE.findall(str(rec["text"])):
        base = imp.rsplit("/", 1)[-1].split("::")[-1]
        stem = base.split(".")[0]
        for cand in (base, stem, f"{stem}.sol", f"{stem}.rs"):
            other = by_base.get(cand)
            if other and other["rel"] != rec["rel"] and other["rel"] not in seen:
                seen.add(str(other["rel"]))
                chunks.append(f"\n--- RELATED {other['rel']} ---\n{str(other['text'])[:RELATED]}")
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
            "functions": [f"{f['line']}:{f['sig']}" for f in rec["functions"][:24]],
            "risk_lines": rec["risk"][:14],
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


def infer(api: str | None, messages: list[dict[str, str]], max_tokens: int, started: float) -> str:
    if not left(started, 8):
        return ""
    endpoint = (api or os.environ.get("INFERENCE_API") or "").rstrip("/")
    if not endpoint:
        return ""
    body = json.dumps({
        "model": MODEL,
        "temperature": 0.0,
        "messages": messages,
        "max_tokens": max_tokens,
    }).encode()
    headers = {
        "Content-Type": "application/json",
        "x-inference-api-key": os.environ.get("INFERENCE_API_KEY", ""),
    }
    for attempt in range(3):
        if not left(started, 8):
            return ""
        timeout = min(HTTP_TIMEOUT, max(12.0, RUN_CAP - (time.monotonic() - started) - 6))
        try:
            req = urllib.request.Request(
                endpoint + "/inference", data=body, method="POST", headers=headers,
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return pull_text(json.loads(resp.read().decode("utf-8", "replace")))
        except urllib.error.HTTPError as exc:
            if exc.code not in TRANSIENT:
                return ""
        except (OSError, TimeoutError, ValueError):
            pass
        wait = min(10.0, 1.5 * (attempt + 1))
        if not left(started, wait + 30):
            break
        time.sleep(wait)
    return ""


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
        "Triage this map. Pick deep-audit targets AND report every REAL high/critical "
        "bug already justified by signatures/risk lines. " + FOCUS + "\n"
        'STRICT JSON: {"target_files":["path"],"findings":[...]}\n' + SCHEMA
        + "\n\nMap:\n" + repo_map(records)
    )
    obj = load_json(infer(
        api,
        [{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt}],
        6000,
        started,
    ))
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
        if parent not in parents or len(chosen) < 2:
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
        f"Audit pass ({mode}). Max 6 findings. Name exact real functions. "
        "If an exploit is clear, include it — missing true bugs costs the round. "
        + FOCUS + "\nSTRICT JSON only:\n" + SCHEMA + "\n"
    )
    parts: list[str] = [header]
    room = budget - len(header)
    for rec in batch:
        body = str(rec["text"])
        if compact:
            body = compact_src(body, per_file)
        elif len(body) > per_file:
            body = body[:per_file] + "\n/* truncated */\n"
        sigs = [f"{f['line']}:{f['sig']}" for f in rec["functions"][:30]]
        block = (
            f"\n\n=== {rec['rel']} ===\nContracts: {', '.join(rec['contracts'][:6])}\n"
            f"Functions: {json.dumps(sigs)}\nRisk: {json.dumps(rec['risk'][:14])}\n"
            f"{body}\n{related(rec, by_base)}\n"
        )
        if room <= 0:
            break
        if len(block) > room:
            block = block[:room] + "\n/* truncated */\n"
        parts.append(block)
        room -= len(block)
    obj = load_json(infer(
        api,
        [{"role": "system", "content": SYSTEM}, {"role": "user", "content": "".join(parts)}],
        7500,
        started,
    ))
    items = obj.get("findings") or obj.get("vulnerabilities") or []
    return [x for x in items if isinstance(x, dict)] if isinstance(items, list) else []


def line_at(text: str, offset: int) -> int:
    return 1 if offset < 0 else text.count("\n", 0, offset) + 1


def brace_slice(text: str, start: int) -> str:
    open_i = text.find("{", start)
    if open_i < 0:
        return text[start : start + 700]
    depth = 0
    for i in range(open_i, min(len(text), open_i + 5500)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return text[start : start + 1200]


def fn_slices(text: str) -> list[dict[str, Any]]:
    marks = [(m.start(), m.group(1), " ".join(m.group(0).split())) for m in SOL_FN.finditer(text)]
    for m in SOL_SPECIAL.finditer(text):
        marks.append((m.start(), m.group(1), m.group(1)))
    marks.sort(key=lambda x: x[0])
    out: list[dict[str, Any]] = []
    for i, (pos, name, sig) in enumerate(marks):
        end = marks[i + 1][0] if i + 1 < len(marks) else len(text)
        out.append({
            "name": name,
            "sig": sig,
            "body": text[pos:end],
            "line": line_at(text, pos),
        })
    return out


def hit(
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
        "confidence": 0.88,
        "mechanism": mechanism,
        "impact": impact,
        "description": (
            f"In `{rec['rel']}`"
            + (f", function `{function}`" if function else "")
            + f". Mechanism: {mechanism.rstrip('.')}. Impact: {impact.rstrip('.')}."
        ),
    }


def probes(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """High-precision Solidity smell detectors — supplements only."""
    hits: list[dict[str, Any]] = []
    for rec in records:
        if rec["ext"] != ".sol":
            continue
        text = str(rec["text"])
        low = text.lower()
        if "contract " not in low and "library " not in low:
            continue

        for m in re.finditer(r"\breceive\s*\(\s*\)\s*external\s+payable\s*\{", text):
            body = brace_slice(text, m.start()).lower()
            if ("stake(" in body or "deposit(" in body) and "msg.sender" not in body:
                hits.append(hit(
                    rec, "Payable receive auto-stakes native transfers", "accounting",
                    "The payable receive hook stakes or deposits every native transfer "
                    "without distinguishing protocol returns from user deposits",
                    "Returned native funds can be restaked immediately, locking liquidity "
                    "and corrupting withdrawal accounting",
                    function="receive", line=line_at(text, m.start()),
                ))
                break

        if "function initialize" in low and not any(
            x in low for x in ("initializer", "onlyowner", "onlyrole", "_disableinitializers")
        ):
            hits.append(hit(
                rec, "Unprotected initializer", "access-control",
                "The initialize entrypoint is externally reachable without a one-time "
                "initializer modifier or owner/role gate",
                "An attacker can seize ownership or critical configuration on first call",
                function="initialize" if "initialize" in rec["fnames"] else "",
            ))

        if "tx.origin" in low:
            hits.append(hit(
                rec, "Authorization relies on tx.origin", "access-control",
                "A security branch authenticates with tx.origin rather than msg.sender",
                "Phishing contracts can bypass checks and act as the victim",
                line=line_at(text, low.find("tx.origin")),
            ))

        for fn in fn_slices(text):
            body, sig, name = fn["body"].lower(), fn["sig"].lower(), fn["name"]
            if "delegatecall" in body and ("external" in sig or "public" in sig):
                if not any(g in sig + body for g in ("onlyowner", "onlyrole", "requiresauth")):
                    hits.append(hit(
                        rec, "Unprotected delegatecall in external entrypoint", "access-control",
                        "An external function performs delegatecall without a hard owner/role gate",
                        "Callers can execute attacker logic in the contract storage context",
                        function=name, line=fn["line"],
                    ))
            if ("external" in sig or "public" in sig) and "nonreentrant" not in sig + body:
                call_m = re.search(r"\.call\s*\{|\.call\(|transfer\(|safetransfer", body)
                write_m = re.search(r"\b(balances?|shares?|deposits?|allowances?|total)\b.*=", body)
                if call_m and write_m and call_m.start() < write_m.start():
                    hits.append(hit(
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
                    hits.append(hit(
                        rec, "Signature path lacks replay / freshness binding", "signature",
                        "Signature recovery accepts a signer without nonce, deadline, or chain id binding",
                        "Valid signatures can be replayed across time or deployments",
                        function=name, line=fn["line"],
                    ))
        if len(hits) >= 6:
            break
    return hits[:6]


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
    mech = clean(raw.get("mechanism"))
    impact = clean(raw.get("impact"))
    desc = clean(raw.get("description"))
    title = clean(raw.get("title")) or f"{contract}.{fn or 'logic'} - high-impact bug"
    if len(mech) < 22 and len(desc) < 100:
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
    if len(rebuilt) < 100:
        return None
    line = raw.get("line")
    if not isinstance(line, int) and fn:
        for needle in (f"function {fn}", f"def {fn}", f"fn {fn}", f"fun {fn}"):
            idx = str(rec["text"]).find(needle)
            if idx >= 0:
                line = line_at(str(rec["text"]), idx)
                break
    base = rel.rsplit("/", 1)[-1]
    loc = f" Affected location: `{rel}`, `{base}`" + (f", `{fn}()`" if fn else "") + "."
    if loc.strip() not in rebuilt:
        rebuilt += loc
    try:
        # If the model omitted confidence, treat it as "no evidence" so we don't
        # accidentally elevate weak noise into high/critical findings.
        conf_raw = raw.get("confidence")
        conf = float(conf_raw) if conf_raw is not None else 0.0
    except (TypeError, ValueError):
        conf = 0.0

    # Precision-first gate: drop low-confidence "high" findings.
    if sev == "high" and conf < 0.60:
        return None

    return {
        "title": title[:220],
        "description": rebuilt[:3000],
        "severity": sev,
        "file": rel,
        "function": fn,
        "line": line if isinstance(line, int) else None,
        "type": str(raw.get("type") or "logic"),
        "confidence": min(0.97, conf),
    }


def dedupe(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str]] = set()
    per_file: dict[str, int] = {}
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
        if per_file.get(file_key, 0) >= 2:
            continue
        key = (
            str(item.get("file") or "").lower(),
            str(item.get("function") or "").lower(),
            re.sub(r"[^a-z0-9]+", " ", str(item.get("title") or "").lower())[:70],
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
        per_file[file_key] = per_file.get(file_key, 0) + 1
        if len(out) >= MAX_FINDINGS:
            break
    return out


if __name__ == "__main__":
    import sys

    print(json.dumps(agent_main(sys.argv[1] if len(sys.argv) > 1 else None), indent=2))
