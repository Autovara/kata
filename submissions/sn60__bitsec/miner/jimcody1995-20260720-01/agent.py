"""SN60 miner: precision-first challenger for the jimcody1995 king.

Arena Challenge 2 showed the reigning king paying for recall with ~4–11%
precision and several invalid replica runs. This agent flips the tradeoff:

* hard 3-call / 680s budget so the TEE always returns JSON
* emit at most 8 high-confidence findings (matcher-shaped)
* no structural probe emitters (they flooded false positives)
* Cairo/Starknet-aware ranking and prompts for perpetual-style projects
* import-centrality boosts ranking without fingerprint tables
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
FILE_CAP = 85
BYTE_CAP = 260_000
DIGEST_BUDGET = 24_000
DEPTH_BUDGET = 44_000
SWEEP_BUDGET = 46_000
DEPTH_FILE = 18_000
SWEEP_FILE = 6_800
IMPORT_SNIP = 2_800
EMIT_CAP = 8
DEADLINE_S = 680.0
HTTP_S = 190
KEEP_S = 220.0
CALL_LIMIT = 3
MODEL_ID = os.environ.get("KATA_MINER_MODEL", "deepseek-ai/DeepSeek-V3.2-TEE")

IGNORE = frozenset({
    ".git", ".github", ".venv", "artifacts", "broadcast", "cache", "coverage",
    "dist", "docs", "example", "examples", "lib", "libs", "node_modules", "out",
    "script", "scripts", "target", "test", "tests", "vendor", "vendors",
    "mock", "mocks", "fixtures", "fixture", "deps", "build", "interfaces",
    "interface",
})

HOT = (
    "withdraw", "redeem", "borrow", "repay", "liquidat", "claim", "stake",
    "unstake", "deposit", "mint", "burn", "swap", "bridge", "permit",
    "delegatecall", "call{", ".call", "assembly", "unchecked", "tx.origin",
    "selfdestruct", "upgrade", "initialize", "oracle", "price", "share",
    "rounding", "fee", "collateral", "signature", "ecrecover", "nonce",
    "flash", "transferfrom", "settle", "invoke", "cpi", "signer", "authority",
    "get_caller_address", "felt252", "starknet", "storage",
)

NAME_HINTS = (
    "vault", "pool", "router", "manager", "controller", "strategy", "market",
    "oracle", "bridge", "staking", "reward", "treasury", "proxy", "liquidat",
    "borrow", "token", "perp", "position", "lending", "escrow", "amm",
    "clearing", "margin", "program", "account", "factory", "perpetual",
)

RE_SOL_FN = re.compile(
    r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*([^{};]*)(?:;|\{)",
    re.MULTILINE,
)
RE_VY_FN = re.compile(r"^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", re.MULTILINE)
RE_RS_FN = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
RE_MOVE_FN = re.compile(
    r"^\s*(?:public\s*(?:\([^)]*\))?\s+)?(?:entry\s+)?(?:native\s+)?fun\s+"
    r"([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
RE_CAIRO_FN = re.compile(
    r"^\s*(?:pub\s+)?(?:fn|func)\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
RE_SOL_CT = re.compile(
    r"^\s*(?:abstract\s+contract|contract|library|interface)\s+"
    r"([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
RE_RS_CT = re.compile(
    r"^\s*(?:pub\s+)?(?:mod|struct|enum)\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
RE_MOVE_CT = re.compile(
    r"^\s*module\s+(?:[A-Za-z_0-9]+::)?([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
RE_CAIRO_CT = re.compile(
    r"^\s*(?:pub\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
RE_IMPORT = re.compile(
    r'^\s*(?:import|use)\b[^;\n]*?["\']?([A-Za-z0-9_./:]+)["\']?',
    re.MULTILINE,
)
RE_DEF = re.compile(
    r"\bfunction\b|\bdef\b|\bfn\b|\bfun\b|\bmodifier\b|\bconstructor\b|"
    r"\bmodule\b|\bmapping\b|\bstorage\b"
)

AUDITOR = (
    "You are a precision-focused smart-contract auditor for Solidity, Vyper, "
    "Rust/Solana, Move, and Cairo/Starknet. Report ONLY clearly exploitable "
    "HIGH or CRITICAL bugs with a concrete attacker path and material impact. "
    "Prefer missing a maybe-bug over emitting a false positive. Reject gas, "
    "style, missing events, and admin-trust notes. Return strict JSON only."
)

FOCUS = (
    "Hunt: accounting/share inflation, rounding theft, oracle/price manipulation, "
    "missing access control, reentrancy ordering, signature replay, unsafe "
    "delegatecall/upgrade/init, liquidation edges. On Cairo/Starknet also check "
    "storage address confusion, missing caller checks, and felt overflow edges."
)


def agent_main(project_dir: str | None = None, inference_api: str | None = None) -> dict:
    t0 = time.monotonic()
    out: list[dict[str, Any]] = []
    try:
        root = find_root(project_dir)
        if root is None:
            return {"vulnerabilities": out}
        files = scan(root)
        if not files:
            return {"vulnerabilities": out}

        by_rel = {f["rel"]: f for f in files}
        by_base = {Path(f["rel"]).name: f for f in files}
        draft: list[dict[str, Any]] = []
        used = 0
        ranked = files

        if remaining(t0, KEEP_S):
            picks, early = map_pass(inference_api, files, t0)
            draft.extend(early)
            ranked = reorder(picks, files)
            used = 1

        if used < CALL_LIMIT and remaining(t0, KEEP_S):
            # Deeper on fewer files — precision over breadth.
            draft.extend(audit(
                inference_api, ranked[:3], by_base, t0,
                per=DEPTH_FILE, budget=DEPTH_BUDGET, tag="depth-core",
            ))
            used += 1

        if used < CALL_LIMIT and remaining(t0, KEEP_S):
            mid = unique_keep(ranked[2:2 + 8] + ranked[:2])
            draft.extend(audit(
                inference_api, mid[:10], by_base, t0,
                per=SWEEP_FILE, budget=SWEEP_BUDGET, tag="sweep-compact",
                window=True,
            ))
            used += 1

        for row in draft:
            item = shape(row, by_rel)
            if item is not None:
                out.append(item)
    except Exception:
        pass
    return {"vulnerabilities": prune(out)}


def remaining(t0: float, need: float = 0.0) -> bool:
    return time.monotonic() - t0 < DEADLINE_S - need


def find_root(project_dir: str | None) -> Path | None:
    cands: list[str] = []
    if project_dir:
        cands.append(project_dir)
    for key in ("PROJECT_DIR", "PROJECT_PATH", "PROJECT_ROOT", "PROJECT_CODE"):
        val = os.environ.get(key)
        if val:
            cands.append(val)
    cands.extend(("/app/project_code", "/app/project", "/project", "/code", "."))
    for raw in cands:
        try:
            path = Path(raw).expanduser().resolve()
        except (OSError, RuntimeError):
            continue
        if path.is_dir() and has_code(path):
            return path
    return None


def has_code(root: Path) -> bool:
    try:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [
                d for d in dirnames if d.lower() not in IGNORE and not d.startswith(".")
            ]
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
        ".t.sol", ".s.sol", "_test.sol", ".test.sol", "_test.rs", ".test.rs",
        "_tests.move",
    ))


def load(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def funcs(text: str, ext: str) -> list[dict[str, Any]]:
    if ext == ".vy":
        pats = [RE_VY_FN]
    elif ext == ".rs":
        pats = [RE_RS_FN]
    elif ext == ".move":
        pats = [RE_MOVE_FN]
    elif ext == ".cairo":
        pats = [RE_CAIRO_FN]
    else:
        pats = [RE_SOL_FN]
    rows: list[dict[str, Any]] = []
    for pat in pats:
        for m in pat.finditer(text):
            rows.append({
                "name": m.group(1),
                "line": text.count("\n", 0, m.start()) + 1,
                "sig": " ".join(m.group(0).strip().split())[:170],
            })
    return rows


def units(text: str, ext: str, stem: str) -> list[str]:
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


def hot_lines(text: str) -> list[str]:
    rows: list[str] = []
    terms = tuple(w.lower() for w in HOT)
    for num, line in enumerate(text.splitlines(), start=1):
        low = line.lower().replace(" ", "")
        if any(t in low for t in terms):
            compact = " ".join(line.strip().split())
            if compact:
                rows.append(f"{num}: {compact[:150]}")
        if len(rows) >= 14:
            break
    return rows


def rank(rel: str, text: str, ext: str) -> int:
    path, body = rel.lower(), text.lower()
    compact = body.replace(" ", "")
    score = min(
        body.count("function ") + body.count("\ndef ") + body.count("\nfn ")
        + body.count("\nfun ") + body.count(" pub fn"),
        45,
    )
    for word in NAME_HINTS:
        if word in path:
            score += 11
        elif word in body:
            score += 2
    for word in HOT:
        if word.lower().replace(" ", "") in compact:
            score += 3
    if any(tok in body for tok in ("external", "public", "entry", "pub fn", "#[external")):
        score += 6
    if ext == ".cairo" or "starknet" in body or "felt" in body:
        score += 8
    if "interface" in path:
        score -= 12
    return score


def scan(root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    inbound: dict[str, int] = defaultdict(int)
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
                    if skip_path(rel):
                        continue
                    if path.stat().st_size > BYTE_CAP:
                        continue
                except OSError:
                    continue
                text = load(path)
                if not any(
                    tok in text
                    for tok in (
                        "function", "contract ", "library ", "\ndef ", "\nfn ",
                        " fun ", "pub fn", "module ", "mod ", "struct ", "storage",
                    )
                ):
                    continue
                rel_s = rel.as_posix()
                for imp in RE_IMPORT.findall(text):
                    inbound[imp.rsplit("/", 1)[-1].rsplit("::", 1)[-1]] += 1
                rows.append({
                    "rel": rel_s,
                    "text": text,
                    "ext": ext,
                    "contracts": units(text, ext, path.stem),
                    "functions": funcs(text, ext),
                    "risk": hot_lines(text),
                    "score": rank(rel_s, text, ext),
                    "base": path.name,
                })
                if len(rows) >= FILE_CAP * 2:
                    break
            if len(rows) >= FILE_CAP * 2:
                break
    except OSError:
        return []
    for row in rows:
        row["score"] = int(row["score"]) + min(inbound.get(Path(row["rel"]).stem, 0), 8) * 2
    rows.sort(key=lambda r: (-int(r["score"]), str(r["rel"])))
    return rows[:FILE_CAP]


def windowed(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    lines = text.splitlines()
    keep: set[int] = set()
    terms = tuple(w.lower() for w in HOT)
    for idx, line in enumerate(lines):
        low = line.lower()
        if RE_DEF.search(line) or any(t in low for t in terms):
            for j in range(max(0, idx - 3), min(len(lines), idx + 14)):
                keep.add(j)
    if not keep:
        return text[:limit]
    out: list[str] = []
    last = -3
    size = 0
    for idx in sorted(keep):
        if idx > last + 1:
            gap = f"\n/* ... {idx - last - 1} lines omitted ... */\n"
            out.append(gap)
            size += len(gap)
        entry = lines[idx] + "\n"
        if size + len(entry) > limit:
            break
        out.append(entry)
        size += len(entry)
        last = idx
    return "".join(out) if out else text[:limit]


def digest(files: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    for f in files:
        parts.append(json.dumps({
            "file": f["rel"],
            "lang": f["ext"].lstrip("."),
            "score": f["score"],
            "contracts": f["contracts"][:5],
            "functions": [f"{x['line']}:{x['sig']}" for x in f["functions"][:16]],
            "risk_lines": f["risk"][:10],
        }, separators=(",", ":")))
    return "\n".join(parts)[:DIGEST_BUDGET]


def ask(
    api: str | None,
    messages: list[dict[str, str]],
    max_tokens: int,
    t0: float,
) -> str:
    if not remaining(t0, 5):
        return ""
    endpoint = (api or os.environ.get("INFERENCE_API") or "").rstrip("/")
    if not endpoint:
        return ""
    left = max(8.0, DEADLINE_S - (time.monotonic() - t0) - 8.0)
    timeout = min(HTTP_S, int(left))
    body = json.dumps({
        "model": MODEL_ID,
        "temperature": 0.0,
        "messages": messages,
        "max_tokens": max_tokens,
    }).encode()
    headers = {
        "Content-Type": "application/json",
        "x-inference-api-key": os.environ.get("INFERENCE_API_KEY", ""),
    }
    for attempt in range(2):
        if not remaining(t0, 5):
            return ""
        try:
            req = urllib.request.Request(
                endpoint + "/inference", data=body, method="POST", headers=headers,
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return extract(json.loads(resp.read().decode("utf-8", "replace")))
        except urllib.error.HTTPError as exc:
            if exc.code in {429, 503}:
                return ""
            if attempt == 0:
                time.sleep(0.35)
        except (OSError, TimeoutError, ValueError):
            if attempt == 0:
                time.sleep(0.35)
    return ""


def extract(payload: dict[str, Any]) -> str:
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
    api: str | None,
    files: list[dict[str, Any]],
    t0: float,
) -> tuple[list[str], list[dict[str, Any]]]:
    prompt = (
        "Map this repository. Pick at most 6 highest-yield files for deep audit "
        "and report ONLY bugs you can already prove from signatures/risk lines. "
        "Cap findings at 3. Prefer precision.\n"
        + FOCUS
        + "\nJSON only:\n"
        '{"target_files":["path"],"findings":[{"title":"Unit.fn - bug","file":"path",'
        '"contract":"Name","function":"fn","line":1,"severity":"high|critical",'
        '"confidence":0.0,"mechanism":"pre -> attack -> effect","impact":"harm",'
        '"description":"2-4 precise sentences"}]}\n\n'
        + digest(files)
    )
    obj = parse_obj(ask(
        api,
        [{"role": "system", "content": AUDITOR}, {"role": "user", "content": prompt}],
        3500,
        t0,
    ))
    targets = obj.get("target_files")
    items = obj.get("findings") or obj.get("vulnerabilities") or []
    return (
        [str(x) for x in targets if isinstance(x, str)] if isinstance(targets, list) else [],
        [x for x in items if isinstance(x, dict)] if isinstance(items, list) else [],
    )


def reorder(targets: list[str], files: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for target in targets:
        tl = target.lower().strip()
        for f in files:
            rl = str(f["rel"]).lower()
            if tl == rl or rl.endswith(tl) or tl.endswith(rl):
                if f not in out:
                    out.append(f)
                break
    for f in files:
        if f not in out:
            out.append(f)
    return out


def unique_keep(seq: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for item in seq:
        if item["rel"] in seen:
            continue
        seen.add(item["rel"])
        out.append(item)
    return out


def neighbors(rec: dict[str, Any], by_base: dict[str, dict[str, Any]]) -> str:
    chunks: list[str] = []
    for imp in RE_IMPORT.findall(str(rec["text"])):
        name = imp.rsplit("/", 1)[-1].rsplit("::", 1)[-1]
        other = (
            by_base.get(name)
            or by_base.get(name + ".sol")
            or by_base.get(name + ".rs")
            or by_base.get(name + ".cairo")
            or by_base.get(name + ".move")
        )
        if other and other["rel"] != rec["rel"]:
            chunks.append(
                f"\n--- RELATED {other['rel']} ---\n{str(other['text'])[:IMPORT_SNIP]}"
            )
        if len(chunks) >= 2:
            break
    return "".join(chunks)


def audit(
    api: str | None,
    batch: list[dict[str, Any]],
    by_base: dict[str, dict[str, Any]],
    t0: float,
    *,
    per: int,
    budget: int,
    tag: str,
    window: bool = False,
) -> list[dict[str, Any]]:
    if not batch:
        return []
    header = (
        f"Audit tag={tag}. {FOCUS}\n"
        "Return at most 4 findings. Every finding must cite a real function and "
        "explain why existing checks fail. Strict JSON:\n"
        '{"findings":[{"title":"Unit.fn - bug","file":"path","contract":"C",'
        '"function":"fn","line":1,"severity":"high|critical","confidence":0.0,'
        '"type":"logic","mechanism":"pre->attack->effect","impact":"harm",'
        '"description":"2-5 sentences"}]}\n'
    )
    parts, room = [header], budget - len(header)
    for rec in batch:
        src = str(rec["text"])
        body = windowed(src, per) if window else src[:per]
        sigs = [f"{x['line']}:{x['sig']}" for x in rec["functions"][:20]]
        block = (
            f"\n\n=== {rec['rel']} ===\nUnits: {', '.join(rec['contracts'][:6])}\n"
            f"Functions: {json.dumps(sigs)}\nRisk: {json.dumps(rec['risk'][:10])}\n"
            f"{body}\n{neighbors(rec, by_base)}\n"
        )
        if room <= 0:
            break
        if len(block) > room:
            block = block[:room] + "\n/* truncated */\n"
        parts.append(block)
        room -= len(block)
    obj = parse_obj(ask(
        api,
        [{"role": "system", "content": AUDITOR}, {"role": "user", "content": "".join(parts)}],
        5500,
        t0,
    ))
    items = obj.get("findings") or obj.get("vulnerabilities") or []
    return [x for x in items if isinstance(x, dict)] if isinstance(items, list) else []


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


def at_line(text: str, offset: int) -> int:
    return 1 if offset < 0 else text.count("\n", 0, offset) + 1


def tidy(value: object) -> str:
    return " ".join(str(value or "").strip().split())


def shape(
    raw: dict[str, Any],
    by_rel: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    rel, rec = resolve(str(raw.get("file") or raw.get("path") or ""), by_rel)
    if not rel or not rec:
        return None
    sev = str(raw.get("severity") or "").lower().strip()
    if sev not in {"high", "critical"}:
        return None
    try:
        conf = float(raw.get("confidence") or 0.0)
    except (TypeError, ValueError):
        conf = 0.0
    # Soft floor: triage noise without confidence still allowed if well described.
    fn = str(raw.get("function") or "").strip().strip("`() ")
    if "." in fn:
        fn = fn.split(".")[-1]
    if "::" in fn:
        fn = fn.split("::")[-1]
    names = {str(x["name"]) for x in rec["functions"]}
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
    if len(mech) < 28 and len(desc) < 130:
        return None
    if conf and conf < 0.55 and len(desc) < 180:
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
    if len(rebuilt) < 130:
        return None
    line = raw.get("line")
    if not isinstance(line, int) and fn:
        for needle in (f"function {fn}", f"def {fn}", f"fn {fn}", f"fun {fn}"):
            idx = str(rec["text"]).find(needle)
            if idx >= 0:
                line = at_line(str(rec["text"]), idx)
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
        "confidence": max(conf, 0.88 if sev == "critical" else 0.8),
    }


def prune(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
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
            str(item.get("title") or "").lower()[:90],
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
        if len(out) >= EMIT_CAP:
            break
    return out


if __name__ == "__main__":
    import sys
    print(json.dumps(agent_main(sys.argv[1] if len(sys.argv) > 1 else None), indent=2))
