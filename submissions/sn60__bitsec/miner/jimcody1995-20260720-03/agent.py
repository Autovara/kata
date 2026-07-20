"""SN60 miner: project-pass hunter for the continuous king ladder.

Bitsec scoring: a project replica PASSES only at 100% detection.
Kata promotion order: pass score → projects passed → TPs → fewer invalids →
precision → F1, vs the king's reign average. Challenge #164 lost that average
bar; this agent prioritizes completing small projects and lifting TPs while
keeping invalids near zero under the Phala 840s TEE budget.
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
SCAN_LIMIT = 90
SIZE_LIMIT = 260_000
MAP_BUDGET = 32_000
DEPTH_BUDGET = 47_000
WIDE_BUDGET = 50_000
DEPTH_EACH = 15_000
WIDE_EACH = 8_200
IMPORT_SNIP = 3_000
DEPTH_N = 6
WIDE_N = 12
EMIT_LIMIT = 20
TIME_BUDGET = 735.0
HTTP_LIMIT = 195
RESERVE = 210.0
CALLS = 3
# Strong Chutes TEE model; override with KATA_MINER_MODEL if needed.
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
)

STEMS = (
    "vault", "pool", "router", "manager", "controller", "strategy", "market",
    "oracle", "bridge", "staking", "reward", "treasury", "proxy", "liquidat",
    "borrow", "token", "perp", "position", "lending", "escrow", "amm",
    "clearing", "margin", "program", "account", "factory", "perpetual",
    "pair", "adapter", "gate",
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

PERSONA = (
    "You are an elite smart-contract auditor for Solidity, Vyper, Rust/Solana, "
    "Move, and Cairo/Starknet. Report REAL exploitable HIGH or CRITICAL bugs "
    "with concrete attacker steps and material fund/privilege impact. Reject "
    "gas, style, missing events, and trusted-admin notes. Return strict JSON."
)

GOALS = (
    "Prioritize bugs that complete coverage of small codebases (aim to catch "
    "every high/critical issue present). Hunt: share/reserve accounting and "
    "first-depositor inflation, rounding theft, oracle/price manipulation, "
    "missing access control, reentrancy, signature replay, unsafe "
    "delegatecall/init/upgrade, liquidation edges. On Cairo/Starknet also "
    "check caller checks, storage address confusion, and felt overflow."
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

        raw: list[dict[str, Any]] = []
        n = 0
        order = records

        if have_time(started, RESERVE):
            targets, early = triage(inference_api, records, started)
            raw.extend(early)
            order = prioritize(targets, records)
            n = 1

        if n < CALLS and have_time(started, RESERVE):
            raw.extend(deep_audit(
                inference_api, order[:DEPTH_N], by_base, started,
                each=DEPTH_EACH, budget=DEPTH_BUDGET, label="contiguous-depth",
            ))
            n += 1

        if n < CALLS and have_time(started, RESERVE):
            wide = uniq(order[3:3 + WIDE_N] + order[:4])
            raw.extend(deep_audit(
                inference_api, wide[:WIDE_N], by_base, started,
                each=WIDE_EACH, budget=WIDE_BUDGET, label="cross-module-window",
                use_window=True,
            ))
            n += 1

        raw.extend(static_hits(records))

        for item in raw:
            shaped = shape(item, by_rel)
            if shaped is not None:
                findings.append(shaped)
        if not findings:
            for item in static_hits(records, fallback=True):
                shaped = shape(item, by_rel)
                if shaped is not None:
                    findings.append(shaped)
    except Exception:
        pass
    return {"vulnerabilities": collapse(findings)}


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


def parse_units(text: str, ext: str, stem: str) -> list[str]:
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


def risk_snip(text: str) -> list[str]:
    rows: list[str] = []
    terms = tuple(w.lower() for w in SIGNALS)
    for num, line in enumerate(text.splitlines(), start=1):
        low = line.lower().replace(" ", "")
        if any(t in low for t in terms):
            compact = " ".join(line.strip().split())
            if compact:
                rows.append(f"{num}: {compact[:155]}")
        if len(rows) >= 14:
            break
    return rows


def weight(rel: str, text: str, ext: str) -> int:
    path, body = rel.lower(), text.lower()
    compact = body.replace(" ", "")
    score = min(
        body.count("function ") + body.count("\ndef ") + body.count("\nfn ")
        + body.count("\nfun ") + body.count(" pub fn"),
        50,
    )
    for word in STEMS:
        if word in path:
            score += 11
        elif word in body:
            score += 2
    for word in SIGNALS:
        if word.lower().replace(" ", "") in compact:
            score += 3
    if any(tok in body for tok in ("external", "public", "entry", "pub fn", "#[external")):
        score += 6
    if ext in {".cairo", ".rs", ".move"} or "starknet" in body:
        score += 7
    if "interface" in path:
        score -= 12
    # Small files are easier to fully cover (project-pass hunting).
    if len(text) < 8_000 and score > 20:
        score += 6
    return score


def collect(root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    inbound: dict[str, int] = defaultdict(int)
    try:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [
                d for d in dirnames if d.lower() not in SKIP and not d.startswith(".")
            ]
            for fname in filenames:
                path = Path(dirpath) / fname
                ext = path.suffix.lower()
                if ext not in SUFFIXES:
                    continue
                try:
                    rel = path.relative_to(root)
                    if banned(rel):
                        continue
                    if path.stat().st_size > SIZE_LIMIT:
                        continue
                except OSError:
                    continue
                text = read(path)
                if not any(
                    tok in text
                    for tok in (
                        "function", "contract ", "library ", "\ndef ", "\nfn ",
                        " fun ", "pub fn", "module ", "mod ", "struct ", "storage",
                    )
                ):
                    continue
                rel_s = rel.as_posix()
                for imp in IMPORT.findall(text):
                    inbound[imp.rsplit("/", 1)[-1].rsplit("::", 1)[-1]] += 1
                rows.append({
                    "rel": rel_s,
                    "base": path.name,
                    "stem": path.stem,
                    "text": text,
                    "ext": ext,
                    "contracts": parse_units(text, ext, path.stem),
                    "functions": parse_fns(text, ext),
                    "risk": risk_snip(text),
                    "score": weight(rel_s, text, ext),
                })
                if len(rows) >= SCAN_LIMIT * 2:
                    break
            if len(rows) >= SCAN_LIMIT * 2:
                break
    except OSError:
        return []
    for row in rows:
        row["score"] = int(row["score"]) + min(inbound.get(row["stem"], 0), 8) * 2
    rows.sort(key=lambda r: (-int(r["score"]), str(r["rel"])))
    return rows[:SCAN_LIMIT]


def windowed(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    lines = text.splitlines()
    keep: set[int] = set()
    terms = tuple(w.lower() for w in SIGNALS)
    for idx, line in enumerate(lines):
        low = line.lower()
        if DEF_MARK.search(line) or any(t in low for t in terms):
            for j in range(max(0, idx - 4), min(len(lines), idx + 15)):
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


def map_blob(records: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    for r in records:
        parts.append(json.dumps({
            "file": r["rel"],
            "lang": r["ext"].lstrip("."),
            "score": r["score"],
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
    if not have_time(started, 5):
        return ""
    endpoint = (api or os.environ.get("INFERENCE_API") or "").rstrip("/")
    if not endpoint:
        return ""
    left = max(8.0, TIME_BUDGET - (time.monotonic() - started) - 8.0)
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
        if not have_time(started, 5):
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
            if attempt == 0:
                time.sleep(0.4)
        except (OSError, TimeoutError, ValueError):
            if attempt == 0:
                time.sleep(0.4)
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
    api: str | None,
    records: list[dict[str, Any]],
    started: float,
) -> tuple[list[str], list[dict[str, Any]]]:
    prompt = (
        "Repository map. (1) Pick up to 8 highest-yield files. (2) Report every "
        "HIGH/CRITICAL bug already justified by signatures/risk lines — especially "
        "on small files where full coverage is realistic.\n"
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
        6000,
        started,
    ))
    targets = obj.get("target_files")
    items = obj.get("findings") or obj.get("vulnerabilities") or []
    return (
        [str(x) for x in targets if isinstance(x, str)] if isinstance(targets, list) else [],
        [x for x in items if isinstance(x, dict)] if isinstance(items, list) else [],
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
    use_window: bool = False,
) -> list[dict[str, Any]]:
    if not batch:
        return []
    header = (
        f"Audit mode={label}. {GOALS}\n"
        "If the batch is small, list EVERY real high/critical issue — incomplete "
        "coverage fails the project. Max 7 findings. Strict JSON:\n"
        '{"findings":[{"title":"Unit.fn - bug","file":"path","contract":"C",'
        '"function":"fn","line":1,"severity":"high|critical","confidence":0.0,'
        '"type":"logic","mechanism":"pre->attack->effect","impact":"harm",'
        '"description":"2-5 sentences with exploit path"}]}\n'
    )
    parts, room = [header], budget - len(header)
    for rec in batch:
        src = str(rec["text"])
        body = windowed(src, each) if use_window else src[:each]
        sigs = [f"{f['line']}:{f['sig']}" for f in rec["functions"][:22]]
        block = (
            f"\n\n=== {rec['rel']} ===\nUnits: {', '.join(rec['contracts'][:7])}\n"
            f"Functions: {json.dumps(sigs)}\nRisk: {json.dumps(rec['risk'][:12])}\n"
            f"{body}\n{related(rec, by_base)}\n"
        )
        if room <= 0:
            break
        if len(block) > room:
            block = block[:room] + "\n/* truncated */\n"
        parts.append(block)
        room -= len(block)
    obj = as_obj(chat(
        api,
        [{"role": "system", "content": PERSONA}, {"role": "user", "content": "".join(parts)}],
        7500,
        started,
    ))
    items = obj.get("findings") or obj.get("vulnerabilities") or []
    return [x for x in items if isinstance(x, dict)] if isinstance(items, list) else []


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
        "confidence": 0.78,
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
    fallback: bool = False,
) -> list[dict[str, Any]]:
    """High-precision Solidity smell detectors — capped to protect precision."""
    out: list[dict[str, Any]] = []
    limit = 4 if fallback else 6
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
        if len(out) >= limit:
            break
    return out[:limit]


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
) -> dict[str, Any] | None:
    rel, rec = resolve(str(raw.get("file") or raw.get("path") or ""), by_rel)
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
    if len(mech) < 22 and len(desc) < 110:
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
    if len(rebuilt) < 120:
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
    return {
        "title": title[:220],
        "description": rebuilt[:3000],
        "severity": sev,
        "file": rel,
        "function": fn,
        "line": line if isinstance(line, int) else None,
        "type": str(raw.get("type") or "logic"),
        "confidence": max(conf, 0.9 if sev == "critical" else 0.84),
    }


def collapse(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
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
        if len(out) >= EMIT_LIMIT:
            break
    return out


if __name__ == "__main__":
    import sys
    print(json.dumps(agent_main(sys.argv[1] if len(sys.argv) > 1 else None), indent=2))
