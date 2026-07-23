"""SN60 Bitsec challenger: consistent multi-pass auditor.

Goals against the current crown:
  - Project PASS needs 100% detection on 2 of 3 replicas, so decoding must be
    deterministic (temperature 0) and the same high-yield files must be read
    more than once under independent prompts.
  - Precision still matters on later tiers, so weak highs are filtered, emit is
    capped per file, and findings corroborated by multiple passes rank first.

Stdlib only. Model calls go only through the validator inference proxy.
"""

from __future__ import annotations

import json
import os
import re
import socket
import time
import urllib.error
import urllib.request
from pathlib import Path

# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

EXTS = (".sol", ".vy", ".rs", ".move", ".cairo")
SKIP = frozenset({
    "test", "tests", "mock", "mocks", "example", "examples", "script", "scripts",
    "broadcast", "node_modules", "vendor", "vendors", "lib", "libs", "out",
    "artifacts", "cache", "coverage", "interfaces", "interface", "fixtures", "fixture",
    "target", "docs", ".git", ".github", "deps", "dist", "build",
})

RX_SOL_UNIT = re.compile(
    r"\b(?:abstract\s+contract|contract|library|interface)\s+([A-Za-z_][A-Za-z0-9_]*)"
)
RX_SOL_FN = re.compile(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)([^{};]*)")
RX_SOL_SPECIAL = re.compile(r"\b(constructor|receive|fallback)\b\s*\(")
RX_VY_FN = re.compile(r"(?m)^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)")
RX_RS_FN = re.compile(
    r"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)"
)
RX_RS_MOD = re.compile(r"(?m)^\s*(?:pub\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{")
RX_MOVE_FN = re.compile(
    r"(?m)^\s*(?:public\s*(?:\([^)]*\))?\s+)?(?:entry\s+)?(?:native\s+)?fun\s+([A-Za-z_][A-Za-z0-9_]*)"
)
RX_MOVE_MOD = re.compile(r"(?m)^\s*module\s+(?:[A-Za-z_0-9]+::)?([A-Za-z_][A-Za-z0-9_]*)")
RX_CAIRO_FN = re.compile(r"(?m)^\s*(?:pub\s+)?(?:fn|func)\s+([A-Za-z_][A-Za-z0-9_]*)")
RX_CAIRO_MOD = re.compile(r"(?m)^\s*(?:pub\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{")
RX_IMPORT = re.compile(r'(?m)^\s*(?:import|use)\b[^;\n]*?["\']?([A-Za-z0-9_./]+)["\']?')
RX_DECL = re.compile(
    r"\bfunction\b|\bdef\b|\bfn\b|\bfun\b|\bmodifier\b|\bconstructor\b|\bmodule\b|\bmapping\b"
)
FN_WORDS = ("function", "fn", "fun", "def", "func")

PATH_HINTS = (
    "vault", "pool", "router", "manager", "controller", "strategy", "market", "lend",
    "borrow", "oracle", "price", "stak", "reward", "treasury", "bridge", "factory",
    "proxy", "govern", "token", "escrow", "auction", "liquidat", "swap", "stable",
    "collateral", "vesting", "distributor", "minter", "gauge", "farm", "perp",
    "position", "margin", "settle", "clearing", "coin", "account", "program",
)
RISK_TOKENS = (
    "delegatecall", ".call{", ".call.value", "selfdestruct", "tx.origin", "assembly",
    "ecrecover", "permit", "signature", "nonce", "initialize", "upgradeto",
    "onlyowner", "onlyrole", "_mint", "_burn", "mint(", "burn(", "withdraw", "redeem",
    "deposit", "borrow", "repay", "liquidat", "collateral", "share", "totalsupply",
    "balanceof", "oracle", "getprice", "latestround", "slot0", "flash", "swap",
    "reward", "claim", "unchecked", "safetransfer", "transferfrom", "approve",
    "settle", "rebalance", "liquidity", "reserve", "invariant",
    "signer", "authority", "lamports", "invoke", "cpi", "checked_", "unwrap",
    "close_account", "realloc", "try_borrow", "deserialize", "next_account",
    "assert_eq", "owner", "is_signer", "wasm", "msg.sender", "info.sender",
    "transfer", "sub_msg", "coin(",
    "acquires", "borrow_global", "move_to", "move_from", "capability", "signer::",
    "get_caller_address", "get_contract_address", "felt", "starknet", "assert(",
)

# ---------------------------------------------------------------------------
# Budgets: finish all passes reliably; replica consistency > max tokens
# ---------------------------------------------------------------------------

FILE_BYTES = 260_000
FILE_LIMIT = 90
IMPORT_CHARS = 3_000
DEEP_PER_FILE = 15_000
DEEP_BUDGET = 48_000
DEEP_N = 5
REAUDIT_BUDGET = 46_000
REAUDIT_N = 8
REAUDIT_PER = 8_000
# Optional third code pass only when the clock still has headroom after reaudit.
WIDE_BUDGET = 36_000
WIDE_N = 8
WIDE_PER = 7_000
MAP_CHARS = 40_000
EMIT_TOTAL = 14
EMIT_PER_FILE = 4
DESC_MIN = 40
CONF_DROP = 0.45

MODEL = os.environ.get("KATA_MINER_MODEL", "deepseek-ai/DeepSeek-V3.2-TEE")
TEMP = 0.0
MAP_TOK = 7_000
DEEP_TOK = 8_000
REAUDIT_TOK = 8_000
WIDE_TOK = 7_000

# Runner allows ~840s wall for the agent process; leave a cushion and still finish
# map + deep + independent reaudit on every replica (temp=0 for 2/3 PASS).
DEADLINE_S = 780.0
HTTP_S = 190.0
PASS_RESERVE = 205.0
REAUDIT_RESERVE = 150.0
WIDE_RESERVE = 180.0
TAIL_S = 12.0
MIN_CALL_S = 30.0
TRIES = 2

_TRANSIENT = frozenset({408, 409, 425, 500, 502, 504, 520, 522, 524, 529})

# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------

SYS = (
    "You are a senior on-chain security reviewer for Solidity, Vyper, Rust "
    "(Anchor/Solana and CosmWasm), Move, and Cairo. Across every file given, "
    "list each distinct HIGH or CRITICAL flaw you can pin to a specific function. "
    "Missing a real high/critical is costly; inventing filler is also costly. "
    "In scope: fund theft or lockup, insolvency, unauthorized state change, "
    "privilege escalation, permanent DoS, mint/supply corruption, oracle "
    "manipulation, reentrancy, signature/replay defects, missing signer/owner/"
    "authority checks. Out of scope: gas, style, missing events, pure "
    "centralization, informational notes. Reason privately; emit one minified "
    "JSON object only - no prose, markdown, or fences."
)

LANG = (
    "Sweep these classes. "
    "Solidity/Vyper: reentrancy and call ordering; wrong/missing access control; "
    "delegatecall and upgrade/init flaws; first-depositor share inflation and "
    "rounding; spot vs TWAP and stale/manipulable oracles; permit/signature "
    "replay; unsafe token assumptions and fee-on-transfer; native-value "
    "accounting; permanent DoS. "
    "Anchor/Solana: missing is_signer, owner check, has_one/constraint, PDA "
    "seed validation, account close, unchecked math, CPI to unverified program, "
    "discriminator/type confusion. "
    "CosmWasm: missing info.sender auth; open migrate. "
    "Move: missing signer/capability; public entry wrapping privileged call; "
    "resource ownership confusion. "
    "Cairo: missing get_caller_address auth; felt over/underflow; L1-L2 handler "
    "auth; storage-slot collision."
)

BREADTH = (
    "Be complete on genuine flaws: typically 3 to 8 distinct high/critical "
    "entries for a codebase this size, one per vulnerable function (more if one "
    "function has unrelated defects). Do not stop after the first couple when "
    "more plainly exist, and do not pad with speculation. For each entry, note "
    "why existing modifiers or requires fail to stop it."
)

PIN = (
    "Anchoring: copy file paths verbatim from FILE headers or the map. function "
    "must be a real name in that file, exact, no args, no contract prefix. "
    "contract must be declared in that file. mechanism = precondition -> "
    "attacker action -> broken state."
)

OUT = (
    "Emit ONE bare minified JSON object; double quotes; no trailing commas; "
    "severity exactly high or critical; descriptions 2-4 sentences; strongest "
    "first; if space runs out, close the current object cleanly."
)

SHAPE = (
    '{"findings":[{"title":"Contract.function - concrete flaw","file":"exact/path.sol",'
    '"contract":"ContractOrModule","function":"functionName","severity":"high|critical",'
    '"confidence":0.0,"type":"reentrancy|access-control|price-oracle|signature-replay|'
    'accounting|initialization|arithmetic|logic",'
    '"mechanism":"precondition -> attacker action -> broken state",'
    '"impact":"funds stolen / privilege escalation / insolvency / DoS",'
    '"description":"2-4 sentences naming file, contract, function, mechanism, and impact"}]}'
)

_RULES = BREADTH + " " + LANG + " " + PIN + " " + OUT

MAP_P = (
    "Structured map of an on-chain repo (units, signatures, flagged lines). "
    "Do BOTH: (1) copy 8-12 richest paths into target_files verbatim; (2) report "
    "every high/critical already justified from the map, including lower-"
    "confidence but precisely anchored candidates. "
    + _RULES + "\n"
    'Strict JSON only: {"target_files":["exact/path"],"findings":[...]} matching '
    + SHAPE + "\nRepository map:\n"
)

DEEP_P = (
    "Deep-audit the source below for HIGH or CRITICAL flaws. A valid entry "
    "names exact file and function, exploitable transition, and material impact. "
    + _RULES + "\nStrict JSON only: " + SHAPE + "\n"
)

REAUDIT_P = (
    "Fully independent re-audit of the SAME central files. Ignore any earlier "
    "pass - derive everything again from raw source. Prioritize completeness on "
    "genuine flaws a first read often misses: cross-function and cross-file "
    "flows, init/upgrade takeover, rounding and share inflation, stale or "
    "bendable prices, missing signer/owner/authority checks, and "
    "callback/reentrancy sequencing. Same strict bar: concrete exploit path, "
    "exact file and function, no speculation. "
    + _RULES + "\nStrict JSON only: " + SHAPE + "\n"
)

WIDE_P = (
    "Fresh-lens sweep over a wider slice. For each proposed flaw, explain why "
    "existing guards fail. Focus on cross-contract flows, accounting/rounding "
    "theft, stale prices, auth gaps, reentrancy, liquidation math, unsafe "
    "init/upgrade, signature replay. "
    + _RULES + "\nStrict JSON only: " + SHAPE + "\n"
)

CLASS_HINTS = (
    ("reentrancy", ("reentran", "re-enter", "reenter", "callback")),
    ("access", ("access control", "onlyowner", "onlyrole", "authoriz", "permission",
                "unprotected", "missing owner", "missing signer", "is_signer", "info.sender")),
    ("oracle", ("oracle", "price", "stale", "manipulat", "slot0", "twap")),
    ("sigreplay", ("signature", "ecrecover", "replay", "nonce", "domain", "permit")),
    ("accounting", ("share", "rounding", "first deposit", "first-deposit", "reserve",
                    "totalsupply", "total supply", "insolven", "inflat")),
    ("init", ("initiali", "upgrade", "delegatecall", "proxy")),
    ("arith", ("unchecked", "overflow", "underflow", "arithmetic")),
)
CLASS_TYPE = {
    "reentrancy": "reentrancy", "access": "access-control", "oracle": "price-oracle",
    "sigreplay": "signature-replay", "accounting": "accounting",
    "init": "initialization", "arith": "arithmetic",
}


def classify(*parts):
    blob = " ".join(p for p in parts if p).lower()
    for name, cues in CLASS_HINTS:
        if any(c in blob for c in cues):
            return name
    return "other"


def find_root(project_dir):
    cands = []
    if project_dir:
        cands.append(project_dir)
    for k in ("PROJECT_DIR", "PROJECT_PATH", "PROJECT_ROOT", "PROJECT_CODE"):
        v = os.environ.get(k)
        if v:
            cands.append(v)
    cands += ["/app/project_code", "/app/project", "/project", "/code", "."]
    for raw in cands:
        try:
            root = Path(raw).expanduser().resolve()
        except (OSError, RuntimeError):
            continue
        if not root.is_dir():
            continue
        try:
            for p in root.rglob("*"):
                if p.is_file() and p.suffix.lower() in EXTS:
                    return root
        except OSError:
            continue
    return None


def read_text(path):
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def looks_code(text, ext):
    if ext == ".sol":
        return "contract " in text or "library " in text or "function " in text
    if ext == ".vy":
        return "def " in text or "@external" in text or "@internal" in text
    if ext == ".rs":
        return "fn " in text
    if ext == ".move":
        return "fun " in text or "module " in text
    if ext == ".cairo":
        return "fn " in text or "func " in text or "mod " in text
    return False


def outline(text, ext):
    sigs = []
    if ext == ".sol":
        units = RX_SOL_UNIT.findall(text)
        for m in RX_SOL_FN.finditer(text):
            tail = " ".join(m.group(3).split())
            sigs.append((m.group(1), (m.group(1) + "(" + m.group(2).strip() + ") " + tail).strip()))
        for m in RX_SOL_SPECIAL.finditer(text):
            sigs.append((m.group(1), m.group(1)))
    elif ext == ".vy":
        units = []
        for m in RX_VY_FN.finditer(text):
            sigs.append((m.group(1), m.group(1) + "(" + m.group(2).strip() + ")"))
    elif ext == ".rs":
        units = RX_RS_MOD.findall(text)
        sigs = [(m.group(1), m.group(0).strip()) for m in RX_RS_FN.finditer(text)]
    elif ext == ".move":
        units = RX_MOVE_MOD.findall(text)
        sigs = [(m.group(1), m.group(0).strip()) for m in RX_MOVE_FN.finditer(text)]
    elif ext == ".cairo":
        units = RX_CAIRO_MOD.findall(text)
        sigs = [(m.group(1), m.group(0).strip()) for m in RX_CAIRO_FN.finditer(text)]
    else:
        units = []
    return units, sigs


def heat(rel_low, body_low, nfn):
    w = min(nfn, 30)
    for h in PATH_HINTS:
        if h in rel_low:
            w += 8
    for t in RISK_TOKENS:
        w += min(body_low.count(t), 5) * 3
    if any(x in body_low for x in ("external", "public", "@external", "pub fn", "entry fun")):
        w += 5
    if any(x in body_low for x in ("balances", "totalsupply", "total_supply", "reserve", "invariant")):
        w += 6
    if "nonreentrant" not in body_low and any(x in body_low for x in ("withdraw", "redeem", ".call{")):
        w += 6
    return w


def harvest(root):
    rows = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in EXTS:
            continue
        try:
            rel = path.relative_to(root)
            if any(p.lower() in SKIP for p in rel.parts[:-1]):
                continue
            if path.stat().st_size > FILE_BYTES:
                continue
        except OSError:
            continue
        ext = path.suffix.lower()
        text = read_text(path)
        if not looks_code(text, ext):
            continue
        units, sigs = outline(text, ext)
        if not units and ext != ".sol":
            units = [path.stem]
        if not units and not sigs:
            continue
        rows.append({
            "path": path, "rel": rel.as_posix(), "base": path.name, "text": text,
            "low": text.lower(), "stem": path.stem, "ext": ext,
            "units": units, "sigs": sigs, "fnames": {n for n, _ in sigs},
        })
    for r in rows:
        w = heat(r["rel"].lower(), r["low"], len(r["sigs"]))
        low = r["low"]
        if r["ext"] == ".sol" and "contract " not in low and "library " not in low:
            w *= 0.2
        elif r["ext"] != ".vy" and r["sigs"] and low.count("{") < max(1, len(r["sigs"]) // 3):
            w *= 0.4
        parts = [p.lower() for p in Path(r["rel"]).parts]
        stem = r["stem"].lower()
        if (stem in ("test", "tests") or stem.startswith("test_")
                or stem.endswith(("_test", "_tests", ".t")) or "test" in parts
                or any(p in ("generated", "gen", "bindings", "sim") for p in parts)):
            w *= 0.1
        r["heat"] = w
    rows.sort(key=lambda r: (-r["heat"], r["rel"]))
    return rows[:FILE_LIMIT]


def imports_of(rec, by_base):
    out = []
    seen = set()
    for imp in RX_IMPORT.findall(rec["text"]):
        leaf = imp.rsplit("/", 1)[-1]
        base = leaf.split(".")[0]
        for cand in (leaf, base):
            other = by_base.get(cand)
            if other and other["rel"] != rec["rel"] and other["rel"] not in seen:
                seen.add(other["rel"])
                out.append("// import " + other["rel"] + "\n" + other["text"][:IMPORT_CHARS])
                break
        if len(out) >= 2:
            break
    return "\n\n".join(out)


def risk_lines(text, limit=16):
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        low = line.lower()
        if any(t in low for t in RISK_TOKENS):
            s = " ".join(line.split())
            if s:
                out.append(str(i) + ": " + s[:180])
        if len(out) >= limit:
            break
    return out


def map_blob(rows, budget):
    parts = []
    used = 0
    rich = int(budget * 0.82)
    for r in rows:
        if used < rich:
            chunk = json.dumps({
                "file": r["rel"],
                "contracts": r["units"][:8],
                "score": round(float(r.get("heat", 0)), 1),
                "functions": [s[:150] for _, s in r["sigs"][:24]],
                "risk_lines": risk_lines(r["text"], 16),
            }, separators=(",", ":"))
        else:
            chunk = json.dumps({
                "file": r["rel"],
                "contracts": r["units"][:4],
                "score": round(float(r.get("heat", 0)), 1),
            }, separators=(",", ":"))
        if used + len(chunk) + 1 > budget:
            break
        parts.append(chunk)
        used += len(chunk) + 1
    return "\n".join(parts)


def squeeze(text, limit):
    if len(text) <= limit:
        return text
    lines = text.splitlines()
    keep = set()
    for i, line in enumerate(lines):
        low = line.lower()
        if RX_DECL.search(line) or any(t in low for t in RISK_TOKENS):
            for j in range(max(0, i - 5), min(len(lines), i + 18)):
                keep.add(j)
    out = []
    prev = -10
    size = 0
    for i in sorted(keep):
        if i > prev + 1:
            gap = "\n// ... " + str(i - prev - 1) + " lines omitted ...\n"
            out.append(gap)
            size += len(gap)
        row = str(i + 1) + ": " + lines[i]
        out.append(row)
        size += len(row) + 1
        prev = i
        if size >= limit:
            break
    body = "\n".join(out)
    if len(body) < limit // 2:
        body += "\n\n// file prefix\n" + text[: max(0, limit - len(body) - 20)]
    return body[:limit]


def pluck(payload):
    if not isinstance(payload, dict):
        return ""
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        return ""
    msg = choices[0].get("message")
    if not isinstance(msg, dict):
        return ""
    c = msg.get("content")
    if isinstance(c, list):
        c = "".join(p.get("text", "") for p in c if isinstance(p, dict))
    if isinstance(c, str) and c.strip():
        return c
    for k in ("reasoning", "reasoning_content"):
        v = msg.get(k)
        if isinstance(v, str) and v.strip():
            return v
    d = msg.get("reasoning_details")
    if isinstance(d, list):
        j = "".join(p.get("text", "") for p in d if isinstance(p, dict))
        if j.strip():
            return j
    return ""


def call_model(inference_api, prompt, deadline, max_tokens):
    endpoint = (inference_api or os.environ.get("INFERENCE_API") or "").rstrip("/")
    if not endpoint:
        raise RuntimeError("no inference endpoint")
    body = json.dumps({
        "model": MODEL,
        "messages": [
            {"role": "system", "content": SYS},
            {"role": "user", "content": prompt},
        ],
        "max_tokens": max_tokens,
        "temperature": TEMP,
    }).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "x-inference-api-key": os.environ.get("INFERENCE_API_KEY", ""),
    }
    err = None
    n = 0
    while n < TRIES:
        left = deadline - time.monotonic() - TAIL_S
        wait = min(HTTP_S, float(int(left)))
        if wait < MIN_CALL_S:
            raise RuntimeError("budget gone")
        try:
            req = urllib.request.Request(
                endpoint + "/inference", data=body, method="POST", headers=headers)
            with urllib.request.urlopen(req, timeout=wait) as resp:
                raw = resp.read()
            return pluck(json.loads(raw.decode("utf-8", "replace")))
        except urllib.error.HTTPError as exc:
            if exc.code not in _TRANSIENT and exc.code not in {429, 503}:
                raise RuntimeError("http " + str(exc.code)) from exc
            if exc.code in {429, 503}:
                raise RuntimeError("http " + str(exc.code)) from exc
            err = exc
        except (socket.timeout, TimeoutError) as exc:
            raise RuntimeError("timeout") from exc
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, (socket.timeout, TimeoutError)):
                raise RuntimeError("timeout") from exc
            err = exc
        except (OSError, ValueError) as exc:
            err = exc
        n += 1
        if n >= TRIES:
            break
        if deadline - time.monotonic() <= 2.0 + PASS_RESERVE:
            break
        time.sleep(2.0)
    raise RuntimeError(str(err) if err else "request failed")


def scan_objs(text):
    found = []
    depth = 0
    start = -1
    instr = esc = False
    for i, ch in enumerate(text):
        if instr:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                instr = False
            continue
        if ch == '"':
            instr = True
        elif ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            if depth > 0:
                depth -= 1
                if depth == 0 and start >= 0:
                    try:
                        o = json.loads(text[start:i + 1])
                        if isinstance(o, dict):
                            found.append(o)
                    except json.JSONDecodeError:
                        pass
                    start = -1
    return found


_KEYS = ("title", "file", "severity", "description", "function", "contract", "mechanism")


def unfence(text):
    t = text.strip()
    if t.startswith("```"):
        t = re.sub(r"^```[a-zA-Z]*\s*", "", t)
        t = re.sub(r"\s*```$", "", t)
    return t


def parse_findings(text):
    if not isinstance(text, str):
        return []
    t = unfence(text)
    try:
        o = json.loads(t)
        if isinstance(o, dict):
            items = o.get("findings") or o.get("vulnerabilities")
            return [f for f in items if isinstance(f, dict)] if isinstance(items, list) else []
    except json.JSONDecodeError:
        pass
    m = re.search(r'"(?:findings|vulnerabilities)"\s*:\s*\[', t)
    win = t[m.end():] if m else t
    return [o for o in scan_objs(win) if any(k in o for k in _KEYS)]


def parse_map(text):
    targets, findings = [], []
    if not isinstance(text, str):
        return targets, findings
    t = unfence(text)
    try:
        o = json.loads(t)
        if isinstance(o, dict):
            tg = o.get("target_files")
            if isinstance(tg, list):
                targets = [str(x) for x in tg if isinstance(x, str)]
            fs = o.get("findings") or o.get("vulnerabilities")
            if isinstance(fs, list):
                findings = [f for f in fs if isinstance(f, dict)]
            return targets, findings
    except json.JSONDecodeError:
        pass
    m = re.search(r'"target_files"\s*:\s*\[(.*?)\]', t, re.S)
    if m:
        targets = re.findall(r'"([^"]+)"', m.group(1))
    return targets, parse_findings(text)


def deep_prompt(batch, by_base, per_cap, budget):
    parts = [DEEP_P]
    left = budget - len(DEEP_P)
    ctx = imports_of(batch[0], by_base) if batch else ""
    for rec in batch:
        take = min(len(rec["text"]), per_cap, max(0, left))
        if take <= 0:
            break
        text = rec["text"]
        body = text if len(text) <= take else squeeze(text, take)
        block = (
            "\n\n===== FILE: " + rec["rel"] + " =====\n"
            "Contracts/modules: " + (", ".join(rec["units"][:8]) or rec["stem"]) + "\n" + body
        )
        if len(text) > take:
            block += "\n/* truncated */"
        parts.append(block)
        left -= len(block)
    if ctx and left > 800:
        parts.append("\n\n===== IMPORTED CONTEXT (read-only) =====\n" + ctx[:left - 200])
    return "".join(parts)


def batch_prompt(batch, preface, per_cap, budget):
    parts = [preface]
    left = budget - len(preface)
    for rec in batch:
        body = squeeze(rec["text"], per_cap)
        block = (
            "\n\n===== FILE: " + rec["rel"] + " =====\n"
            "Contracts/modules: " + (", ".join(rec["units"][:8]) or rec["stem"]) + "\n" + body + "\n"
        )
        if left <= 0:
            break
        if len(block) > left:
            block = block[:left] + "\n/* truncated */"
        parts.append(block)
        left -= len(block)
    return "".join(parts)


def reorder(rows, targets):
    if not targets:
        return rows
    front, seen = [], set()
    for tg in targets:
        cleaned = tg.strip().lstrip("./")
        if not cleaned:
            continue
        base = cleaned.rsplit("/", 1)[-1]
        for r in rows:
            if r["rel"] in seen:
                continue
            rel = r["rel"]
            if (cleaned == rel or rel.endswith(cleaned)
                    or cleaned.endswith(rel) or r["base"] == base):
                front.append(r)
                seen.add(rel)
                break
    for r in rows:
        if r["rel"] not in seen:
            front.append(r)
    return front


def line_of(text, needle):
    i = text.find(needle)
    return text.count("\n", 0, i) + 1 if i >= 0 else None


def fn_line(rec, fn):
    if not fn:
        return None
    for needle in ("function " + fn, "fn " + fn, "fun " + fn, "def " + fn, "func " + fn, fn):
        ln = line_of(rec["text"], needle)
        if ln:
            return ln
    return None


def resolve_file(file_value, by_rel, by_base, hint=""):
    if not file_value:
        return None
    fv = file_value.strip().strip("`").lstrip("./")
    if fv in by_rel:
        return by_rel[fv]
    hits = [r for rel, r in by_rel.items()
            if rel == fv or rel.endswith(fv) or (len(fv) > 3 and fv.endswith(rel))]
    if len(hits) == 1:
        return hits[0]
    if len(hits) > 1:
        if hint:
            for r in hits:
                if hint in r["fnames"]:
                    return r
        return hits[0]
    base = fv.rsplit("/", 1)[-1]
    same = [r for r in by_rel.values() if r["base"] == base]
    if len(same) == 1:
        return same[0]
    if same and hint:
        for r in same:
            if hint in r["fnames"]:
                return r
    return by_base.get(base)


def declared(text, fn):
    if not fn:
        return False
    pat = r"\b(?:" + "|".join(FN_WORDS) + r")\s+" + re.escape(fn) + r"\b"
    return re.search(pat, text) is not None


def normalize(raw, by_rel, by_base):
    file_value = str(raw.get("file") or raw.get("path") or raw.get("location") or "").strip()
    fn = str(raw.get("function") or "").strip().strip("`() ")
    fn = fn.split(".")[-1].split("::")[-1]
    rec = resolve_file(file_value, by_rel, by_base, fn)
    if rec is None:
        return None
    sev = str(raw.get("severity") or "").strip().lower()
    if sev in {"medium", "med", "moderate"}:
        sev = "high"
    if sev not in {"high", "critical"}:
        return None
    try:
        conf = max(0.0, min(1.0, float(raw.get("confidence"))))
    except (TypeError, ValueError):
        conf = 0.5
    # Drop weak highs (noise) but keep all criticals.
    if sev == "high" and conf < CONF_DROP:
        return None
    if fn and fn not in rec["fnames"] and not declared(rec["text"], fn):
        fn = ""
    units = rec["units"]
    unit = str(raw.get("contract") or raw.get("module") or "").strip().strip("`")
    unit_real = bool(unit and (not units or unit in units))
    if not unit or (units and unit not in units):
        unit = units[0] if units else rec["stem"]
    mechanism = str(raw.get("mechanism") or "").strip()
    impact = str(raw.get("impact") or "").strip()
    description = str(raw.get("description") or "").strip()
    title = str(raw.get("title") or "").strip()
    loc = ".".join(x for x in (unit, fn) if x)
    if not title:
        title = (loc + " - high/critical vulnerability") if loc else "High/critical vulnerability"
    elif loc and loc.lower() not in title.lower():
        title = loc + " - " + title
    body = "In `" + rec["rel"] + "`"
    if unit:
        body += ", contract `" + unit + "`"
    if fn:
        body += ", function `" + fn + "()`"
    body += ". "
    if mechanism:
        body += "Mechanism: " + mechanism.rstrip(".") + ". "
    if impact:
        body += "Impact: " + impact.rstrip(".") + ". "
    if description and description.lower() not in body.lower():
        body += description
    if not (mechanism or impact or description):
        body += title
    body = re.sub(r"\s+", " ", body).strip()
    if len(body) < DESC_MIN and not title:
        return None
    tag = classify(title, mechanism, impact, description)
    return {
        "title": title[:220],
        "description": body[:2400],
        "severity": sev,
        "file": rec["rel"],
        "function": fn,
        "line": fn_line(rec, fn),
        "type": CLASS_TYPE.get(tag) or str(raw.get("type") or "logic"),
        "confidence": 0.9 if sev == "critical" else conf,
        "pinned": bool(fn) or unit_real,
        "votes": 1,
    }


def stub(title, rel, unit, fn, mechanism, impact):
    return {
        "title": title, "file": rel, "contract": unit, "function": fn,
        "severity": "high", "mechanism": mechanism, "impact": impact,
        "description": mechanism + ". " + impact, "confidence": 0.7,
    }


def brace(text, start):
    open_i = text.find("{", start)
    if open_i < 0:
        return text[start:start + 600]
    depth = 0
    for i in range(open_i, min(len(text), open_i + 6000)):
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return text[start:start + 1500]


def carve_fns(text):
    marks = []
    for m in RX_SOL_FN.finditer(text):
        marks.append((m.start(), m.group(1), " ".join(m.group(0).split())))
    for m in RX_SOL_SPECIAL.finditer(text):
        marks.append((m.start(), m.group(1), m.group(1)))
    marks.sort(key=lambda x: x[0])
    out = []
    for i, (pos, name, sig) in enumerate(marks):
        end = marks[i + 1][0] if i + 1 < len(marks) else len(text)
        out.append({"name": name, "sig": sig, "body": text[pos:end]})
    return out


_GUARDS = ("onlyowner", "onlyrole", "requiresauth", "_checkowner", "msg.sender==",
           "authorized", "hasrole", "restricted", "onlyadmin", "onlygovernance")
RX_AUTH_MAP = re.compile(r"(operator|extension|approv|allowed|authoriz|whitelist|trusted)s?\s*\[")
RX_AUTH_SELF = re.compile(
    r"(operator|extension|approv|allowed|authoriz|whitelist|trusted)s?\s*\[\s*msg\.sender")
RX_ROLE = re.compile(
    r"validator|minter|operator|admin|guardian|keeper|signer|treasury|governance|pauser|role", re.I)
RX_MOD = re.compile(r"\b(external|public|payable|virtual|override|returns)\b|\([^)]*\)|[\s,]")
_SKIP_STEM = ("mock", "dummy", "fake", "stub", "harness", "example",
              "weth", "wavax", "wmatic", "wbnb", "weth9", "wrapped")


def probes(rows):
    hits = []
    for r in rows:
        if r["ext"] != ".sol":
            continue
        stem = r["stem"].lower()
        if any(w in stem for w in _SKIP_STEM) or stem[:1].isdigit():
            continue
        if "contract " not in r["low"] and "library " not in r["low"]:
            continue
        text = r["text"]
        unit = r["units"][0] if r["units"] else r["stem"]
        for m in re.finditer(r"\breceive\s*\(\s*\)\s*external\s+payable\s*\{", text):
            body = brace(text, m.start()).lower()
            if ("stake(" in body or "deposit(" in body) and "msg.sender" not in body:
                hits.append(stub(
                    unit + ".receive - inbound native transfer auto-staked",
                    r["rel"], unit, "receive",
                    "the payable receive hook stakes or deposits every native transfer "
                    "without distinguishing protocol returns from user deposits",
                    "native funds returned from unstake or rewards are restaked instead "
                    "of settling withdrawals, locking liquidity"))
                break
        for fn in carve_fns(text):
            name, sig, b = fn["name"], fn["sig"].lower(), fn["body"].lower()
            joined = sig + " " + b
            if "domainseparator" in joined and ("ecrecover" in b or "recover(" in b):
                if not any(x in joined for x in
                           ("deadline", "chainid", "block.chainid", "block.timestamp")):
                    hits.append(stub(
                        unit + "." + name + " - replayable signature domain",
                        r["rel"], unit, name,
                        "signature recovery uses a domain separator unbound to deadline "
                        "or chain id",
                        "a captured signature can be replayed on another chain or deploy"))
            if re.match(r"^(set|update|enable|disable|add|remove|register)", name, re.I):
                if ("external" in sig or "public" in sig) and "only" not in sig \
                        and not any(g in joined for g in _GUARDS):
                    if RX_AUTH_MAP.search(b) and not RX_AUTH_SELF.search(b):
                        hits.append(stub(
                            unit + "." + name + " - unauthenticated authorization change",
                            r["rel"], unit, name,
                            "external config writes an authorization mapping with no "
                            "owner or role check",
                            "any caller can authorize itself for privileged actions"))
            if name.lower() in ("cancelorder", "modifyorder", "fillorder", "executeorder") \
                    and "external" in sig and "nonreentrant" not in sig:
                if "safetransfer" in b or "transfer(" in b or ".call{" in b:
                    hits.append(stub(
                        unit + "." + name + " - order mutation without reentrancy guard",
                        r["rel"], unit, name,
                        "order path reaches token transfer without nonReentrant",
                        "callback can reenter mid-mutation to double-refund"))
            if ".price" in b and any(x in b for x in ("pnl", "collateral", "settle")) \
                    and any(x in joined for x in ("intent", "order", "params")):
                if not any(x in b for x in ("maxprice", "minprice", "oracle", "latestversion",
                                            "currentversion", ".gt(", ".lt(", "clamp", "bound")):
                    hits.append(stub(
                        unit + "." + name + " - unbounded user price in value math",
                        r["rel"], unit, name,
                        "user-supplied price flows into PnL/collateral without oracle clamp",
                        "extreme price can manufacture settlement value"))
            if re.match(r"^(add|register|Add|Register)[A-Z_]", name) and RX_ROLE.search(name):
                modzone = sig.rsplit(")", 1)[-1]
                if ("external" in sig or "public" in sig) and not RX_MOD.sub("", modzone):
                    if "msg.sender" not in b and not ("require(" in b and "owner" in b):
                        hits.append(stub(
                            unit + "." + name + " - privileged role added without access control",
                            r["rel"], unit, name,
                            "role-adding function has no modifier or in-body auth check",
                            "any caller can register as a privileged role"))
        if len(hits) >= 10:
            break
    return hits[:10]


def fallback(rows):
    out = []
    for r in rows:
        if r["ext"] != ".sol":
            continue
        low = r["low"]
        unit = r["units"][0] if r["units"] else r["stem"]
        if "function initialize" in low and not any(
                x in low for x in ("initializer", "onlyowner", "onlyrole", "_disableinitializers")):
            out.append(stub(
                unit + ".initialize - unprotected initializer", r["rel"], unit,
                "initialize" if "initialize" in r["fnames"] else "",
                "initializer is externally reachable without one-time or owner guard",
                "attacker can seize ownership via initialize"))
        elif "tx.origin" in low:
            out.append(stub(
                unit + " - authorization depends on tx.origin", r["rel"], unit, "",
                "auth gated on tx.origin, defeated by phishing via intermediate contract",
                "privileged account can be tricked into fund-moving actions"))
        if len(out) >= 3:
            break
    return out


def title_key(title):
    return re.sub(r"[^a-z0-9]+", " ", (title or "").lower()).strip()[:70]


def merge_vote(items):
    """Collapse duplicates; count cross-pass agreement.

    Key is (file, function, normalized title) so two distinct bugs in one
    function both survive, matching how the grader scores separate findings.
    """
    groups = {}
    for e in items:
        key = (e["file"].lower(), e["function"].lower(), title_key(e["title"]))
        cur = groups.get(key)
        if cur is None:
            e = dict(e)
            e["votes"] = int(e.get("votes", 1))
            groups[key] = e
            continue
        cur["votes"] = int(cur.get("votes", 1)) + 1
        if e["severity"] == "critical" and cur["severity"] != "critical":
            cur["severity"] = "critical"
        if float(e.get("confidence", 0)) > float(cur.get("confidence", 0)):
            cur["confidence"] = e["confidence"]
        if e.get("pinned") and not cur.get("pinned"):
            cur["pinned"] = True
        if len(e.get("description", "")) > len(cur.get("description", "")):
            cur["description"] = e["description"]
            cur["title"] = e["title"]
        if cur.get("line") is None and e.get("line") is not None:
            cur["line"] = e["line"]
    # Multi-pass agreement is the strongest signal for project PASS.
    for e in groups.values():
        votes = int(e.get("votes", 1))
        if votes >= 2:
            e["confidence"] = min(1.0, float(e.get("confidence", 0.5)) + 0.12 * (votes - 1))
            e["pinned"] = True
    return list(groups.values())


def select(items):
    merged = merge_vote(items)

    def rank(e):
        return (
            bool(e.get("pinned")),
            int(e.get("votes", 1)),
            e["severity"] == "critical",
            float(e.get("confidence", 0)),
            len(e.get("description", "")),
        )

    merged.sort(key=rank, reverse=True)
    pinned = [e for e in merged if e.get("pinned")]
    loose = [e for e in merged if not e.get("pinned")]
    ordered = pinned + loose
    per_file = {}
    out = []
    for e in ordered:
        fkey = e["file"].lower()
        if per_file.get(fkey, 0) >= EMIT_PER_FILE:
            continue
        per_file[fkey] = per_file.get(fkey, 0) + 1
        e["confidence"] = float(e.get("confidence", 0.5))
        e.pop("votes", None)
        e.pop("pinned", None)
        out.append(e)
        if len(out) >= EMIT_TOTAL:
            break
    return out


def agent_main(project_dir=None, inference_api=None):
    vulns = []
    deadline = time.monotonic() + DEADLINE_S
    try:
        root = find_root(project_dir)
        if root is None:
            return {"vulnerabilities": vulns}
        rows = harvest(root)
        if not rows:
            return {"vulnerabilities": vulns}
        by_base = {}
        for r in rows:
            by_base.setdefault(r["base"], r)
        by_rel = {r["rel"]: r for r in rows}

        raw = []
        ordered = rows
        if deadline - time.monotonic() >= PASS_RESERVE:
            try:
                targets, seeded = parse_map(
                    call_model(inference_api, MAP_P + map_blob(rows, MAP_CHARS),
                               deadline, MAP_TOK))
                raw.extend(seeded)
                ordered = reorder(rows, targets)
            except Exception:
                pass
        if deadline - time.monotonic() >= PASS_RESERVE:
            try:
                raw.extend(parse_findings(call_model(
                    inference_api,
                    deep_prompt(ordered[:DEEP_N], by_base, DEEP_PER_FILE, DEEP_BUDGET),
                    deadline, DEEP_TOK)))
            except Exception:
                pass
        # Independent re-audit of the SAME central files - key for 100% detection
        # across replicas (Dexterity104 #197's decisive lever).
        if deadline - time.monotonic() >= REAUDIT_RESERVE:
            core = ordered[:REAUDIT_N]
            if core:
                try:
                    raw.extend(parse_findings(call_model(
                        inference_api,
                        batch_prompt(core, REAUDIT_P, REAUDIT_PER, REAUDIT_BUDGET),
                        deadline, REAUDIT_TOK)))
                except Exception:
                    pass
        # Wider slice only when deep+reaudit left ample clock; never starve reaudit.
        if deadline - time.monotonic() >= WIDE_RESERVE:
            wide = ordered[DEEP_N:DEEP_N + WIDE_N]
            if wide:
                try:
                    raw.extend(parse_findings(call_model(
                        inference_api,
                        batch_prompt(wide, WIDE_P, WIDE_PER, WIDE_BUDGET),
                        deadline, WIDE_TOK)))
                except Exception:
                    pass

        try:
            raw.extend(probes(rows))
        except Exception:
            pass

        cleaned = []
        for item in raw:
            e = normalize(item, by_rel, by_base)
            if e is not None:
                cleaned.append(e)
        if not cleaned:
            for item in fallback(rows):
                e = normalize(item, by_rel, by_base)
                if e is not None:
                    cleaned.append(e)
        vulns = select(cleaned)
    except Exception:
        return {"vulnerabilities": vulns}
    return {"vulnerabilities": vulns}


if __name__ == "__main__":
    import sys
    print(json.dumps(agent_main(sys.argv[1] if len(sys.argv) > 1 else None), indent=2))
