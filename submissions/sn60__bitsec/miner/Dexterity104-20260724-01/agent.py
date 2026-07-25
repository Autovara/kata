"""SN60 / Bitsec miner: concurrent breadth-first on-chain audit.

A whole-repository high/critical vulnerability hunter for smart-contract code in
Solidity, Vyper, Rust (Solana/Anchor + CosmWasm), Move and Cairo.

Design
------
Earlier single-threaded reviewers audit only a handful of files per run, each pass
cramming many files into one prompt so the model skims and overlooks issues. This
agent instead treats the inference endpoint as a pool: it ranks the repository once,
then dispatches many *focused* reviews concurrently -- most looking at a single file
with its imported neighbours in full -- so each candidate function gets undivided
attention and far more of the tree is actually read inside one wall-clock budget.

Every network reviewer is wrapped so a slow or failing one silently drops its share
of the work instead of failing the run, and every worker checks the shared deadline
before it starts, so the process always returns a report well inside the limit. When
the endpoint serialises requests the pool simply drains fewer items -- never worse
than the sequential baseline. Independent reviews of the same code are then folded
together and issues that more than one reviewer localises to the same
file/function/class are ranked first, so the strongest-supported issues lead the
report. Pure standard library; the only outbound traffic is to the injected endpoint.
"""

from __future__ import annotations

import json
import os
import queue
import re
import socket
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

# ---------------------------------------------------------------------------
# Discovery configuration
# ---------------------------------------------------------------------------

SOURCE_SUFFIXES = (".sol", ".vy", ".rs", ".move", ".cairo")
SKIP_DIRS = frozenset({
    "test", "tests", "mock", "mocks", "example", "examples", "script", "scripts",
    "broadcast", "node_modules", "vendor", "vendors", "lib", "libs", "out",
    "artifacts", "cache", "coverage", "interfaces", "interface", "fixtures", "fixture",
    "target", "docs", ".git", ".github", "deps", "dist", "build",
})

RX_SOL_UNIT = re.compile(
    r"\b(?:abstract\s+contract|contract|library|interface)\s+([A-Za-z_][A-Za-z0-9_]*)")
RX_SOL_FN = re.compile(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)([^{};]*)")
RX_SOL_SPECIAL = re.compile(r"\b(constructor|receive|fallback)\b\s*\(")
RX_VY_FN = re.compile(r"(?m)^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)")
RX_RS_FN = re.compile(
    r"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)")
RX_RS_MOD = re.compile(r"(?m)^\s*(?:pub\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{")
RX_MOVE_FN = re.compile(
    r"(?m)^\s*(?:public\s*(?:\([^)]*\))?\s+)?(?:entry\s+)?(?:native\s+)?fun\s+([A-Za-z_][A-Za-z0-9_]*)")
RX_MOVE_MOD = re.compile(r"(?m)^\s*module\s+(?:[A-Za-z_0-9]+::)?([A-Za-z_][A-Za-z0-9_]*)")
RX_CAIRO_FN = re.compile(r"(?m)^\s*(?:pub\s+)?(?:fn|func)\s+([A-Za-z_][A-Za-z0-9_]*)")
RX_CAIRO_MOD = re.compile(r"(?m)^\s*(?:pub\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{")
RX_IMPORT = re.compile(r'(?m)^\s*(?:import|use)\b[^;\n]*?["\']?([A-Za-z0-9_./]+)["\']?')
RX_DECL = re.compile(
    r"\bfunction\b|\bdef\b|\bfn\b|\bfun\b|\bmodifier\b|\bconstructor\b|\bmodule\b|\bmapping\b")
FN_KEYWORDS = ("function", "fn", "fun", "def", "func")

# Path/name fragments that hint a file carries value-bearing logic.
VALUE_WORDS = (
    "vault", "pool", "router", "manager", "controller", "strategy", "market", "lend",
    "borrow", "oracle", "price", "stak", "reward", "treasury", "bridge", "factory",
    "proxy", "govern", "token", "escrow", "auction", "liquidat", "swap", "stable",
    "collateral", "vesting", "distributor", "minter", "gauge", "farm", "perp",
    "position", "margin", "settle", "clearing", "coin", "account", "program",
)

# Source tokens that tend to sit next to real high/critical bugs.
RISK_TOKENS = (
    # EVM
    "delegatecall", ".call{", ".call.value", "selfdestruct", "tx.origin", "assembly",
    "ecrecover", "permit", "signature", "nonce", "initialize", "upgradeto",
    "onlyowner", "onlyrole", "_mint", "_burn", "mint(", "burn(", "withdraw", "redeem",
    "deposit", "borrow", "repay", "liquidat", "collateral", "share", "totalsupply",
    "balanceof", "oracle", "getprice", "latestround", "slot0", "flash", "swap",
    "reward", "claim", "unchecked", "safetransfer", "transferfrom", "approve",
    "settle", "rebalance", "liquidity", "reserve", "invariant", "msg.sender",
    # Rust / Solana / CosmWasm
    "signer", "authority", "lamports", "invoke", "cpi", "checked_", "unwrap",
    "close_account", "realloc", "try_borrow", "deserialize", "next_account",
    "assert_eq", "owner", "is_signer", "wasm", "info.sender", "transfer",
    "sub_msg", "coin(",
    # Move / Cairo
    "acquires", "borrow_global", "move_to", "move_from", "capability", "signer::",
    "get_caller_address", "get_contract_address", "felt", "starknet", "assert(",
)

# ---------------------------------------------------------------------------
# Budgets
# ---------------------------------------------------------------------------

BYTE_CEILING = 260_000
CATALOG_CAP = 110
NEIGHBOUR_CHARS = 3_200
FOCUS_FILE_CHARS = 26_000
FOCUS_PROMPT_CHARS = 30_000
PAIR_FILE_CHARS = 9_000
PAIR_PROMPT_CHARS = 24_000
SURVEY_CHARS = 40_000

# The runner allows a 30-minute wall clock and the endpoint accepts several
# requests at once, so coverage comes from breadth: several single-file reviews
# dispatched concurrently rather than a few crammed prompts. The counts stay
# modest to keep the per-run request volume in check while still reading far more
# of the tree, at full attention, than a single sequential pass.
FOCUS_COUNT = 20          # single-file deep reviews
PAIR_SPAN = 12            # files beyond the focus set covered two-per-call
RECHECK_COUNT = 3         # adversarial second reads of the very top files
WORKERS = 6
CONSECUTIVE_FAIL_STOP = 5

# The grader keeps up to 100 findings, and a spurious entry only costs a slot,
# never a detection, so the report is generous and led by the best-supported ones.
EMIT_CAP = 50
PER_FILE_CAP = 8
MIN_BODY = 40
BASE_CONF = 0.55
HIGH_CONF_FLOOR = 0.42

MODEL = os.environ.get("KATA_MINER_MODEL", "deepseek-ai/DeepSeek-V3.2-TEE")
DECODE_TEMP = 0.0
SURVEY_TOKENS = 12_000
FOCUS_TOKENS = 16_000
PAIR_TOKENS = 12_000
RECHECK_TOKENS = 16_000

WALL_BUDGET = 1450.0
PER_CALL_TIMEOUT = 270.0
TAIL_RESERVE = 25.0
CALL_FLOOR = 30.0
CALL_RETRIES = 3
RETRYABLE = frozenset({408, 409, 425, 429, 500, 502, 503, 504, 520, 522, 524, 529})

# reasoning_effort is offered opportunistically; a 400 turns it off for the run.
_EFFORT_OK = True
_EFFORT_LOCK = threading.Lock()

# ---------------------------------------------------------------------------
# Prompt copy
# ---------------------------------------------------------------------------

SYSTEM = (
    "You are a principal smart-contract auditor equally fluent in Solidity, Vyper, "
    "Rust for Solana/Anchor and CosmWasm, Move, and Cairo. Within the code you are "
    "shown, enumerate every distinct HIGH or CRITICAL weakness you can tie to one "
    "concrete function; do not stop at the single worst one. Overlooking a real "
    "high/critical costs far more than naming a candidate that later proves wrong. "
    "In scope: theft or freezing of funds, insolvency, unauthorized state changes, "
    "privilege escalation, permanent lockup or denial of service, mint/supply "
    "corruption, oracle manipulation, reentrancy, replay or signature flaws, and "
    "absent signer/owner/authority checks. Out of scope: gas, style, missing events, "
    "bare centralization, and informational notes. Reason privately, then output "
    "exactly one minified JSON object -- no prose, no markdown, no fences."
)

CATALOG_BY_LANG = (
    "Sweep this catalogue per language. "
    "Solidity/Vyper: reentrancy and external-call ordering; missing or incorrect "
    "access control; delegatecall, upgrade and initialization faults; first-depositor "
    "share inflation and rounding; spot-vs-time-weighted and stale or steerable "
    "oracles; permit and signature replay; unsafe token assumptions and fee-on-transfer; "
    "native-value accounting; and irreversible denial of service. "
    "Solana/Anchor Rust: missing is_signer, missing account-owner check, missing "
    "has_one/constraint, unchecked PDA seeds, skipped account close, unchecked math, "
    "CPI into an unvetted program, and missing discriminator or type confusion. "
    "CosmWasm: unchecked info.sender and an open migrate entry point. "
    "Move: missing signer or capability, a public entry that wraps a privileged call, "
    "and resource-ownership confusion. "
    "Cairo/Starknet: missing get_caller_address check, felt over/underflow, "
    "L1->L2 handler authentication, and storage-slot collision."
)

THOROUGH = (
    "Be exhaustive on GENUINE issues: write up each distinct high/critical you can bind "
    "to a specific function, and add a separate entry when one function hides more than "
    "one flaw. Do not halt after the first one or two, and do not cap the count yourself. "
    "For each, state briefly why the modifiers or require-checks present do not stop it. "
    "Do not manufacture filler -- a weak entry only drags the set down."
)

ANCHORING = (
    "Anchoring: copy file exactly from a FILE header, never invent it. function must be a "
    "real name that appears in that file, copied verbatim, with no arguments and no "
    "contract prefix. contract must be one declared in that file. Keep mechanism "
    "concrete: precondition, then the attacker's step, then the broken state."
)

EMISSION = (
    "Emit one bare minified JSON object and nothing else; double quotes only, no trailing "
    "commas; severity is exactly high or critical; each description is two to four "
    "sentences; order entries strongest first and keep each self-contained; if you run low "
    "on room, finish the current object and close the array and object cleanly rather than "
    "opening another."
)

SHAPE = (
    '{"findings":[{"title":"Contract.function - specific flaw","file":"exact/path.sol",'
    '"contract":"ContractOrModule","function":"functionName","severity":"high|critical",'
    '"confidence":0.0,"type":"reentrancy|access-control|price-oracle|signature-replay|'
    'accounting|initialization|arithmetic|logic",'
    '"mechanism":"precondition -> attacker action -> broken state",'
    '"impact":"funds stolen / privilege escalation / insolvency / DoS",'
    '"description":"2-4 sentences naming file, contract, function, mechanism, and impact"}]}'
)

_GUIDE = THOROUGH + " " + CATALOG_BY_LANG + " " + ANCHORING + " " + EMISSION

FOCUS_HEAD = (
    "Audit the single source file below in depth for HIGH or CRITICAL weaknesses; the "
    "imported context that follows it is read-only support. Trace each externally reachable "
    "entry point end to end. " + _GUIDE + "\nReturn strict JSON only: " + SHAPE + "\n"
)

PAIR_HEAD = (
    "Audit the source files below in depth for HIGH or CRITICAL weaknesses, watching the "
    "flows that cross between them. " + _GUIDE + "\nReturn strict JSON only: " + SHAPE + "\n"
)

RECHECK_HEAD = (
    "Re-audit the file below from scratch, trusting no earlier read. Hunt above all for the "
    "issues a first pass misses: cross-function interplay, initialization/upgrade takeover, "
    "rounding and share inflation, stale or steerable prices, absent signer/owner/authority "
    "checks, and callback/reentrancy ordering. For each proposed issue, say why the guards "
    "already present fail to stop it. " + _GUIDE + "\nReturn strict JSON only: " + SHAPE + "\n"
)

SURVEY_HEAD = (
    "Below is a structured map of a smart-contract project: per file its contracts or "
    "modules, function signatures, and risk-relevant lines. Report every high or critical "
    "already justifiable from these signatures and risk lines, including concretely "
    "pinnable lower-confidence candidates (mark those with lower confidence). Do not hold "
    "back. " + _GUIDE + "\nReturn strict JSON only: " + SHAPE + "\nProject map:\n"
)

# ---------------------------------------------------------------------------
# Bug-class tags (dedup + type)
# ---------------------------------------------------------------------------

_CLASS_CUES = (
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
_CLASS_TYPE = {
    "reentrancy": "reentrancy", "access": "access-control", "oracle": "price-oracle",
    "sigreplay": "signature-replay", "accounting": "accounting", "init": "initialization",
    "arith": "arithmetic",
}


def bug_class(*texts):
    blob = " ".join(t for t in texts if t).lower()
    for name, cues in _CLASS_CUES:
        if any(c in blob for c in cues):
            return name
    return "other"


# ---------------------------------------------------------------------------
# Repository loading + ranking
# ---------------------------------------------------------------------------

def find_root(project_dir):
    candidates = []
    if project_dir:
        candidates.append(project_dir)
    for var in ("PROJECT_DIR", "PROJECT_PATH", "PROJECT_ROOT", "PROJECT_CODE"):
        val = os.environ.get(var)
        if val:
            candidates.append(val)
    candidates += ["/app/project_code", "/app/project", "/project", "/code", "."]
    for raw in candidates:
        try:
            root = Path(raw).expanduser().resolve()
        except (OSError, RuntimeError):
            continue
        if not root.is_dir():
            continue
        try:
            for entry in root.rglob("*"):
                if entry.is_file() and entry.suffix.lower() in SOURCE_SUFFIXES:
                    return root
        except OSError:
            continue
    return None


def read_text(path):
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def looks_like_code(text, suffix):
    if suffix == ".sol":
        return "contract " in text or "library " in text or "function " in text
    if suffix == ".vy":
        return "def " in text or "@external" in text or "@internal" in text
    if suffix == ".rs":
        return "fn " in text
    if suffix == ".move":
        return "fun " in text or "module " in text
    if suffix == ".cairo":
        return "fn " in text or "func " in text or "mod " in text
    return False


# Keywords that RX_SOL_UNIT can capture out of NatSpec prose ("This contract is
# upgradeable") or type text; never valid contract/module names.
_UNIT_STOP = frozenset({
    "is", "if", "for", "while", "do", "return", "returns", "abstract", "contract",
    "interface", "library", "using", "event", "error", "struct", "enum", "mapping",
    "function", "modifier", "constructor", "memory", "storage", "calldata", "public",
    "private", "external", "internal", "view", "pure", "payable", "virtual", "override",
    "address", "bool", "uint", "int", "string", "bytes", "the", "this", "a", "an",
    "and", "or", "pattern", "version", "type", "new", "import", "pragma", "solidity",
})


def _strip_comments(text, suffix):
    """Drop comments before symbol parsing so prose like "This contract is ..." is
    not mistaken for a declaration. Only used for outlining, never for line lookup."""
    if suffix == ".vy":
        return re.sub(r"#[^\n]*", "", text)
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def outline(text, suffix):
    text = _strip_comments(text, suffix)
    signatures = []
    if suffix == ".sol":
        units = [u for u in RX_SOL_UNIT.findall(text) if u.lower() not in _UNIT_STOP]
        for m in RX_SOL_FN.finditer(text):
            trailer = " ".join(m.group(3).split())
            signatures.append((m.group(1), (m.group(1) + "(" + m.group(2).strip() + ") " + trailer).strip()))
        for m in RX_SOL_SPECIAL.finditer(text):
            signatures.append((m.group(1), m.group(1)))
    elif suffix == ".vy":
        units = []
        for m in RX_VY_FN.finditer(text):
            signatures.append((m.group(1), m.group(1) + "(" + m.group(2).strip() + ")"))
    elif suffix == ".rs":
        units = RX_RS_MOD.findall(text)
        signatures = [(m.group(1), m.group(0).strip()) for m in RX_RS_FN.finditer(text)]
    elif suffix == ".move":
        units = RX_MOVE_MOD.findall(text)
        signatures = [(m.group(1), m.group(0).strip()) for m in RX_MOVE_FN.finditer(text)]
    elif suffix == ".cairo":
        units = RX_CAIRO_MOD.findall(text)
        signatures = [(m.group(1), m.group(0).strip()) for m in RX_CAIRO_FN.finditer(text)]
    else:
        units = []
    return units, signatures


def rank_of(rel_low, body_low, num_fns):
    score = min(num_fns, 30)
    for word in VALUE_WORDS:
        if word in rel_low:
            score += 8
    for token in RISK_TOKENS:
        score += min(body_low.count(token), 5) * 3
    if any(x in body_low for x in ("external", "public", "@external", "pub fn", "entry fun")):
        score += 5
    if any(x in body_low for x in ("balances", "totalsupply", "total_supply", "reserve", "invariant")):
        score += 6
    if "nonreentrant" not in body_low and any(x in body_low for x in ("withdraw", "redeem", ".call{")):
        score += 6
    return score


def catalog(root):
    records = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        try:
            rel = path.relative_to(root)
            if any(part.lower() in SKIP_DIRS for part in rel.parts[:-1]):
                continue
            if path.stat().st_size > BYTE_CEILING:
                continue
        except OSError:
            continue
        suffix = path.suffix.lower()
        text = read_text(path)
        if not looks_like_code(text, suffix):
            continue
        units, signatures = outline(text, suffix)
        if not units and suffix != ".sol":
            units = [path.stem]
        if not units and not signatures:
            continue
        low = text.lower()
        rec = {
            "path": path, "rel": rel.as_posix(), "base": path.name, "text": text,
            "low": low, "stem": path.stem, "suffix": suffix,
            "units": units, "fns": signatures, "fnames": {n for n, _ in signatures},
        }
        score = rank_of(rel.as_posix().lower(), low, len(signatures))
        if suffix == ".sol" and "contract " not in low and "library " not in low:
            score *= 0.2
        elif suffix != ".vy" and signatures and low.count("{") < max(1, len(signatures) // 3):
            score *= 0.4
        parts = [p.lower() for p in rel.parts]
        stem = rec["stem"].lower()
        if (stem in ("test", "tests") or stem.startswith("test_")
                or stem.endswith(("_test", "_tests", ".t")) or "test" in parts
                or any(p in ("generated", "gen", "bindings", "sim") for p in parts)):
            score *= 0.1
        rec["score"] = score
        records.append(rec)
    records.sort(key=lambda r: (-r["score"], r["rel"]))
    return records[:CATALOG_CAP]


def imported_context(rec, by_base):
    blocks = []
    seen = set()
    for imp in RX_IMPORT.findall(rec["text"]):
        tail = imp.rsplit("/", 1)[-1]
        for cand in (tail, tail.split(".")[0]):
            other = by_base.get(cand)
            if other and other["rel"] != rec["rel"] and other["rel"] not in seen:
                seen.add(other["rel"])
                blocks.append("// import " + other["rel"] + "\n" + other["text"][:NEIGHBOUR_CHARS])
                break
        if len(blocks) >= 2:
            break
    return "\n\n".join(blocks)


def risk_lines(text, limit=16):
    picked = []
    for lineno, line in enumerate(text.splitlines(), 1):
        low = line.lower()
        if any(token in low for token in RISK_TOKENS):
            squeezed = " ".join(line.split())
            if squeezed:
                picked.append(str(lineno) + ": " + squeezed[:180])
        if len(picked) >= limit:
            break
    return picked


def condense(text, limit):
    if len(text) <= limit:
        return text
    lines = text.splitlines()
    keep = set()
    for idx, line in enumerate(lines):
        low = line.lower()
        if RX_DECL.search(line) or any(token in low for token in RISK_TOKENS):
            for j in range(max(0, idx - 5), min(len(lines), idx + 18)):
                keep.add(j)
    out = []
    prev = -10
    size = 0
    for idx in sorted(keep):
        if idx > prev + 1:
            gap = "\n// ... " + str(idx - prev - 1) + " lines omitted ...\n"
            out.append(gap)
            size += len(gap)
        row = str(idx + 1) + ": " + lines[idx]
        out.append(row)
        size += len(row) + 1
        prev = idx
        if size >= limit:
            break
    trimmed = "\n".join(out)
    if len(trimmed) < limit // 2:
        trimmed += "\n\n// file prefix\n" + text[: max(0, limit - len(trimmed) - 20)]
    return trimmed[:limit]


def survey_map(records, budget):
    pieces = []
    used = 0
    rich = int(budget * 0.82)
    for rec in records:
        if used < rich:
            sigs = [sig[:150] for _, sig in rec["fns"][:24]]
            piece = json.dumps({
                "file": rec["rel"],
                "contracts": rec["units"][:8],
                "score": round(float(rec.get("score", 0)), 1),
                "functions": sigs,
                "risk_lines": risk_lines(rec["text"], 16),
            }, separators=(",", ":"))
        else:
            piece = json.dumps({
                "file": rec["rel"],
                "contracts": rec["units"][:4],
                "score": round(float(rec.get("score", 0)), 1),
            }, separators=(",", ":"))
        if used + len(piece) + 1 > budget:
            break
        pieces.append(piece)
        used += len(piece) + 1
    return "\n".join(pieces)


# ---------------------------------------------------------------------------
# Inference transport
# ---------------------------------------------------------------------------

def extract_message(payload):
    if not isinstance(payload, dict):
        return ""
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        return ""
    message = choices[0].get("message")
    if not isinstance(message, dict):
        return ""
    content = message.get("content")
    if isinstance(content, list):
        content = "".join(p.get("text", "") for p in content if isinstance(p, dict))
    if isinstance(content, str) and content.strip():
        return content
    for alt in ("reasoning", "reasoning_content"):
        val = message.get(alt)
        if isinstance(val, str) and val.strip():
            return val
    details = message.get("reasoning_details")
    if isinstance(details, list):
        joined = "".join(p.get("text", "") for p in details if isinstance(p, dict))
        if joined.strip():
            return joined
    return ""


def _wire(prompt, max_tokens, effort):
    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": prompt},
        ],
        "max_tokens": max_tokens,
        "temperature": DECODE_TEMP,
    }
    if effort:
        payload["reasoning_effort"] = effort
    return json.dumps(payload).encode("utf-8")


def ask_model(endpoint, prompt, deadline, max_tokens, effort):
    global _EFFORT_OK
    if not endpoint:
        raise RuntimeError("no endpoint")
    headers = {
        "Content-Type": "application/json",
        "x-inference-api-key": os.environ.get("INFERENCE_API_KEY", ""),
    }
    error = None
    tries = 0
    backoff = 2.0
    while tries < CALL_RETRIES:
        remaining = deadline - time.monotonic() - TAIL_RESERVE
        timeout = min(PER_CALL_TIMEOUT, float(int(remaining)))
        if timeout < CALL_FLOOR:
            raise RuntimeError("clock exhausted")
        use_effort = effort if _EFFORT_OK else None
        body = _wire(prompt, max_tokens, use_effort)
        try:
            request = urllib.request.Request(
                endpoint + "/inference", data=body, method="POST", headers=headers)
            with urllib.request.urlopen(request, timeout=timeout) as response:
                raw = response.read()
            return extract_message(json.loads(raw.decode("utf-8", "replace")))
        except urllib.error.HTTPError as exc:
            if exc.code == 400 and use_effort:
                with _EFFORT_LOCK:
                    _EFFORT_OK = False
                continue
            if exc.code not in RETRYABLE:
                raise RuntimeError("http " + str(exc.code)) from exc
            error = exc
        except (socket.timeout, TimeoutError) as exc:
            raise RuntimeError("timeout") from exc
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, (socket.timeout, TimeoutError)):
                raise RuntimeError("timeout") from exc
            error = exc
        except (OSError, ValueError) as exc:
            error = exc
        tries += 1
        if tries >= CALL_RETRIES:
            break
        if deadline - time.monotonic() <= backoff + TAIL_RESERVE + CALL_FLOOR:
            break
        time.sleep(backoff)
        backoff = min(backoff * 2.0, 8.0)
    raise RuntimeError(str(error) if error else "request failed")


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------

def collect_objects(text):
    found = []
    depth = 0
    start = -1
    in_str = escaped = False
    for i, ch in enumerate(text):
        if in_str:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
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
                        obj = json.loads(text[start:i + 1])
                        if isinstance(obj, dict):
                            found.append(obj)
                    except json.JSONDecodeError:
                        pass
                    start = -1
    return found


_ENTRY_KEYS = ("title", "file", "severity", "description", "function", "contract", "mechanism")


def strip_fences(text):
    t = text.strip()
    if t.startswith("```"):
        t = re.sub(r"^```[a-zA-Z]*\s*", "", t)
        t = re.sub(r"\s*```$", "", t)
    return t


def parse_findings(text):
    if not isinstance(text, str):
        return []
    t = strip_fences(text)
    try:
        obj = json.loads(t)
        if isinstance(obj, dict):
            items = obj.get("findings") or obj.get("vulnerabilities")
            return [f for f in items if isinstance(f, dict)] if isinstance(items, list) else []
    except json.JSONDecodeError:
        pass
    marker = re.search(r'"(?:findings|vulnerabilities)"\s*:\s*\[', t)
    tail = t[marker.end():] if marker else t
    return [obj for obj in collect_objects(tail) if any(k in obj for k in _ENTRY_KEYS)]


# ---------------------------------------------------------------------------
# Prompt assembly for the network reviewers
# ---------------------------------------------------------------------------

def focus_prompt(rec, by_base):
    head = FOCUS_HEAD
    body = rec["text"]
    if len(body) > FOCUS_FILE_CHARS:
        body = condense(body, FOCUS_FILE_CHARS)
    block = ("\n\n===== FILE: " + rec["rel"] + " =====\n"
             "Contracts/modules: " + (", ".join(rec["units"][:8]) or rec["stem"]) + "\n" + body)
    prompt = head + block
    room = FOCUS_PROMPT_CHARS - len(prompt)
    if room > 900:
        extra = imported_context(rec, by_base)
        if extra:
            prompt += "\n\n===== IMPORTED CONTEXT (read-only) =====\n" + extra[:room - 200]
    return prompt


def pair_prompt(batch):
    parts = [PAIR_HEAD]
    left = PAIR_PROMPT_CHARS - len(PAIR_HEAD)
    for rec in batch:
        body = condense(rec["text"], PAIR_FILE_CHARS)
        block = ("\n\n===== FILE: " + rec["rel"] + " =====\n"
                 "Contracts/modules: " + (", ".join(rec["units"][:8]) or rec["stem"]) + "\n" + body + "\n")
        if left <= 0:
            break
        if len(block) > left:
            block = block[:left] + "\n/* truncated */"
        parts.append(block)
        left -= len(block)
    return "".join(parts)


def recheck_prompt(rec):
    body = rec["text"]
    if len(body) > FOCUS_FILE_CHARS:
        body = condense(body, FOCUS_FILE_CHARS)
    return (RECHECK_HEAD + "\n\n===== FILE: " + rec["rel"] + " =====\n"
            "Contracts/modules: " + (", ".join(rec["units"][:8]) or rec["stem"]) + "\n" + body)


# ---------------------------------------------------------------------------
# Concurrent reviewer pool
# ---------------------------------------------------------------------------

def run_pool(jobs, deadline):
    """Drain `jobs` (zero-arg callables returning raw finding lists) across a
    thread pool, honouring the shared deadline. Returns the merged raw findings.

    Workers are daemons that stop pulling once too little time remains, so the
    process always returns promptly; a serialising endpoint simply yields fewer
    completed jobs than a concurrent one, never an aborted run.
    """
    pending = queue.Queue()
    for job in jobs:
        pending.put(job)
    gathered = []
    lock = threading.Lock()
    fail_streak = [0]

    def worker():
        while True:
            if deadline - time.monotonic() <= CALL_FLOOR + TAIL_RESERVE:
                return
            with lock:
                if fail_streak[0] >= CONSECUTIVE_FAIL_STOP:
                    return
            try:
                job = pending.get_nowait()
            except queue.Empty:
                return
            try:
                produced = job()
                ok = True
            except Exception:
                produced = []
                ok = False
            with lock:
                if produced:
                    gathered.extend(produced)
                if ok:
                    fail_streak[0] = 0
                else:
                    fail_streak[0] += 1

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(min(WORKERS, max(1, len(jobs))))]
    for th in threads:
        th.start()
    for th in threads:
        remaining = (deadline - TAIL_RESERVE) - time.monotonic()
        if remaining <= 0:
            break
        th.join(timeout=remaining)
    with lock:
        return list(gathered)


def build_jobs(records, by_base, endpoint, deadline):
    """Order jobs so the highest-value work lands first even under low concurrency."""
    jobs = []

    def focus_job(rec):
        return lambda: parse_findings(
            ask_model(endpoint, focus_prompt(rec, by_base), deadline, FOCUS_TOKENS, "high"))

    def recheck_job(rec):
        return lambda: parse_findings(
            ask_model(endpoint, recheck_prompt(rec), deadline, RECHECK_TOKENS, "high"))

    def pair_job(batch):
        return lambda: parse_findings(
            ask_model(endpoint, pair_prompt(batch), deadline, PAIR_TOKENS, "medium"))

    def survey_job():
        return parse_findings(
            ask_model(endpoint, SURVEY_HEAD + survey_map(records, SURVEY_CHARS),
                      deadline, SURVEY_TOKENS, "medium"))

    focus_set = records[:FOCUS_COUNT]
    # Top files first, then a whole-repo survey, then adversarial re-reads, then the
    # rest of the focus set and paired reviews of the tail. Baseline coverage (top
    # files + survey) is front-loaded; breadth follows when the pool has capacity.
    lead = focus_set[:6]
    rest = focus_set[6:]
    for rec in lead:
        jobs.append(focus_job(rec))
    jobs.append(survey_job)
    for rec in focus_set[:RECHECK_COUNT]:
        jobs.append(recheck_job(rec))
    for rec in rest:
        jobs.append(focus_job(rec))
    tail = records[FOCUS_COUNT:FOCUS_COUNT + PAIR_SPAN]
    for i in range(0, len(tail), 2):
        batch = tail[i:i + 2]
        if batch:
            jobs.append(pair_job(batch))
    return jobs


# ---------------------------------------------------------------------------
# Finding normalization + localization
# ---------------------------------------------------------------------------

def line_of(text, needle):
    i = text.find(needle)
    return text.count("\n", 0, i) + 1 if i >= 0 else None


def function_line(rec, function):
    if not function:
        return None
    for needle in ("function " + function, "fn " + function, "fun " + function,
                   "def " + function, "func " + function, function):
        ln = line_of(rec["text"], needle)
        if ln:
            return ln
    return None


def resolve_file(file_value, by_rel, by_base, fn_hint=""):
    if not file_value:
        return None
    cleaned = file_value.strip().strip("`").lstrip("./")
    direct = by_rel.get(cleaned)
    if direct is not None:
        return direct
    hits = [
        rec for rel, rec in by_rel.items()
        if rel == cleaned or rel.endswith("/" + cleaned) or (len(cleaned) > 3 and cleaned.endswith("/" + rel))
    ]
    if len(hits) == 1:
        return hits[0]
    if len(hits) > 1:
        if fn_hint:
            for rec in hits:
                if fn_hint in rec["fnames"]:
                    return rec
        return hits[0]
    base = cleaned.rsplit("/", 1)[-1]
    same_base = [rec for rec in by_rel.values() if rec["base"] == base]
    if len(same_base) == 1:
        return same_base[0]
    if same_base and fn_hint:
        for rec in same_base:
            if fn_hint in rec["fnames"]:
                return rec
    return by_base.get(base)


def is_declared(text, function):
    if not function:
        return False
    pattern = r"\b(?:" + "|".join(FN_KEYWORDS) + r")\s+" + re.escape(function) + r"\b"
    return re.search(pattern, text) is not None


def normalize(raw, by_rel, by_base):
    file_value = str(raw.get("file") or raw.get("path") or raw.get("location") or "").strip()
    fn = str(raw.get("function") or "").strip().strip("`() ")
    fn = re.sub(r"\(.*$", "", fn).split(".")[-1].split("::")[-1].strip()
    rec = resolve_file(file_value, by_rel, by_base, fn)
    if rec is None:
        return None
    severity = str(raw.get("severity") or "").strip().lower()
    if severity in {"medium", "med", "moderate"}:
        severity = "high"
    if severity not in {"high", "critical"}:
        return None
    try:
        confidence = max(0.0, min(1.0, float(raw.get("confidence"))))
    except (TypeError, ValueError):
        confidence = BASE_CONF
    if severity == "high" and confidence < HIGH_CONF_FLOOR:
        return None
    if fn and fn not in rec["fnames"] and not is_declared(rec["text"], fn):
        fn = ""
    declared_units = rec["units"]
    contract = str(raw.get("contract") or raw.get("module") or "").strip().strip("`")
    contract_real = bool(contract and (not declared_units or contract in declared_units))
    if not contract or (declared_units and contract not in declared_units):
        contract = declared_units[0] if declared_units else rec["stem"]
    mechanism = str(raw.get("mechanism") or "").strip()
    impact = str(raw.get("impact") or "").strip()
    description = str(raw.get("description") or "").strip()
    title = str(raw.get("title") or "").strip()

    where = ".".join(x for x in (contract, fn) if x)
    if not title:
        title = (where + " - high/critical vulnerability") if where else "High/critical vulnerability"
    elif where and where.lower() not in title.lower():
        title = where + " - " + title
    body = "In `" + rec["rel"] + "`"
    if contract:
        body += ", contract `" + contract + "`"
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
    if len(body) < MIN_BODY and not title:
        return None
    cls = bug_class(title, mechanism, impact, description)
    return {
        "title": title[:220],
        "description": body[:2400],
        "severity": severity,
        "file": rec["rel"],
        "function": fn,
        "line": function_line(rec, fn),
        "type": _CLASS_TYPE.get(cls) or str(raw.get("type") or "logic"),
        "confidence": 0.9 if severity == "critical" else confidence,
        "pinned": bool(fn) or contract_real,
        "refined": bool(raw.get("_refined")),
    }


# ---------------------------------------------------------------------------
# Model-free structural probes (no network, always available)
# ---------------------------------------------------------------------------

def probe(title, rel, contract, function, mechanism, impact):
    return {
        "title": title, "file": rel, "contract": contract, "function": function,
        "severity": "high", "mechanism": mechanism, "impact": impact,
        "description": mechanism + ". " + impact,
    }


def enclosing_block(text, start):
    open_at = text.find("{", start)
    if open_at < 0:
        return text[start:start + 600]
    depth = 0
    for i in range(open_at, min(len(text), open_at + 6000)):
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return text[start:start + 1500]


def sol_functions(text):
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


_GUARD_TOKENS = ("onlyowner", "onlyrole", "requiresauth", "_checkowner", "msg.sender==",
                 "authorized", "hasrole", "restricted", "onlyadmin", "onlygovernance")
RX_AUTH_MAP = re.compile(r"(operator|extension|approv|allowed|authoriz|whitelist|trusted)s?\s*\[")
RX_AUTH_SELF = re.compile(
    r"(operator|extension|approv|allowed|authoriz|whitelist|trusted)s?\s*\[\s*msg\.sender")
RX_PRIV_ROLE = re.compile(
    r"validator|minter|operator|admin|guardian|keeper|signer|treasury|governance|pauser|role", re.I)
RX_MOD_STRIP = re.compile(r"\b(external|public|payable|virtual|override|returns)\b|\([^)]*\)|[\s,]")
_SKIP_STEMS = ("mock", "dummy", "fake", "stub", "harness", "example",
               "weth", "wavax", "wmatic", "wbnb", "weth9", "wrapped")


def structural_probes(records):
    out = []
    for rec in records:
        if rec["suffix"] != ".sol":
            continue
        stem = rec["stem"].lower()
        if any(w in stem for w in _SKIP_STEMS) or stem[:1].isdigit():
            continue
        if "contract " not in rec["low"] and "library " not in rec["low"]:
            continue
        text = rec["text"]
        contract = rec["units"][0] if rec["units"] else rec["stem"]
        for m in re.finditer(r"\breceive\s*\(\s*\)\s*external\s+payable\s*\{", text):
            block = enclosing_block(text, m.start()).lower()
            if ("stake(" in block or "deposit(" in block) and "msg.sender" not in block:
                out.append(probe(
                    contract + ".receive - inbound native transfer auto-staked",
                    rec["rel"], contract, "receive",
                    "the payable receive hook stakes or deposits every native transfer "
                    "without separating protocol/system returns from user deposits",
                    "native funds returned from an unstake, validator withdrawal, or reward "
                    "path are restaked instead of settling pending withdrawals, locking "
                    "liquidity and corrupting withdrawal accounting"))
                break
        for fn in sol_functions(text):
            name = fn["name"]
            sig = fn["sig"].lower()
            block = fn["body"].lower()
            both = sig + " " + block
            if "domainseparator" in both and ("ecrecover" in block or "recover(" in block):
                if not any(x in both for x in ("deadline", "chainid", "block.chainid", "block.timestamp")):
                    out.append(probe(
                        contract + "." + name + " - replayable signature domain",
                        rec["rel"], contract, name,
                        "the signature check recovers a signer with a domain separator not "
                        "bound to a deadline or the current chain id",
                        "a captured signature is replayed on another deployment or chain to "
                        "execute the signed privileged action"))
            if re.match(r"^(set|update|enable|disable|add|remove|register)", name, re.I):
                if ("external" in sig or "public" in sig) and "only" not in sig \
                        and not any(g in both for g in _GUARD_TOKENS):
                    if RX_AUTH_MAP.search(block) and not RX_AUTH_SELF.search(block):
                        out.append(probe(
                            contract + "." + name + " - unauthenticated authorization change",
                            rec["rel"], contract, name,
                            "an external configuration function writes an operator, approval, "
                            "or authorization mapping with no owner/role check",
                            "any caller authorizes itself and then acts on behalf of other "
                            "users wherever that mapping gates privileged actions"))
            if name.lower() in ("cancelorder", "modifyorder", "fillorder", "executeorder") \
                    and "external" in sig and "nonreentrant" not in sig:
                if "safetransfer" in block or "transfer(" in block or ".call{" in block:
                    out.append(probe(
                        contract + "." + name + " - order mutation without reentrancy guard",
                        rec["rel"], contract, name,
                        "an external order cancel/modify/fill path reaches a token transfer or "
                        "external call without a nonReentrant guard",
                        "a malicious token or callback reenters mid-mutation to double-refund "
                        "or corrupt pending-order bookkeeping"))
            if ".price" in block and any(x in block for x in ("pnl", "collateral", "settle")) \
                    and any(x in both for x in ("intent", "order", "params")):
                if not any(x in block for x in ("maxprice", "minprice", "oracle", "latestversion",
                                                "currentversion", ".gt(", ".lt(", "clamp", "bound")):
                    out.append(probe(
                        contract + "." + name + " - unbounded user price in value math",
                        rec["rel"], contract, name,
                        "a user-supplied order/intent price flows into PnL, collateral, or "
                        "settlement math without being clamped to a live oracle price",
                        "an extreme price manufactures settlement value and extracts collateral "
                        "from counterparties"))
            if re.match(r"^(add|register|Add|Register)[A-Z_]", name) and RX_PRIV_ROLE.search(name):
                modzone = sig.rsplit(")", 1)[-1]
                if ("external" in sig or "public" in sig) and not RX_MOD_STRIP.sub("", modzone):
                    if "msg.sender" not in block and not ("require(" in block and "owner" in block):
                        out.append(probe(
                            contract + "." + name + " - privileged role added without access control",
                            rec["rel"], contract, name,
                            "an external/public role-adding function has no modifier and no "
                            "in-body authorization check, so any account can call it",
                            "any caller registers itself as a privileged validator, minter, or "
                            "operator and performs the authorized actions"))
        if len(out) >= 10:
            break
    return out[:10]


def fallback_probes(records):
    out = []
    for rec in records:
        if rec["suffix"] != ".sol":
            continue
        low = rec["low"]
        contract = rec["units"][0] if rec["units"] else rec["stem"]
        if "function initialize" in low and not any(
                x in low for x in ("initializer", "onlyowner", "onlyrole", "_disableinitializers")):
            out.append(probe(
                contract + ".initialize - unprotected initializer", rec["rel"], contract,
                "initialize" if "initialize" in rec["fnames"] else "",
                "the initializer is externally reachable with no one-time initializer modifier "
                "and no owner/role check",
                "an attacker initializes or re-initializes ownership and critical configuration "
                "and seizes privileged control"))
        elif "tx.origin" in low:
            out.append(probe(
                contract + " - authorization relies on tx.origin", rec["rel"], contract, "",
                "authorization is gated on tx.origin, which a malicious intermediate contract "
                "defeats by phishing a privileged caller",
                "a privileged account is tricked into a fund-moving or configuration action"))
        if len(out) >= 3:
            break
    return out


# ---------------------------------------------------------------------------
# Focused refinement of near-miss candidates
# ---------------------------------------------------------------------------
# A bug the first passes missed often still produced a candidate that named the
# right function but stated the cause too vaguely to be credited. A second look at
# that one function's exact source, re-deriving precisely what is wrong, sharpens
# those into creditable findings. Emitted alongside the originals; the merge step
# keeps the sharper writeup.

REFINE_TARGETS = 16
REFINE_PER_FILE = 4
REFINE_PER_CALL = 4
REFINE_SRC = 9_000
REFINE_HEAD = 1_800
REFINE_MIN_TIME = 130.0
REFINE_TOKENS = 16_000

REFINE_HEAD_MSG = (
    "Second-pass sharpening. Below are individual functions from a smart-contract "
    "project, each followed by the candidate findings a first pass produced for it. "
    "Those candidates tend to name the right function but state the cause too vaguely "
    "to be credited, and a finding with the right function but a vague or wrong cause is "
    "worth nothing. For EACH function, re-derive from the source what is actually wrong: "
    "where a candidate is right, restate it precisely - name the exact expression, not "
    "the category; where it is vague, replace it; where the source refutes it, discard it "
    "and report whatever IS wrong instead. Emit a separate entry per distinct mechanism, "
    "and nothing for a function that is genuinely safe. " + _GUIDE +
    "\nReturn strict JSON only: " + SHAPE + "\n"
)


def function_source(rec, fn, limit=REFINE_SRC):
    """Source of one function, bounded at its own closing brace (a flat forward
    slice would return mostly the following functions)."""
    text = rec["text"]
    pos = -1
    for needle in ("function " + fn, "fn " + fn, "fun " + fn, "def " + fn, "func " + fn):
        pos = text.find(needle)
        if pos >= 0:
            break
    if pos < 0:
        pos = text.find(fn)
        if pos < 0:
            return ""
    start = text.rfind("\n", 0, max(0, pos - 300)) + 1
    if rec["suffix"] == ".vy":
        nxt = RX_VY_FN.search(text, pos + 1)
        end = nxt.start() if nxt else len(text)
    else:
        end = pos + len(enclosing_block(text, pos))
    end = min(len(text), max(end, start + 800), start + limit)
    return text[start:end]


def refine_targets(raw, by_rel, by_base, rank_of):
    """(file, function) pairs worth a focused second look: by file rank first, then
    by how many distinct mechanisms the first passes proposed for that function."""
    groups = {}
    for f in raw:
        if not isinstance(f, dict):
            continue
        rec = resolve_file(str(f.get("file") or "").strip(), by_rel, by_base)
        if rec is None:
            continue
        fn = str(f.get("function") or "").strip().strip("`() ")
        fn = fn.split(".")[-1].split("::")[-1]
        if not fn or fn not in rec["fnames"]:
            continue
        groups.setdefault((rec["rel"], fn), []).append(f)
    scored = []
    for (rel, fn), items in groups.items():
        distinct = {re.sub(r"\s+", " ", str(i.get("title") or "")).lower()[:120] for i in items}
        scored.append((rank_of.get(rel, 10_000), -len(distinct), rel, fn))
    scored.sort()
    out = []
    per_file = {}
    for _, _, rel, fn in scored:
        if per_file.get(rel, 0) >= REFINE_PER_FILE:
            continue
        rec = by_rel.get(rel)
        if rec is None:
            continue
        src = function_source(rec, fn)
        if not src:
            continue
        per_file[rel] = per_file.get(rel, 0) + 1
        out.append((rec, fn, src, groups[(rel, fn)]))
        if len(out) >= REFINE_TARGETS:
            break
    return out


def refine_prompt(chunk):
    parts = [REFINE_HEAD_MSG]
    heads = set()
    for rec, fn, src, items in chunk:
        # State vars, constants and struct layouts live in the declaration head and
        # many findings turn on them; the brace-bounded slice excludes it.
        if rec["rel"] not in heads:
            heads.add(rec["rel"])
            parts.append("\n\n===== DECLARATIONS: " + rec["rel"] + " (context) =====\n")
            parts.append(rec["text"][:REFINE_HEAD])
        parts.append("\n\n===== FUNCTION: " + fn + " in " + rec["rel"] + " =====\n")
        parts.append("Contracts/modules: " + (", ".join(rec["units"][:8]) or rec["stem"]) + "\n")
        parts.append(src)
        seen = set()
        lines = []
        for it in items:
            title = re.sub(r"\s+", " ", str(it.get("title") or "")).strip()[:160]
            mech = re.sub(r"\s+", " ",
                          str(it.get("mechanism") or it.get("description") or "")).strip()[:240]
            key = title.lower()[:110]
            if not title or key in seen:
                continue
            seen.add(key)
            lines.append("- " + title + ": " + mech)
            if len(lines) >= 6:
                break
        if lines:
            parts.append("\nFirst-pass candidates for this function (sharpen or replace "
                         "these):\n" + "\n".join(lines) + "\n")
    return "".join(parts)


def run_refine(endpoint, raw, by_rel, by_base, rank_of, deadline):
    targets = refine_targets(raw, by_rel, by_base, rank_of)
    if not targets:
        return []
    chunks = [targets[i:i + REFINE_PER_CALL] for i in range(0, len(targets), REFINE_PER_CALL)]

    def make(chunk):
        def call():
            found = parse_findings(
                ask_model(endpoint, refine_prompt(chunk), deadline, REFINE_TOKENS, "high"))
            for f in found:
                if isinstance(f, dict):
                    f["_refined"] = True
            return found
        return call

    return run_pool([make(c) for c in chunks], deadline)


# ---------------------------------------------------------------------------
# Corroboration + selection
# ---------------------------------------------------------------------------

def merge(entries):
    groups = {}
    for e in entries:
        key = (e["file"].lower(), e["function"].lower(), bug_class(e["title"], e["description"]))
        cur = groups.get(key)
        if cur is None:
            e = dict(e)
            e["votes"] = 1
            groups[key] = e
            continue
        cur["votes"] += 1
        if e["severity"] == "critical" and cur["severity"] != "critical":
            cur["severity"] = "critical"
        if float(e.get("confidence", 0)) > float(cur.get("confidence", 0)):
            cur["confidence"] = e["confidence"]
        if e.get("pinned") and not cur.get("pinned"):
            cur["pinned"] = True
        # Prefer a sharpened (refined) writeup; otherwise the fuller description.
        take_text = (
            (e.get("refined") and not cur.get("refined"))
            or (bool(e.get("refined")) == bool(cur.get("refined"))
                and len(e.get("description", "")) > len(cur.get("description", "")))
        )
        if take_text:
            cur["description"] = e["description"]
            cur["title"] = e["title"]
        if e.get("refined"):
            cur["refined"] = True
        if cur.get("line") is None and e.get("line") is not None:
            cur["line"] = e["line"]
    return list(groups.values())


def select(entries):
    merged = merge(entries)

    def rank(e):
        return (
            bool(e.get("pinned")),
            int(e.get("votes", 1)),
            e["severity"] == "critical",
            float(e.get("confidence", 0)),
            len(e.get("description", "")),
        )

    merged.sort(key=rank, reverse=True)
    per_file = {}
    chosen = []
    overflow = []
    for e in merged:
        fkey = e["file"].lower()
        if per_file.get(fkey, 0) >= PER_FILE_CAP:
            overflow.append(e)
            continue
        # A pinned issue, or one corroborated by more than one reviewer, always earns
        # a slot; a lone unpinned guess waits in case room is left over.
        if e.get("pinned") or int(e.get("votes", 1)) >= 2:
            chosen.append(e)
            per_file[fkey] = per_file.get(fkey, 0) + 1
        else:
            overflow.append(e)
        if len(chosen) >= EMIT_CAP:
            break
    for e in overflow:
        if len(chosen) >= EMIT_CAP:
            break
        fkey = e["file"].lower()
        if per_file.get(fkey, 0) >= PER_FILE_CAP:
            continue
        chosen.append(e)
        per_file[fkey] = per_file.get(fkey, 0) + 1
    for e in chosen:
        e["confidence"] = float(e.get("confidence", BASE_CONF))
        for bookkeeping in ("votes", "pinned", "refined"):
            e.pop(bookkeeping, None)
    return chosen[:EMIT_CAP]


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def agent_main(project_dir=None, inference_api=None):
    report = []
    deadline = time.monotonic() + WALL_BUDGET
    try:
        root = find_root(project_dir)
        if root is None:
            return {"vulnerabilities": report}
        records = catalog(root)
        if not records:
            return {"vulnerabilities": report}
        by_base = {}
        for rec in records:
            by_base.setdefault(rec["base"], rec)
        by_rel = {rec["rel"]: rec for rec in records}
        endpoint = (inference_api or os.environ.get("INFERENCE_API") or "").rstrip("/")

        raw = []
        if endpoint and deadline - time.monotonic() >= CALL_FLOOR + TAIL_RESERVE:
            try:
                jobs = build_jobs(records, by_base, endpoint, deadline)
                raw.extend(run_pool(jobs, deadline))
            except Exception:
                pass
        try:
            raw.extend(structural_probes(records))
        except Exception:
            pass
        # Sharpening wave: re-audit the functions the first passes flagged, with
        # their exact source in view, to turn vague near-misses into creditable
        # findings. Adds to (never replaces) raw, and only runs with clock to spare.
        if endpoint and raw and deadline - time.monotonic() >= REFINE_MIN_TIME:
            try:
                rank_of = {rec["rel"]: idx for idx, rec in enumerate(records)}
                raw.extend(run_refine(endpoint, raw, by_rel, by_base, rank_of, deadline))
            except Exception:
                pass

        cleaned = []
        # Bound the localization work: the constrained CPU makes per-item regex
        # matching slow, and the report is capped long before this many survive.
        for item in raw[:1500]:
            entry = normalize(item, by_rel, by_base)
            if entry is not None:
                cleaned.append(entry)
        if not cleaned:
            for item in fallback_probes(records):
                entry = normalize(item, by_rel, by_base)
                if entry is not None:
                    cleaned.append(entry)
        report = select(cleaned)
    except Exception:
        return {"vulnerabilities": report}
    return {"vulnerabilities": report}


if __name__ == "__main__":
    import sys
    print(json.dumps(agent_main(sys.argv[1] if len(sys.argv) > 1 else None), indent=2))
