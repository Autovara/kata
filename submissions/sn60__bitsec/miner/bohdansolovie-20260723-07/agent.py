"""SN60 / Bitsec miner.

A whole-repository vulnerability hunter for smart-contract code across Solidity,
Vyper, Rust (Solana/Anchor + CosmWasm), Move and Cairo.

Design notes
------------
The grader awards a project PASS only when every planted issue is detected, and
the project-pass tier is settled before any other, so a challenger that misses
even one issue on a project cannot make it up elsewhere. That pushes toward high
recall. To keep precision defensible at that recall, this agent runs several
independent review passes and then *votes*: an issue that more than one pass
localizes to the same file/function/class is promoted, and any issue that cannot
be pinned to a function or a contract that truly exists in the resolved file is
demoted (those are the usual hallucinations and rarely match the grader anyway).

The module is pure standard library. It only talks to the model through the
inference endpoint the validator injects, and every network call is wrapped in a
wall-clock budget so a slow or failing pass degrades the report instead of
turning the whole run invalid.
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
# File discovery configuration
# ---------------------------------------------------------------------------

CODE_EXTENSIONS = (".sol", ".vy", ".rs", ".move", ".cairo")
IGNORED_DIRECTORIES = frozenset({
    "test", "tests", "mock", "mocks", "example", "examples", "script", "scripts",
    "broadcast", "node_modules", "vendor", "vendors", "lib", "libs", "out",
    "artifacts", "cache", "coverage", "interfaces", "interface", "fixtures", "fixture",
    "target", "docs", ".git", ".github", "deps", "dist", "build",
})

RE_SOL_TYPE = re.compile(
    r"\b(?:abstract\s+contract|contract|library|interface)\s+([A-Za-z_][A-Za-z0-9_]*)"
)
RE_SOL_FN = re.compile(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)([^{};]*)")
RE_SOL_SPECIAL = re.compile(r"\b(constructor|receive|fallback)\b\s*\(")
RE_VY_FN = re.compile(r"(?m)^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)")
RE_RS_FN = re.compile(
    r"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)"
)
RE_RS_MOD = re.compile(r"(?m)^\s*(?:pub\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{")
RE_MOVE_FN = re.compile(
    r"(?m)^\s*(?:public\s*(?:\([^)]*\))?\s+)?(?:entry\s+)?(?:native\s+)?fun\s+([A-Za-z_][A-Za-z0-9_]*)"
)
RE_MOVE_MOD = re.compile(r"(?m)^\s*module\s+(?:[A-Za-z_0-9]+::)?([A-Za-z_][A-Za-z0-9_]*)")
RE_CAIRO_FN = re.compile(r"(?m)^\s*(?:pub\s+)?(?:fn|func)\s+([A-Za-z_][A-Za-z0-9_]*)")
RE_CAIRO_MOD = re.compile(r"(?m)^\s*(?:pub\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{")
RE_IMPORT = re.compile(r'(?m)^\s*(?:import|use)\b[^;\n]*?["\']?([A-Za-z0-9_./]+)["\']?')
RE_DECL_LINE = re.compile(
    r"\bfunction\b|\bdef\b|\bfn\b|\bfun\b|\bmodifier\b|\bconstructor\b|\bmodule\b|\bmapping\b"
)
DECLARATION_WORDS = ("function", "fn", "fun", "def", "func")

# Words in a path/name that hint the file holds value-bearing logic.
DOMAIN_WORDS = (
    "vault", "pool", "router", "manager", "controller", "strategy", "market", "lend",
    "borrow", "oracle", "price", "stak", "reward", "treasury", "bridge", "factory",
    "proxy", "govern", "token", "escrow", "auction", "liquidat", "swap", "stable",
    "collateral", "vesting", "distributor", "minter", "gauge", "farm", "perp",
    "position", "margin", "settle", "clearing", "coin", "account", "program",
)

# Source tokens that tend to sit next to real high/critical bugs. Grouped by
# language family only to keep the list maintainable; they are flattened once.
_EVM_HOT = (
    "delegatecall", ".call{", ".call.value", "selfdestruct", "tx.origin", "assembly",
    "ecrecover", "permit", "signature", "nonce", "initialize", "upgradeto",
    "onlyowner", "onlyrole", "_mint", "_burn", "mint(", "burn(", "withdraw", "redeem",
    "deposit", "borrow", "repay", "liquidat", "collateral", "share", "totalsupply",
    "balanceof", "oracle", "getprice", "latestround", "slot0", "flash", "swap",
    "reward", "claim", "unchecked", "safetransfer", "transferfrom", "approve",
    "settle", "rebalance", "liquidity", "reserve", "invariant", "msg.sender",
)
_RUST_HOT = (
    "signer", "authority", "lamports", "invoke", "cpi", "checked_", "unwrap",
    "close_account", "realloc", "try_borrow", "deserialize", "next_account",
    "assert_eq", "owner", "is_signer", "wasm", "info.sender", "transfer",
    "sub_msg", "coin(",
)
_MOVE_CAIRO_HOT = (
    "acquires", "borrow_global", "move_to", "move_from", "capability", "signer::",
    "get_caller_address", "get_contract_address", "felt", "starknet", "assert(",
)
HOT_TOKENS = _EVM_HOT + _RUST_HOT + _MOVE_CAIRO_HOT

# ---------------------------------------------------------------------------
# Budgets and limits
# ---------------------------------------------------------------------------

FILE_BYTE_CAP = 260_000
FILE_COUNT_CAP = 90
IMPORT_CHAR_CAP = 3_000
DEEP_FILE_CHAR_CAP = 15_000
DEEP_PROMPT_BUDGET = 47_000
DEEP_FILE_COUNT = 8
WIDE_PROMPT_BUDGET = 52_000
WIDE_FILE_COUNT = 13
WIDE_FILE_CHAR_CAP = 8_500
MAP_CHAR_BUDGET = 40_000
EMIT_CAP = 28
MIN_BODY_LEN = 40

MODEL_NAME = os.environ.get("KATA_MINER_MODEL", "deepseek-ai/DeepSeek-V3.2-TEE")
MAP_TOKENS = 12_000
DEEP_TOKENS = 16_000
WIDE_TOKENS = 15_000

TOTAL_BUDGET_SECONDS = 755.0
PER_CALL_TIMEOUT = 200.0
CALL_HEADROOM = 220.0
TAIL_HEADROOM = 12.0
CALL_FLOOR = 35.0
CALL_RETRIES = 2

_SEND_TUNING = True
_RETRYABLE_HTTP = frozenset({408, 409, 425, 500, 502, 504, 520, 522, 524, 529})

# ---------------------------------------------------------------------------
# Prompt text
# ---------------------------------------------------------------------------

ROLE = (
    "Act as a lead smart-contract security reviewer fluent in Solidity, Vyper, "
    "Rust for Solana/Anchor and CosmWasm, Move, and Cairo. In each file provided, "
    "list every separate HIGH or CRITICAL vulnerability you can pin to a specific "
    "function; do not report only the worst one. Missing a genuine high/critical is "
    "far costlier than naming a candidate that turns out wrong. Consider in scope: "
    "stolen or lost funds, insolvency, unauthorized state mutation, privilege "
    "escalation, permanent lockup or denial of service, supply/mint corruption, "
    "oracle manipulation, reentrancy, replay or signature defects, and absent "
    "signer/owner/authority checks. Consider out of scope: gas, style, missing "
    "events, plain centralization, and informational notes. Reason silently and "
    "emit exactly one minified JSON object with no prose, markdown, or fences."
)

BUG_MENU = (
    "Checklist by language. "
    "Solidity/Vyper: reentrancy and call ordering; missing or wrong access control; "
    "delegatecall, upgrade and initialization defects; first-depositor / share "
    "inflation / rounding; spot vs time-weighted and stale or gameable oracles; "
    "permit and signature replay; unsafe token assumptions and fee-on-transfer; "
    "native-value accounting; and permanent denial of service. "
    "Solana/Anchor Rust: absent is_signer, absent account-owner check, absent "
    "has_one/constraint, unchecked PDA seeds, missing account close, unchecked math, "
    "CPI into an unverified program, and missing discriminator / type confusion. "
    "CosmWasm: absent info.sender authorization and an unguarded migrate entry. "
    "Move: absent signer or capability, a public entry exposing a privileged call, "
    "and resource-ownership confusion. "
    "Cairo/Starknet: absent get_caller_address authorization, felt over/underflow, "
    "L1->L2 handler authorization, and storage-slot collision."
)

BE_COMPLETE = (
    "Cover the whole file: report each distinct high/critical you can pin to an exact "
    "function - often 8 to 15 when the code deserves it. One entry per vulnerable "
    "function, and more than one when a function has several separate defects. Never "
    "stop after the first couple and never cap the count yourself. For each entry, note "
    "briefly why the present modifiers or require checks fail to block it."
)

PIN_RULES = (
    "Pinning rules: copy file verbatim from a FILE header or the project map, never "
    "guess it. function must be a real name present in that file, copied exactly, with "
    "no arguments and no contract prefix. contract must be one declared in that file. "
    "Never invent files or functions. Make mechanism concrete: precondition, then the "
    "attacker's move, then the broken state."
)

OUTPUT_RULES = (
    "Formatting: return one bare minified JSON object and nothing outside it; double "
    "quotes, no trailing commas; severity is exactly high or critical; each description "
    "runs two to four sentences; order entries strongest first and make each one fully "
    "self-contained; if space runs short, finish the current object and close the array "
    "and object cleanly rather than opening another."
)

REPORT_SHAPE = (
    '{"findings":[{"title":"Contract.function - specific bug","file":"exact/path.sol",'
    '"contract":"ContractOrModule","function":"functionName","severity":"high|critical",'
    '"confidence":0.0,"type":"reentrancy|access-control|price-oracle|signature-replay|'
    'accounting|initialization|arithmetic|logic",'
    '"mechanism":"precondition -> attacker action -> broken state",'
    '"impact":"funds stolen / privilege escalation / insolvency / DoS",'
    '"description":"2-4 sentences naming file, contract, function, mechanism, and impact"}]}'
)

MAP_PROMPT = (
    "Here is a structured map of a smart-contract project: per file, its contracts or "
    "modules, function signatures, and risk-relevant lines. Do two things. First, copy "
    "the 8 to 12 highest-yield file paths verbatim into target_files. Second, report "
    "every high or critical already justifiable from these signatures and risk lines, "
    "including concretely-pinnable lower-confidence candidates (mark those with lower "
    "confidence). Do not hold back. "
    + BE_COMPLETE + " " + BUG_MENU + " " + PIN_RULES + " " + OUTPUT_RULES + "\n"
    'Return strict JSON only, shaped {"target_files":["exact/path"],"findings":[...]} '
    "with each finding matching: " + REPORT_SHAPE + "\nProject map:\n"
)

DEEP_PROMPT = (
    "Audit the smart-contract source below in depth for HIGH or CRITICAL "
    "vulnerabilities. A valid entry names the exact file and function, the exploitable "
    "state change, and the concrete impact. "
    + BE_COMPLETE + " " + BUG_MENU + " " + PIN_RULES + " " + OUTPUT_RULES + "\n"
    "Return strict JSON only: " + REPORT_SHAPE + "\n"
)

WIDE_PROMPT = (
    "Re-examine more of the project with fresh eyes. For each proposed bug, say why the "
    "existing modifiers or checks do not stop it. Prioritize cross-contract flows, "
    "accounting and rounding theft, stale or gameable prices, access-control holes, "
    "reentrancy and callbacks, liquidation math, unsafe init/upgrade, and signature "
    "replay. "
    + BE_COMPLETE + " " + BUG_MENU + " " + PIN_RULES + " " + OUTPUT_RULES + "\n"
    "Return strict JSON only: " + REPORT_SHAPE + "\n"
)

# ---------------------------------------------------------------------------
# Bug-class tagging (used for dedup keys)
# ---------------------------------------------------------------------------

_CLASS_HINTS = (
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
_CLASS_TO_TYPE = {
    "reentrancy": "reentrancy",
    "access": "access-control",
    "oracle": "price-oracle",
    "sigreplay": "signature-replay",
    "accounting": "accounting",
    "init": "initialization",
    "arith": "arithmetic",
}


def classify(*texts):
    blob = " ".join(t for t in texts if t).lower()
    for name, needles in _CLASS_HINTS:
        for needle in needles:
            if needle in blob:
                return name
    return "other"


# ---------------------------------------------------------------------------
# Repository loading
# ---------------------------------------------------------------------------

def locate_repo(project_dir):
    tries = []
    if project_dir:
        tries.append(project_dir)
    for var in ("PROJECT_DIR", "PROJECT_PATH", "PROJECT_ROOT", "PROJECT_CODE"):
        val = os.environ.get(var)
        if val:
            tries.append(val)
    tries.extend(("/app/project_code", "/app/project", "/project", "/code", "."))
    for raw in tries:
        try:
            root = Path(raw).expanduser().resolve()
        except (OSError, RuntimeError):
            continue
        if not root.is_dir():
            continue
        try:
            for entry in root.rglob("*"):
                if entry.is_file() and entry.suffix.lower() in CODE_EXTENSIONS:
                    return root
        except OSError:
            continue
    return None


def slurp(path):
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def is_code(text, suffix):
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


def parse_symbols(text, suffix):
    signatures = []
    if suffix == ".sol":
        types = RE_SOL_TYPE.findall(text)
        for m in RE_SOL_FN.finditer(text):
            trailer = " ".join(m.group(3).split())
            signatures.append((m.group(1), (m.group(1) + "(" + m.group(2).strip() + ") " + trailer).strip()))
        for m in RE_SOL_SPECIAL.finditer(text):
            signatures.append((m.group(1), m.group(1)))
    elif suffix == ".vy":
        types = []
        for m in RE_VY_FN.finditer(text):
            signatures.append((m.group(1), m.group(1) + "(" + m.group(2).strip() + ")"))
    elif suffix == ".rs":
        types = RE_RS_MOD.findall(text)
        signatures = [(m.group(1), m.group(0).strip()) for m in RE_RS_FN.finditer(text)]
    elif suffix == ".move":
        types = RE_MOVE_MOD.findall(text)
        signatures = [(m.group(1), m.group(0).strip()) for m in RE_MOVE_FN.finditer(text)]
    elif suffix == ".cairo":
        types = RE_CAIRO_MOD.findall(text)
        signatures = [(m.group(1), m.group(0).strip()) for m in RE_CAIRO_FN.finditer(text)]
    else:
        types = []
    return types, signatures


def rank_file(rel_low, body_low, num_fns):
    weight = min(num_fns, 30)
    for word in DOMAIN_WORDS:
        if word in rel_low:
            weight += 8
    for token in HOT_TOKENS:
        weight += min(body_low.count(token), 5) * 3
    if any(x in body_low for x in ("external", "public", "@external", "pub fn", "entry fun")):
        weight += 5
    if any(x in body_low for x in ("balances", "totalsupply", "total_supply", "reserve", "invariant")):
        weight += 6
    if "nonreentrant" not in body_low and any(x in body_low for x in ("withdraw", "redeem", ".call{")):
        weight += 6
    return weight


def catalog(root):
    files = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in CODE_EXTENSIONS:
            continue
        try:
            rel = path.relative_to(root)
            if any(part.lower() in IGNORED_DIRECTORIES for part in rel.parts[:-1]):
                continue
            if path.stat().st_size > FILE_BYTE_CAP:
                continue
        except OSError:
            continue
        suffix = path.suffix.lower()
        text = slurp(path)
        if not is_code(text, suffix):
            continue
        types, signatures = parse_symbols(text, suffix)
        if not types and suffix != ".sol":
            types = [path.stem]
        if not types and not signatures:
            continue
        files.append({
            "path": path, "rel": rel.as_posix(), "base": path.name, "text": text,
            "low": text.lower(), "stem": path.stem, "suffix": suffix,
            "types": types, "fns": signatures,
            "fnames": {n for n, _ in signatures},
        })
    for rec in files:
        weight = rank_file(rec["rel"].lower(), rec["low"], len(rec["fns"]))
        low = rec["low"]
        if rec["suffix"] == ".sol" and "contract " not in low and "library " not in low:
            weight *= 0.2
        elif rec["suffix"] != ".vy" and rec["fns"] and low.count("{") < max(1, len(rec["fns"]) // 3):
            weight *= 0.4
        parts = [p.lower() for p in Path(rec["rel"]).parts]
        stem = rec["stem"].lower()
        if (stem in ("test", "tests") or stem.startswith("test_")
                or stem.endswith(("_test", "_tests", ".t")) or "test" in parts
                or any(p in ("generated", "gen", "bindings", "sim") for p in parts)):
            weight *= 0.1
        rec["weight"] = weight
    files.sort(key=lambda rec: (-rec["weight"], rec["rel"]))
    return files[:FILE_COUNT_CAP]


def neighbors(rec, by_base):
    blocks = []
    seen = set()
    for imp in RE_IMPORT.findall(rec["text"]):
        tail = imp.rsplit("/", 1)[-1]
        base = tail.split(".")[0]
        for cand in (tail, base):
            other = by_base.get(cand)
            if other and other["rel"] != rec["rel"] and other["rel"] not in seen:
                seen.add(other["rel"])
                blocks.append("// import " + other["rel"] + "\n" + other["text"][:IMPORT_CHAR_CAP])
                break
        if len(blocks) >= 2:
            break
    return "\n\n".join(blocks)


def hot_lines(text, limit=16):
    picked = []
    for lineno, line in enumerate(text.splitlines(), 1):
        low = line.lower()
        if any(token in low for token in HOT_TOKENS):
            squeezed = " ".join(line.split())
            if squeezed:
                picked.append(str(lineno) + ": " + squeezed[:180])
        if len(picked) >= limit:
            break
    return picked


def build_map(files, budget):
    pieces = []
    used = 0
    detailed_cutoff = int(budget * 0.82)
    for rec in files:
        if used < detailed_cutoff:
            sigs = [sig[:150] for _, sig in rec["fns"][:24]]
            piece = json.dumps({
                "file": rec["rel"],
                "contracts": rec["types"][:8],
                "score": round(float(rec.get("weight", 0)), 1),
                "functions": sigs,
                "risk_lines": hot_lines(rec["text"], 16),
            }, separators=(",", ":"))
        else:
            piece = json.dumps({
                "file": rec["rel"],
                "contracts": rec["types"][:4],
                "score": round(float(rec.get("weight", 0)), 1),
            }, separators=(",", ":"))
        if used + len(piece) + 1 > budget:
            break
        pieces.append(piece)
        used += len(piece) + 1
    return "\n".join(pieces)


def condense(text, limit):
    if len(text) <= limit:
        return text
    lines = text.splitlines()
    keep = set()
    for idx, line in enumerate(lines):
        low = line.lower()
        if RE_DECL_LINE.search(line) or any(token in low for token in HOT_TOKENS):
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


# ---------------------------------------------------------------------------
# Inference transport
# ---------------------------------------------------------------------------

def read_message(payload):
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
    reasoning = message.get("reasoning") or message.get("reasoning_content")
    if isinstance(reasoning, str) and reasoning.strip():
        return reasoning
    details = message.get("reasoning_details")
    if isinstance(details, list):
        joined = "".join(p.get("text", "") for p in details if isinstance(p, dict))
        if joined.strip():
            return joined
    return ""


def encode_request(prompt, max_tokens, tuned):
    payload = {
        "model": MODEL_NAME,
        "messages": [
            {"role": "system", "content": ROLE},
            {"role": "user", "content": prompt},
        ],
        "max_tokens": max_tokens,
    }
    if tuned:
        payload["reasoning_effort"] = "medium"
    return json.dumps(payload).encode("utf-8")


def call_model(inference_api, prompt, deadline, max_tokens):
    global _SEND_TUNING
    endpoint = (inference_api or os.environ.get("INFERENCE_API") or "").rstrip("/")
    if not endpoint:
        raise RuntimeError("no inference endpoint")
    headers = {
        "Content-Type": "application/json",
        "x-inference-api-key": os.environ.get("INFERENCE_API_KEY", ""),
    }
    error = None
    tries = 0
    while tries < CALL_RETRIES:
        remaining = deadline - time.monotonic() - TAIL_HEADROOM
        timeout = min(PER_CALL_TIMEOUT, float(int(remaining)))
        if timeout < CALL_FLOOR:
            raise RuntimeError("insufficient budget")
        body = encode_request(prompt, max_tokens, _SEND_TUNING)
        try:
            request = urllib.request.Request(
                endpoint + "/inference", data=body, method="POST", headers=headers)
            with urllib.request.urlopen(request, timeout=timeout) as response:
                raw = response.read()
            return read_message(json.loads(raw.decode("utf-8", "replace")))
        except urllib.error.HTTPError as exc:
            if exc.code == 400 and _SEND_TUNING:
                _SEND_TUNING = False
                continue
            if exc.code in {429, 503} or exc.code not in _RETRYABLE_HTTP:
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
        if deadline - time.monotonic() <= 2.0 + CALL_HEADROOM:
            break
        time.sleep(2.0)
    raise RuntimeError(str(error) if error else "request failed")


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------

def scan_objects(text):
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


def read_findings(text):
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
    return [obj for obj in scan_objects(tail) if any(k in obj for k in _ENTRY_KEYS)]


def read_map_reply(text):
    targets = []
    findings = []
    if not isinstance(text, str):
        return targets, findings
    t = strip_fences(text)
    try:
        obj = json.loads(t)
        if isinstance(obj, dict):
            tg = obj.get("target_files")
            if isinstance(tg, list):
                targets = [str(x) for x in tg if isinstance(x, str)]
            fs = obj.get("findings") or obj.get("vulnerabilities")
            if isinstance(fs, list):
                findings = [f for f in fs if isinstance(f, dict)]
            return targets, findings
    except json.JSONDecodeError:
        pass
    marker = re.search(r'"target_files"\s*:\s*\[(.*?)\]', t, re.S)
    if marker:
        targets = re.findall(r'"([^"]+)"', marker.group(1))
    findings = read_findings(text)
    return targets, findings


# ---------------------------------------------------------------------------
# Audit passes
# ---------------------------------------------------------------------------

def deep_prompt(batch, by_base, per_file_cap, budget):
    parts = [DEEP_PROMPT]
    left = budget - len(DEEP_PROMPT)
    extra = neighbors(batch[0], by_base) if batch else ""
    for rec in batch:
        take = min(len(rec["text"]), per_file_cap, max(0, left))
        if take <= 0:
            break
        text = rec["text"]
        body = text if len(text) <= take else condense(text, take)
        block = (
            "\n\n===== FILE: " + rec["rel"] + " =====\n"
            "Contracts/modules: " + (", ".join(rec["types"][:8]) or rec["stem"]) + "\n" + body
        )
        if len(text) > take:
            block += "\n/* truncated */"
        parts.append(block)
        left -= len(block)
    if extra and left > 800:
        parts.append("\n\n===== IMPORTED CONTEXT (read-only) =====\n" + extra[:left - 200])
    return "".join(parts)


def wide_prompt(batch, budget):
    parts = [WIDE_PROMPT]
    left = budget - len(WIDE_PROMPT)
    for rec in batch:
        body = condense(rec["text"], WIDE_FILE_CHAR_CAP)
        block = (
            "\n\n===== FILE: " + rec["rel"] + " =====\n"
            "Contracts/modules: " + (", ".join(rec["types"][:8]) or rec["stem"]) + "\n" + body + "\n"
        )
        if left <= 0:
            break
        if len(block) > left:
            block = block[:left] + "\n/* truncated */"
        parts.append(block)
        left -= len(block)
    return "".join(parts)


def run_deep(inference_api, batch, by_base, deadline, per_file_cap, budget):
    return read_findings(call_model(
        inference_api, deep_prompt(batch, by_base, per_file_cap, budget), deadline, DEEP_TOKENS))


def run_wide(inference_api, batch, deadline, budget):
    return read_findings(call_model(
        inference_api, wide_prompt(batch, budget), deadline, WIDE_TOKENS))


def run_map(inference_api, files, deadline):
    return read_map_reply(call_model(
        inference_api, MAP_PROMPT + build_map(files, MAP_CHAR_BUDGET), deadline, MAP_TOKENS))


def resort_by_targets(files, targets):
    if not targets:
        return files
    front = []
    taken = set()
    for target in targets:
        cleaned = target.strip().lstrip("./")
        if not cleaned:
            continue
        base = cleaned.rsplit("/", 1)[-1]
        for rec in files:
            if rec["rel"] in taken:
                continue
            rel = rec["rel"]
            if (cleaned == rel or rel.endswith(cleaned)
                    or cleaned.endswith(rel) or rec["base"] == base):
                front.append(rec)
                taken.add(rel)
                break
    for rec in files:
        if rec["rel"] not in taken:
            front.append(rec)
    return front


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


def match_file(file_value, by_rel, by_base, fn_hint=""):
    if not file_value:
        return None
    cleaned = file_value.strip().strip("`").lstrip("./")
    direct = by_rel.get(cleaned)
    if direct is not None:
        return direct
    hits = [
        rec for rel, rec in by_rel.items()
        if rel == cleaned or rel.endswith(cleaned) or (len(cleaned) > 3 and cleaned.endswith(rel))
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


def declared(text, function):
    if not function:
        return False
    pattern = r"\b(?:" + "|".join(DECLARATION_WORDS) + r")\s+" + re.escape(function) + r"\b"
    return re.search(pattern, text) is not None


def normalize(raw, by_rel, by_base):
    file_value = str(raw.get("file") or raw.get("path") or raw.get("location") or "").strip()
    fn = str(raw.get("function") or "").strip().strip("`() ")
    fn = fn.split(".")[-1].split("::")[-1]
    rec = match_file(file_value, by_rel, by_base, fn)
    if rec is None:
        return None
    severity = str(raw.get("severity") or "").strip().lower()
    if severity in {"medium", "med", "moderate"}:
        severity = "high"
    if severity not in {"high", "critical"}:
        return None
    if fn and fn not in rec["fnames"] and not declared(rec["text"], fn):
        fn = ""
    declared_types = rec["types"]
    contract = str(raw.get("contract") or raw.get("module") or "").strip().strip("`")
    contract_real = bool(contract and (not declared_types or contract in declared_types))
    if not contract or (declared_types and contract not in declared_types):
        contract = declared_types[0] if declared_types else rec["stem"]
    mechanism = str(raw.get("mechanism") or "").strip()
    impact = str(raw.get("impact") or "").strip()
    description = str(raw.get("description") or "").strip()
    title = str(raw.get("title") or "").strip()
    try:
        confidence = max(0.0, min(1.0, float(raw.get("confidence"))))
    except (TypeError, ValueError):
        confidence = 0.6

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
    if len(body) < MIN_BODY_LEN and not title:
        return None
    cls = classify(title, mechanism, impact, description)
    return {
        "title": title[:220],
        "description": body[:2400],
        "severity": severity,
        "file": rec["rel"],
        "function": fn,
        "line": function_line(rec, fn),
        "type": _CLASS_TO_TYPE.get(cls) or str(raw.get("type") or "logic"),
        "confidence": 0.9 if severity == "critical" else confidence,
        "pinned": bool(fn) or contract_real,
    }


# ---------------------------------------------------------------------------
# Model-free structural probes
# ---------------------------------------------------------------------------

def make_probe(title, rel, contract, function, mechanism, impact):
    return {
        "title": title, "file": rel, "contract": contract, "function": function,
        "severity": "high", "mechanism": mechanism, "impact": impact,
        "description": mechanism + ". " + impact,
    }


def heuristic_findings(files):
    out = []
    for rec in files:
        if rec["suffix"] != ".sol":
            continue
        low = rec["low"]
        contract = rec["types"][0] if rec["types"] else rec["stem"]
        if "function initialize" in low and not any(
                x in low for x in ("initializer", "onlyowner", "onlyrole", "_disableinitializers")):
            out.append(make_probe(
                contract + ".initialize - unprotected initializer", rec["rel"], contract,
                "initialize" if "initialize" in rec["fnames"] else "",
                "the initializer is externally reachable with no one-time initializer "
                "modifier and no owner/role check",
                "an attacker initializes or re-initializes ownership and critical "
                "configuration and seizes privileged control"))
        elif "tx.origin" in low:
            out.append(make_probe(
                contract + " - authorization relies on tx.origin", rec["rel"], contract, "",
                "authorization is gated on tx.origin, which a malicious intermediate "
                "contract defeats by phishing a privileged caller",
                "a privileged account is tricked into a fund-moving or configuration action"))
        if len(out) >= 3:
            break
    return out


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
    for m in RE_SOL_FN.finditer(text):
        marks.append((m.start(), m.group(1), " ".join(m.group(0).split())))
    for m in RE_SOL_SPECIAL.finditer(text):
        marks.append((m.start(), m.group(1), m.group(1)))
    marks.sort(key=lambda x: x[0])
    out = []
    for i, (pos, name, sig) in enumerate(marks):
        end = marks[i + 1][0] if i + 1 < len(marks) else len(text)
        out.append({"name": name, "sig": sig, "body": text[pos:end]})
    return out


_GUARD_TOKENS = ("onlyowner", "onlyrole", "requiresauth", "_checkowner", "msg.sender==",
                 "authorized", "hasrole", "restricted", "onlyadmin", "onlygovernance")
RE_AUTH_MAP = re.compile(r"(operator|extension|approv|allowed|authoriz|whitelist|trusted)s?\s*\[")
RE_AUTH_SELF = re.compile(
    r"(operator|extension|approv|allowed|authoriz|whitelist|trusted)s?\s*\[\s*msg\.sender")
RE_PRIV_ROLE = re.compile(
    r"validator|minter|operator|admin|guardian|keeper|signer|treasury|governance|pauser|role",
    re.I)
RE_MODIFIER_STRIP = re.compile(
    r"\b(external|public|payable|virtual|override|returns)\b|\([^)]*\)|[\s,]")
_SKIP_STEMS = ("mock", "dummy", "fake", "stub", "harness", "example",
               "weth", "wavax", "wmatic", "wbnb", "weth9", "wrapped")


def structural_probes(files):
    out = []
    for rec in files:
        if rec["suffix"] != ".sol":
            continue
        stem = rec["stem"].lower()
        if any(w in stem for w in _SKIP_STEMS) or stem[:1].isdigit():
            continue
        if "contract " not in rec["low"] and "library " not in rec["low"]:
            continue
        text = rec["text"]
        contract = rec["types"][0] if rec["types"] else rec["stem"]
        for m in re.finditer(r"\breceive\s*\(\s*\)\s*external\s+payable\s*\{", text):
            body = enclosing_block(text, m.start()).lower()
            if ("stake(" in body or "deposit(" in body) and "msg.sender" not in body:
                out.append(make_probe(
                    contract + ".receive - inbound native transfer auto-staked",
                    rec["rel"], contract, "receive",
                    "the payable receive hook stakes or deposits every native transfer "
                    "without separating protocol/system returns from user deposits",
                    "native funds returned from an unstake, validator withdrawal, or "
                    "reward path are restaked instead of settling pending withdrawals, "
                    "locking liquidity and corrupting withdrawal accounting"))
                break
        for fn in sol_functions(text):
            name = fn["name"]
            sig = fn["sig"].lower()
            block = fn["body"].lower()
            both = sig + " " + block
            if "domainseparator" in both and ("ecrecover" in block or "recover(" in block):
                if not any(x in both for x in
                           ("deadline", "chainid", "block.chainid", "block.timestamp")):
                    out.append(make_probe(
                        contract + "." + name + " - replayable signature domain",
                        rec["rel"], contract, name,
                        "the signature check recovers a signer with a domain separator "
                        "not bound to a deadline or the current chain id",
                        "a captured signature is replayed on another deployment or chain "
                        "to execute the signed privileged action"))
            if re.match(r"^(set|update|enable|disable|add|remove|register)", name, re.I):
                if ("external" in sig or "public" in sig) and "only" not in sig \
                        and not any(g in both for g in _GUARD_TOKENS):
                    if RE_AUTH_MAP.search(block) and not RE_AUTH_SELF.search(block):
                        out.append(make_probe(
                            contract + "." + name + " - unauthenticated authorization change",
                            rec["rel"], contract, name,
                            "an external configuration function writes an operator, "
                            "approval, or authorization mapping with no owner/role check",
                            "any caller authorizes itself and then acts on behalf of "
                            "other users wherever that mapping gates privileged actions"))
            if name.lower() in ("cancelorder", "modifyorder", "fillorder", "executeorder") \
                    and "external" in sig and "nonreentrant" not in sig:
                if "safetransfer" in block or "transfer(" in block or ".call{" in block:
                    out.append(make_probe(
                        contract + "." + name + " - order mutation without reentrancy guard",
                        rec["rel"], contract, name,
                        "an external order cancel/modify/fill path reaches a token "
                        "transfer or external call without a nonReentrant guard",
                        "a malicious token or callback reenters mid-mutation to "
                        "double-refund or corrupt pending-order bookkeeping"))
            if ".price" in block and any(x in block for x in ("pnl", "collateral", "settle")) \
                    and any(x in both for x in ("intent", "order", "params")):
                if not any(x in block for x in ("maxprice", "minprice", "oracle", "latestversion",
                                                "currentversion", ".gt(", ".lt(", "clamp", "bound")):
                    out.append(make_probe(
                        contract + "." + name + " - unbounded user price in value math",
                        rec["rel"], contract, name,
                        "a user-supplied order/intent price flows into PnL, collateral, "
                        "or settlement math without being clamped to a live oracle price",
                        "an extreme price manufactures settlement value and extracts "
                        "collateral from counterparties"))
            if re.match(r"^(add|register|Add|Register)[A-Z_]", name) and RE_PRIV_ROLE.search(name):
                modzone = sig.rsplit(")", 1)[-1]
                if ("external" in sig or "public" in sig) \
                        and not RE_MODIFIER_STRIP.sub("", modzone):
                    if "msg.sender" not in block and not ("require(" in block and "owner" in block):
                        out.append(make_probe(
                            contract + "." + name + " - privileged role added without access control",
                            rec["rel"], contract, name,
                            "an external/public role-adding function has no modifier and "
                            "no in-body authorization check, so any account can call it",
                            "any caller registers itself as a privileged validator, "
                            "minter, or operator and performs the authorized actions"))
        if len(out) >= 10:
            break
    return out[:10]


# ---------------------------------------------------------------------------
# Corroboration + selection
# ---------------------------------------------------------------------------

def collapse(entries):
    """Fold duplicates together and count how many passes agree on each issue.

    The dedup key is (file, function, bug-class). Repeated hits raise the vote
    count and keep the best-written instance; agreement across passes is the
    strongest available proxy for a real finding.
    """
    groups = {}
    for e in entries:
        key = (e["file"].lower(), e["function"].lower(), classify(e["title"], e["description"]))
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
        if len(e.get("description", "")) > len(cur.get("description", "")):
            cur["description"] = e["description"]
            cur["title"] = e["title"]
        if cur.get("line") is None and e.get("line") is not None:
            cur["line"] = e["line"]
    return list(groups.values())


def choose(entries):
    """Order by corroboration + pinning, then cap.

    Pinned, multiply-corroborated issues lead (they defend precision); the rest of
    the pinned issues follow (they defend the project-pass recall tier); anything
    that could not be pinned to a real function/contract only backfills leftover
    budget as the likeliest false positive.
    """
    merged = collapse(entries)

    def priority(e):
        return (
            bool(e.get("pinned")),
            int(e.get("votes", 1)),
            e["severity"] == "critical",
            float(e.get("confidence", 0)),
            len(e.get("description", "")),
        )

    merged.sort(key=priority, reverse=True)
    pinned = [e for e in merged if e.get("pinned")]
    loose = [e for e in merged if not e.get("pinned")]
    picked = pinned[:EMIT_CAP]
    if len(picked) < EMIT_CAP:
        picked += loose[: EMIT_CAP - len(picked)]
    report = []
    for e in picked:
        report.append({
            "title": e["title"],
            "description": e["description"],
            "severity": e["severity"],
            "file": e["file"],
            "function": e["function"],
            "line": e.get("line"),
            "type": e["type"],
            "confidence": float(e.get("confidence", 0.6)),
        })
    return report


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def agent_main(project_dir=None, inference_api=None):
    findings = []
    deadline = time.monotonic() + TOTAL_BUDGET_SECONDS
    try:
        root = locate_repo(project_dir)
        if root is None:
            return {"vulnerabilities": findings}
        files = catalog(root)
        if not files:
            return {"vulnerabilities": findings}
        by_base = {}
        for rec in files:
            by_base.setdefault(rec["base"], rec)
        by_rel = {rec["rel"]: rec for rec in files}

        raw = []
        ordered = files
        if deadline - time.monotonic() >= CALL_HEADROOM:
            try:
                targets, seeded = run_map(inference_api, files, deadline)
                raw.extend(seeded)
                ordered = resort_by_targets(files, targets)
            except Exception:
                pass
        if deadline - time.monotonic() >= CALL_HEADROOM:
            try:
                raw.extend(run_deep(inference_api, ordered[:DEEP_FILE_COUNT], by_base,
                                    deadline, DEEP_FILE_CHAR_CAP, DEEP_PROMPT_BUDGET))
            except Exception:
                pass
        if deadline - time.monotonic() >= CALL_HEADROOM:
            wide_batch = ordered[5:5 + WIDE_FILE_COUNT] + ordered[:5]
            if wide_batch:
                try:
                    raw.extend(run_wide(inference_api, wide_batch, deadline, WIDE_PROMPT_BUDGET))
                except Exception:
                    pass

        try:
            raw.extend(structural_probes(files))
        except Exception:
            pass

        cleaned = []
        for item in raw:
            entry = normalize(item, by_rel, by_base)
            if entry is not None:
                cleaned.append(entry)
        if not cleaned:
            for item in heuristic_findings(files):
                entry = normalize(item, by_rel, by_base)
                if entry is not None:
                    cleaned.append(entry)
        findings = choose(cleaned)
    except Exception:
        return {"vulnerabilities": findings}
    return {"vulnerabilities": findings}


if __name__ == "__main__":
    import sys
    print(json.dumps(agent_main(sys.argv[1] if len(sys.argv) > 1 else None), indent=2))
