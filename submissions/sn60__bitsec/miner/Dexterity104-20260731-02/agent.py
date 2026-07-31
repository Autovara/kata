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
RX_ANNOT = re.compile(r"^\s*(?:#\[|@[A-Za-z_])|\b(?:struct|resource)\b")
FN_KEYWORDS = ("function", "fn", "fun", "def", "func")

VALUE_WORDS = (
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
    "settle", "rebalance", "liquidity", "reserve", "invariant", "msg.sender",
    "signer", "authority", "lamports", "invoke", "cpi", "checked_", "unwrap",
    "close_account", "realloc", "try_borrow", "deserialize", "next_account",
    "assert_eq", "owner", "is_signer", "wasm", "info.sender", "transfer",
    "sub_msg", "coin(",
    "acquires", "borrow_global", "move_to", "move_from", "capability", "signer::",
    "get_caller_address", "get_contract_address", "felt", "starknet", "assert(",
)


BYTE_CEILING = 260_000
CATALOG_CAP = 80
NEIGHBOUR_CHARS = 2_000
FOCUS_FILE_CHARS = 15_000
FOCUS_PROMPT_CHARS = 18_000
GROUP_FILE_CHARS = 9_000
GROUP_CHARS = 28_000
GROUP_FILES = 3
GROUP_PROMPT_CHARS = 38_000
SURVEY_CHARS = 24_000

FOCUS_COUNT = 12
DEEP_COUNT = 3
RECHECK_COUNT = 1
WORKERS = 8
CONSECUTIVE_FAIL_STOP = 3

EMIT_CAP = 100
PER_FILE_CAP = 8
OVERFLOW_FILE_CAP = 25
MIN_BODY = 40
BASE_CONF = 0.55
HIGH_CONF_FLOOR = 0.42

MODEL = os.environ.get("KATA_MINER_MODEL", "deepseek-ai/DeepSeek-V3.2-TEE")
DECODE_TEMP = 0.0
SURVEY_TOKENS = 6_000
FOCUS_TOKENS = 6_000
GROUP_TOKENS = 8_000
RECHECK_TOKENS = 6_000
MIN_TOKENS = 1_200

WALL_BUDGET = 660.0
PER_CALL_TIMEOUT = 190.0
TAIL_RESERVE = 30.0
CALL_FLOOR = 30.0
CALL_RETRIES = 2
RETRYABLE = frozenset({408, 409, 425, 429, 500, 502, 503, 504, 520, 522, 524, 529})

_EFFORT_OK = True
_TEMP_OK = True
_TOKEN_CEILING = None
_PARAM_LOCK = threading.Lock()


SYSTEM_BASE = (
    "You are a principal smart-contract auditor reviewing %s. Within the code you are "
    "shown, enumerate every distinct HIGH or CRITICAL weakness you can tie to one "
    "concrete function -- do not stop at the single worst one, do not cap the count "
    "yourself, and add a separate entry when one function hides more than one flaw. "
    "Overlooking a real high/critical costs far more than naming a candidate that "
    "later proves wrong, but do not manufacture filler. "
    "In scope: theft or freezing of funds, insolvency, unauthorized state changes, "
    "privilege escalation, permanent lockup or denial of service, mint/supply "
    "corruption, oracle manipulation, reentrancy, replay or signature flaws, and "
    "absent signer/owner/authority checks. Out of scope: gas, style, missing events, "
    "bare centralization, and informational notes. Reason privately, then output "
    "exactly one minified JSON object -- no prose, no markdown, no fences."
)

LANG_NAMES = {
    ".sol": "Solidity", ".vy": "Vyper", ".rs": "Rust for Solana/Anchor and CosmWasm",
    ".move": "Move", ".cairo": "Cairo",
}
LANG_CHECKS = {
    ".sol": (
        "Solidity/Vyper: reentrancy and external-call ordering; missing or incorrect "
        "access control; delegatecall, upgrade and initialization faults; first-depositor "
        "share inflation and rounding; spot-vs-time-weighted and stale or steerable "
        "oracles; permit and signature replay; unsafe token assumptions and fee-on-transfer; "
        "native-value accounting; and irreversible denial of service. "
    ),
    ".rs": (
        "Solana/Anchor Rust: missing is_signer, missing account-owner check, missing "
        "has_one/constraint, unchecked PDA seeds, skipped account close, unchecked math, "
        "CPI into an unvetted program, and missing discriminator or type confusion. "
        "CosmWasm: unchecked info.sender and an open migrate entry point. "
    ),
    ".move": (
        "Move: missing signer or capability, a public entry that wraps a privileged call, "
        "and resource-ownership confusion. "
    ),
    ".cairo": (
        "Cairo/Starknet: missing get_caller_address check, felt over/underflow, "
        "L1->L2 handler authentication, and storage-slot collision."
    ),
}
LANG_CHECKS[".vy"] = LANG_CHECKS[".sol"]

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

FOCUS_HEAD = (
    "Audit the single source file below in depth for HIGH or CRITICAL weaknesses; the "
    "imported context that follows it is read-only support. Trace each externally "
    "reachable entry point end to end.\n"
)

GROUP_HEAD = (
    "Audit every source file below in depth for HIGH or CRITICAL weaknesses. Treat each "
    "FILE section as a separate audit and work through them one at a time in order: trace "
    "that file's externally reachable entry points end to end and report its findings "
    "before moving to the next. Give every file its own share of the answer -- do not spend "
    "the whole response on the first file, and do not skip a later file because an earlier "
    "one looked worse. Also report any flaw in the flows that cross between them.\n"
)

RECHECK_HEAD = (
    "Re-audit the file below from scratch, trusting no earlier read. Hunt above all for the "
    "issues a first pass misses: cross-function interplay, initialization/upgrade takeover, "
    "rounding and share inflation, stale or steerable prices, absent signer/owner/authority "
    "checks, and callback/reentrancy ordering. For each proposed issue, say why the guards "
    "already present fail to stop it.\n"
)

SURVEY_HEAD = (
    "Below is a structured map of a smart-contract project: per file its contracts or "
    "modules, function signatures, and risk-relevant lines. Report every high or critical "
    "already justifiable from these signatures and risk lines, including concretely "
    "pinnable lower-confidence candidates (mark those with lower confidence). Do not hold "
    "back.\nProject map:\n"
)

SYSTEM = SYSTEM_BASE % "on-chain program source"


def configure_prompts(records):
    global SYSTEM
    suffixes = []
    for rec in records:
        if rec["suffix"] not in suffixes:
            suffixes.append(rec["suffix"])
    names = [LANG_NAMES[s] for s in suffixes if s in LANG_NAMES]
    checks, seen = [], set()
    for suffix in suffixes:
        text = LANG_CHECKS.get(suffix)
        if text and text not in seen:
            seen.add(text)
            checks.append(text)
    languages = ", ".join(names) if names else "on-chain program source"
    SYSTEM = "%s\n%sSweep this catalogue: %s\n%s\nReturn strict JSON only: %s" % (
        SYSTEM_BASE % languages, ANCHORING + " ", "".join(checks).strip(), EMISSION, SHAPE)
    return SYSTEM


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


def mech_ids(description, file, function):
    ids = {m.lower() for m in re.findall(r"`([A-Za-z_][A-Za-z0-9_]{2,})`", description or "")}
    ids.discard((function or "").lower())
    ids -= {q.lower() for q in re.split(r"[/\\.]", file or "") if q}
    head = re.match(r"^In `[^`]*`(?:, contract `([A-Za-z_][A-Za-z0-9_]*)`)?", description or "")
    if head and head.group(1):
        ids.discard(head.group(1).lower())
    return tuple(sorted(ids)[:6])


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


_UNIT_STOP = frozenset({
    "is", "if", "for", "while", "do", "return", "returns", "abstract", "contract",
    "interface", "library", "using", "event", "error", "struct", "enum", "mapping",
    "function", "modifier", "constructor", "memory", "storage", "calldata", "public",
    "private", "external", "internal", "view", "pure", "payable", "virtual", "override",
    "address", "bool", "uint", "int", "string", "bytes", "the", "this", "a", "an",
    "and", "or", "pattern", "version", "type", "new", "import", "pragma", "solidity",
})


def _strip_comments(text, suffix):
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
        if len(units) > 6 and len(text) > 60_000:
            score *= 6.0 / len(units)
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
                blocks.append("// import " + other["rel"] + "\n"
                              + condense(other["text"], NEIGHBOUR_CHARS))
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
    total = len(lines)

    def cost(i):
        return len(lines[i]) + len(str(i + 1)) + 3

    primary = set()
    for idx, line in enumerate(lines):
        if RX_DECL.search(line) or RX_ANNOT.search(line):
            end = idx + 5
            for j in range(idx, min(total, idx + 12)):
                if "{" in lines[j] or ";" in lines[j] or lines[j].rstrip().endswith(":"):
                    end = max(end, j + 1)
                    break
            for j in range(idx, min(total, end)):
                primary.add(j)
    used = sum(cost(i) for i in primary)
    keep = set(primary)
    if used < limit:
        halo = [
            i for i in range(total)
            if i not in primary and any(t in lines[i].lower() for t in RISK_TOKENS)
        ]
        for idx in halo:
            for j in range(max(0, idx - 2), min(total, idx + 6)):
                if j in keep:
                    continue
                c = cost(j)
                if used + c > limit:
                    break
                keep.add(j)
                used += c
            if used >= limit:
                break
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


def _wire(prompt, max_tokens, effort, with_temp):
    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": prompt},
        ],
        "max_tokens": max_tokens,
    }
    if with_temp:
        payload["temperature"] = DECODE_TEMP
    if effort:
        payload["reasoning_effort"] = effort
    return json.dumps(payload).encode("utf-8")


def ask_model(endpoint, prompt, deadline, max_tokens, effort):
    global _EFFORT_OK, _TEMP_OK, _TOKEN_CEILING
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
        use_temp = _TEMP_OK
        cap = _TOKEN_CEILING
        want_tokens = min(max_tokens, cap) if cap else max_tokens
        body = _wire(prompt, want_tokens, use_effort, use_temp)
        try:
            request = urllib.request.Request(
                endpoint + "/inference", data=body, method="POST", headers=headers)
            with urllib.request.urlopen(request, timeout=timeout) as response:
                raw = response.read()
            return extract_message(json.loads(raw.decode("utf-8", "replace")))
        except urllib.error.HTTPError as exc:
            if exc.code == 400 and use_effort:
                with _PARAM_LOCK:
                    _EFFORT_OK = False
                continue
            if exc.code == 400 and use_temp:
                with _PARAM_LOCK:
                    _TEMP_OK = False
                continue
            if exc.code == 400 and want_tokens > MIN_TOKENS:
                with _PARAM_LOCK:
                    _TOKEN_CEILING = max(MIN_TOKENS, want_tokens // 2)
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


def pack_groups(records, budget, per_file):
    groups = []
    current = []
    used = 0
    for rec in records:
        size = min(len(rec["text"]), per_file)
        if current and (used + size > budget or len(current) >= GROUP_FILES):
            groups.append(current)
            current = []
            used = 0
        current.append(rec)
        used += size
    if current:
        groups.append(current)
    return groups


def group_prompt(batch):
    parts = [GROUP_HEAD]
    left = GROUP_PROMPT_CHARS - len(GROUP_HEAD)
    for rec in batch:
        body = rec["text"]
        if len(body) > GROUP_FILE_CHARS:
            body = condense(body, GROUP_FILE_CHARS)
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


def run_pool(jobs, deadline):
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
    jobs = []

    def focus_job(rec):
        return lambda: parse_findings(
            ask_model(endpoint, focus_prompt(rec, by_base), deadline, FOCUS_TOKENS, "medium"))

    def recheck_job(rec):
        return lambda: parse_findings(
            ask_model(endpoint, recheck_prompt(rec), deadline, RECHECK_TOKENS, "medium"))

    def group_job(batch):
        return lambda: parse_findings(
            ask_model(endpoint, group_prompt(batch), deadline, GROUP_TOKENS, "medium"))

    def survey_job():
        return parse_findings(
            ask_model(endpoint, SURVEY_HEAD + survey_map(records, SURVEY_CHARS),
                      deadline, SURVEY_TOKENS, "medium"))

    focus_set = records[:FOCUS_COUNT]
    for rec in focus_set[:DEEP_COUNT]:
        jobs.append(focus_job(rec))
    jobs.append(survey_job)
    for rec in focus_set[:RECHECK_COUNT]:
        jobs.append(recheck_job(rec))
    for batch in pack_groups(focus_set[DEEP_COUNT:], GROUP_CHARS, GROUP_FILE_CHARS):
        jobs.append(group_job(batch))
    return jobs


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
        "description": body[:780],
        "severity": severity,
        "file": rec["rel"],
        "function": fn,
        "line": function_line(rec, fn),
        "type": _CLASS_TYPE.get(cls) or str(raw.get("type") or "logic"),
        "confidence": 0.9 if severity == "critical" else confidence,
        "pinned": bool(fn) or contract_real,
        "refined": bool(raw.get("_refined")),
    }


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


REFINE_TARGETS = 18
REFINE_PER_FILE = 3
REFINE_PER_CALL = 6
REFINE_SRC = 6_000
REFINE_HEAD = 1_200
REFINE_MIN_TIME = 120.0
REFINE_TOKENS = 7_000

REFINE_HEAD_MSG = (
    "Second-pass sharpening. Below are individual functions from a smart-contract "
    "project, each followed by the candidate findings a first pass produced for it. "
    "Those candidates tend to name the right function but state the cause too vaguely "
    "to be credited, and a finding with the right function but a vague or wrong cause is "
    "worth nothing. For EACH function, re-derive from the source what is actually wrong: "
    "where a candidate is right, restate it precisely - name the exact expression, not "
    "the category; where it is vague, replace it; where the source refutes it, discard it "
    "and report whatever IS wrong instead. Emit a separate entry per distinct mechanism, "
    "and nothing for a function that is genuinely safe.\n"
)


def function_source(rec, fn, limit=REFINE_SRC):
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
        scored.append((-len(distinct), -len(items), rank_of.get(rel, 10_000), rel, fn))
    scored.sort()
    out = []
    per_file = {}
    for _, _, _, rel, fn in scored:
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
                ask_model(endpoint, refine_prompt(chunk), deadline, REFINE_TOKENS, "medium"))
            for f in found:
                if isinstance(f, dict):
                    f["_refined"] = True
            return found
        return call

    return run_pool([make(c) for c in chunks], deadline)


def merge(entries):
    groups = {}
    for e in entries:
        key = (e["file"].lower(), e["function"].lower(),
               bug_class(e["title"], e["description"]),
               mech_ids(e["description"], e["file"], e["function"]))
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
        if per_file.get(fkey, 0) >= OVERFLOW_FILE_CAP:
            continue
        chosen.append(e)
        per_file[fkey] = per_file.get(fkey, 0) + 1
    for e in chosen:
        e["confidence"] = float(e.get("confidence", BASE_CONF))
        for bookkeeping in ("votes", "pinned", "refined"):
            e.pop(bookkeeping, None)
    return chosen[:EMIT_CAP]


def _audit(project_dir, inference_api):
    report = []
    deadline = time.monotonic() + WALL_BUDGET
    try:
        root = find_root(project_dir)
        if root is None:
            return report
        records = catalog(root)
        if not records:
            return report
        configure_prompts(records)
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
        if endpoint and raw and deadline - time.monotonic() >= REFINE_MIN_TIME:
            try:
                rank_of = {rec["rel"]: idx for idx, rec in enumerate(records)}
                raw.extend(run_refine(endpoint, raw, by_rel, by_base, rank_of, deadline))
            except Exception:
                pass

        cleaned = []
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
        return report
    return report


def write_report(result):
    payload = json.dumps({"success": True, "report": result})
    written = []
    targets = []
    configured = os.environ.get("REPORT_FILE", "").strip()
    if configured:
        targets.append(configured)
    targets += ["/kata_output/report.json", "/app/report.json", "report.json"]
    seen = set()
    for target in targets:
        if target in seen:
            continue
        seen.add(target)
        path = Path(target)
        try:
            if str(path.parent) not in ("", "."):
                path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(payload, encoding="utf-8")
            written.append(str(path))
        except OSError:
            continue
    return written


def agent_main(project_dir=None, inference_api=None):
    try:
        findings = _audit(project_dir, inference_api)
    except Exception:
        findings = []
    result = {"vulnerabilities": findings}
    write_report(result)
    return result


if __name__ == "__main__":
    import sys
    print(json.dumps(agent_main(sys.argv[1] if len(sys.argv) > 1 else None), indent=2))
