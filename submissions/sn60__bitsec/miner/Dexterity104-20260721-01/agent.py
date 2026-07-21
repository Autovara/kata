"""SN60 / Bitsec miner agent — recall-first, multi-language whole-repo auditor.

Self-contained (stdlib only). Reads the project's own source from project_dir and
reaches the model only through the validator-provided inference proxy.
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

SOURCE_SUFFIXES = (".sol", ".vy", ".rs", ".move", ".cairo")
SKIP_DIRS = {
    "test", "tests", "mock", "mocks", "example", "examples", "script", "scripts",
    "broadcast", "node_modules", "vendor", "vendors", "lib", "libs", "out",
    "artifacts", "cache", "coverage", "interfaces", "interface", "fixtures", "fixture",
    "target", "docs", ".git", ".github", "deps", "dist", "build",
}

SOL_CONTRACT_RE = re.compile(
    r"\b(?:abstract\s+contract|contract|library|interface)\s+([A-Za-z_][A-Za-z0-9_]*)"
)
SOL_FUNC_RE = re.compile(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)([^{};]*)")
SOL_SPECIAL_RE = re.compile(r"\b(constructor|receive|fallback)\b\s*\(")
VY_FUNC_RE = re.compile(r"(?m)^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)")
RS_FUNC_RE = re.compile(
    r"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)"
)
RS_MOD_RE = re.compile(r"(?m)^\s*(?:pub\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{")
MOVE_FUNC_RE = re.compile(
    r"(?m)^\s*(?:public\s*(?:\([^)]*\))?\s+)?(?:entry\s+)?(?:native\s+)?fun\s+([A-Za-z_][A-Za-z0-9_]*)"
)
MOVE_MOD_RE = re.compile(r"(?m)^\s*module\s+(?:[A-Za-z_0-9]+::)?([A-Za-z_][A-Za-z0-9_]*)")
CAIRO_FUNC_RE = re.compile(r"(?m)^\s*(?:pub\s+)?(?:fn|func)\s+([A-Za-z_][A-Za-z0-9_]*)")
CAIRO_MOD_RE = re.compile(r"(?m)^\s*(?:pub\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{")
IMPORT_RE = re.compile(r'(?m)^\s*(?:import|use)\b[^;\n]*?["\']?([A-Za-z0-9_./]+)["\']?')
DEF_LINE_RE = re.compile(
    r"\bfunction\b|\bdef\b|\bfn\b|\bfun\b|\bmodifier\b|\bconstructor\b|\bmodule\b|\bmapping\b"
)
DECL_KEYWORDS = ("function", "fn", "fun", "def", "func")

NAME_TERMS = (
    "vault", "pool", "router", "manager", "controller", "strategy", "market", "lend",
    "borrow", "oracle", "price", "stak", "reward", "treasury", "bridge", "factory",
    "proxy", "govern", "token", "escrow", "auction", "liquidat", "swap", "stable",
    "collateral", "vesting", "distributor", "minter", "gauge", "farm", "perp",
    "position", "margin", "settle", "clearing", "coin", "account", "program",
)
RISK_TERMS = (
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

MAX_FILE_BYTES = 260_000
MAX_FILES = 90
MAX_SOURCE_CHARS = 38_000
PER_FILE_CAP = 12_000
MAX_IMPORT_CHARS = 3_000
DEEP_BATCH_CAP = 15_000
DEEP_BATCH_BUDGET = 47_000
DEEP_FILES = 8
TAIL_BUDGET = 52_000
FOCUS_FILES = 13
FOCUS_PER_CAP = 8_500
TRIAGE_CHARS = 40_000
MAX_EMIT = 30
MIN_DESC = 40

MODEL = os.environ.get("KATA_MINER_MODEL", "deepseek-ai/DeepSeek-V3.2-TEE")
TRIAGE_MAX_TOKENS = 12_000
DEEP_MAX_TOKENS = 16_000
FOCUS_MAX_TOKENS = 15_000

GLOBAL_DEADLINE = 755.0
REQUEST_TIMEOUT = 200.0
CALL_RESERVE = 220.0
POST_RESERVE = 12.0
MIN_CALL_TIME = 35.0
MAX_ATTEMPTS = 2

_OPT_FIELDS = True

_TRANSIENT = frozenset({408, 409, 425, 500, 502, 504, 520, 522, 524, 529})

SYSTEM = (
    "You are a principal smart-contract security auditor for Solidity, Vyper, "
    "Rust (Solana/Anchor and CosmWasm), Move, and Cairo. For every file you are given, "
    "ENUMERATE all distinct HIGH or CRITICAL vulnerabilities you can localize to an "
    "exact function - not only the single worst one. A real high or critical you fail "
    "to list is the expensive mistake; a plausible wrong candidate is cheap. In scope: "
    "theft or loss of funds, insolvency, unauthorized state change, privilege "
    "escalation, permanent denial-of-service or lockup, mint/supply corruption, oracle "
    "manipulation, reentrancy, signature or replay flaws, and missing "
    "signer/owner/authority checks. Out of scope: gas, style, missing events, pure "
    "centralization, and informational notes. Do all reasoning privately; output only "
    "one strict minified JSON object - no prose, no markdown, no code fences."
)

CHECKLIST = (
    "Bug classes to check by language. "
    "Solidity/Vyper: reentrancy and external-call ordering, missing or incorrect "
    "access control, delegatecall and upgrade/initialization flaws, first-depositor "
    "and share-inflation and rounding, spot-price versus time-weighted and stale or "
    "manipulable oracles, permit and signature replay, unsafe token assumptions and "
    "fee-on-transfer, native-value accounting, and permanent denial-of-service. "
    "Rust Solana/Anchor: missing is_signer, missing account owner check, missing "
    "has_one or constraint, unvalidated program-derived-address seeds, missing account "
    "close, unchecked arithmetic, cross-program invocation into an unverified program, "
    "and missing discriminator or type confusion. "
    "CosmWasm: missing info.sender authorization and an unguarded migrate entrypoint. "
    "Move: missing signer or capability, a public entry that exposes a privileged "
    "function, and resource-ownership confusion. "
    "Cairo/Starknet: missing get_caller_address authorization, felt over/underflow, "
    "L1-to-L2 handler authorization, and storage-slot collision."
)

ENUM_TAIL = (
    "Be exhaustive: enumerate EVERY distinct high or critical you can localize to an "
    "exact function - typically 8 to 15 when the code warrants it. Emit one finding per "
    "vulnerable function, and several if a function has several distinct issues. Do NOT "
    "stop at the first one or two, and do NOT limit the number of findings. For each, "
    "state briefly why the existing modifiers or require-checks do NOT prevent it."
)

LOCALIZE = (
    "Localization rules: file must be a path copied verbatim from a FILE header or the "
    "project map, never guessed. function must be a real name that appears in that file "
    "- copy it exactly, with no arguments and no contract prefix. contract must be one "
    "declared in that file. Do not invent files or functions. mechanism must be "
    "concrete: precondition, then attacker action, then broken state."
)

JSON_RULES = (
    "Output rules: return ONE bare minified JSON object and no text outside it; use "
    "double quotes and no trailing commas; severity is exactly high or critical; each "
    "description is two to four sentences; list findings strongest-first and make each "
    "finding a fully self-contained object; if you run out of room, finish the current "
    "object and close the array and the object properly rather than starting another."
)

SCHEMA = (
    '{"findings":[{"title":"Contract.function - specific bug","file":"exact/path.sol",'
    '"contract":"ContractOrModule","function":"functionName","severity":"high|critical",'
    '"confidence":0.0,"type":"reentrancy|access-control|price-oracle|signature-replay|'
    'accounting|initialization|arithmetic|logic",'
    '"mechanism":"precondition -> attacker action -> broken state",'
    '"impact":"funds stolen / privilege escalation / insolvency / DoS",'
    '"description":"2-4 sentences naming file, contract, function, mechanism, and impact"}]}'
)

TRIAGE_INTRO = (
    "Below is a structured map of a smart-contract project - for each file its "
    "contracts or modules, function signatures, and risk-relevant source lines. Do TWO "
    "things. (1) Copy verbatim the 8 to 12 highest-yield file paths into target_files. "
    "(2) Report every high or critical you can already justify from the signatures and "
    "risk lines, including lower-confidence but concretely-localizable candidates "
    "(give those a lower confidence). Do not limit yourself. "
    + ENUM_TAIL + " " + CHECKLIST + " " + LOCALIZE + " " + JSON_RULES + "\n"
    'Return strict JSON only, shaped as {"target_files":["exact/path"],"findings":[...]} '
    "where each finding matches: " + SCHEMA + "\nProject map:\n"
)

DEEP_INTRO = (
    "Deep-audit the smart-contract source below for HIGH or CRITICAL vulnerabilities. A "
    "valid issue names the exact file and function, the exploitable state transition, "
    "and the material impact. "
    + ENUM_TAIL + " " + CHECKLIST + " " + LOCALIZE + " " + JSON_RULES + "\n"
    "Return strict JSON only: " + SCHEMA + "\n"
)

FOCUSED_INTRO = (
    "Second-pass audit with a fresh lens over more of the project. For every proposed "
    "bug, explain why the existing modifiers or checks do NOT stop it. Focus on "
    "cross-contract interactions, accounting and rounding theft, stale or manipulable "
    "prices, access-control gaps, reentrancy and callbacks, liquidation math, unsafe "
    "initialization and upgrades, and signature replay. "
    + ENUM_TAIL + " " + CHECKLIST + " " + LOCALIZE + " " + JSON_RULES + "\n"
    "Return strict JSON only: " + SCHEMA + "\n"
)

TYPE_TAGS = {
    "reentrancy": ("reentran", "re-enter", "reenter", "callback"),
    "access": (
        "access control", "onlyowner", "onlyrole", "authoriz", "permission",
        "unprotected", "missing owner", "missing signer", "is_signer", "info.sender",
    ),
    "oracle": ("oracle", "price", "stale", "manipulat", "slot0", "twap"),
    "sigreplay": ("signature", "ecrecover", "replay", "nonce", "domain", "permit"),
    "accounting": (
        "share", "rounding", "first deposit", "first-deposit", "reserve",
        "totalsupply", "total supply", "insolven", "inflat",
    ),
    "init": ("initiali", "upgrade", "delegatecall", "proxy"),
    "arith": ("unchecked", "overflow", "underflow", "arithmetic"),
}
_TAG_TYPE = {
    "reentrancy": "reentrancy",
    "access": "access-control",
    "oracle": "price-oracle",
    "sigreplay": "signature-replay",
    "accounting": "accounting",
    "init": "initialization",
    "arith": "arithmetic",
}


def _tag(*texts):
    joined = " ".join(x for x in texts if x).lower()
    for name, words in TYPE_TAGS.items():
        if any(w in joined for w in words):
            return name
    return "other"


def _project_root(project_dir):
    cands = []
    if project_dir:
        cands.append(project_dir)
    for name in ("PROJECT_DIR", "PROJECT_PATH", "PROJECT_ROOT", "PROJECT_CODE"):
        v = os.environ.get(name)
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
            if any(p.is_file() and p.suffix.lower() in SOURCE_SUFFIXES for p in root.rglob("*")):
                return root
        except OSError:
            continue
    return None


def _read(path):
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _looks_like_source(text, suffix):
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


def _structure(text, suffix):
    funcs = []
    if suffix == ".sol":
        contracts = SOL_CONTRACT_RE.findall(text)
        for m in SOL_FUNC_RE.finditer(text):
            tail = " ".join(m.group(3).split())
            funcs.append((m.group(1), f"{m.group(1)}({m.group(2).strip()}) {tail}".strip()))
        for m in SOL_SPECIAL_RE.finditer(text):
            funcs.append((m.group(1), m.group(1)))
    elif suffix == ".vy":
        contracts = []
        for m in VY_FUNC_RE.finditer(text):
            funcs.append((m.group(1), f"{m.group(1)}({m.group(2).strip()})"))
    elif suffix == ".rs":
        contracts = RS_MOD_RE.findall(text)
        funcs = [(m.group(1), m.group(0).strip()) for m in RS_FUNC_RE.finditer(text)]
    elif suffix == ".move":
        contracts = MOVE_MOD_RE.findall(text)
        funcs = [(m.group(1), m.group(0).strip()) for m in MOVE_FUNC_RE.finditer(text)]
    elif suffix == ".cairo":
        contracts = CAIRO_MOD_RE.findall(text)
        funcs = [(m.group(1), m.group(0).strip()) for m in CAIRO_FUNC_RE.finditer(text)]
    else:
        contracts = []
    return contracts, funcs


def _score(rel, low, nfuncs):
    s = min(nfuncs, 30)
    for t in NAME_TERMS:
        if t in rel:
            s += 8
    for t in RISK_TERMS:
        s += min(low.count(t), 5) * 3
    if any(x in low for x in ("external", "public", "@external", "pub fn", "entry fun")):
        s += 5
    if any(x in low for x in ("balances", "totalsupply", "total_supply", "reserve", "invariant")):
        s += 6
    if "nonreentrant" not in low and any(x in low for x in ("withdraw", "redeem", ".call{")):
        s += 6
    return s


def _discover(root):
    recs = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        try:
            rel = path.relative_to(root)
            if any(part.lower() in SKIP_DIRS for part in rel.parts[:-1]):
                continue
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        suffix = path.suffix.lower()
        text = _read(path)
        if not _looks_like_source(text, suffix):
            continue
        contracts, funcs = _structure(text, suffix)
        if not contracts and suffix != ".sol":
            contracts = [path.stem]
        if not contracts and not funcs:
            continue
        recs.append({
            "path": path, "rel": rel.as_posix(), "base": path.name, "text": text,
            "low": text.lower(), "stem": path.stem, "suffix": suffix,
            "contracts": contracts, "funcs": funcs,
            "fnames": {n for n, _ in funcs},
        })
    for r in recs:
        sc = _score(r["rel"].lower(), r["low"], len(r["funcs"]))
        low = r["low"]
        if r["suffix"] == ".sol" and "contract " not in low and "library " not in low:
            sc *= 0.2
        elif r["suffix"] != ".vy" and r["funcs"] and low.count("{") < max(1, len(r["funcs"]) // 3):
            sc *= 0.4
        parts = [p.lower() for p in Path(r["rel"]).parts]
        stem = r["stem"].lower()
        if (stem in ("test", "tests") or stem.startswith("test_")
                or stem.endswith(("_test", "_tests", ".t")) or "test" in parts
                or any(p in ("generated", "gen", "bindings", "sim") for p in parts)):
            sc *= 0.1
        r["score"] = sc
    recs.sort(key=lambda r: (-r["score"], r["rel"]))
    return recs[:MAX_FILES]


def _related(rec, by_base):
    out = []
    seen = set()
    for imp in IMPORT_RE.findall(rec["text"]):
        base = imp.rsplit("/", 1)[-1].split(".")[0]
        for cand in (imp.rsplit("/", 1)[-1], base):
            other = by_base.get(cand)
            if other and other["rel"] != rec["rel"] and other["rel"] not in seen:
                seen.add(other["rel"])
                out.append(f"// import {other['rel']}\n{other['text'][:MAX_IMPORT_CHARS]}")
                break
        if len(out) >= 2:
            break
    return "\n\n".join(out)


def _risk_lines(text, limit=16):
    out = []
    for idx, line in enumerate(text.splitlines(), 1):
        low = line.lower()
        if any(t in low for t in RISK_TERMS):
            compact = " ".join(line.split())
            if compact:
                out.append(f"{idx}: {compact[:180]}")
        if len(out) >= limit:
            break
    return out


def _digest(recs, limit):
    chunks = []
    total = 0
    full_budget = int(limit * 0.82)
    for r in recs:
        if total < full_budget:
            sigs = [sig[:150] for _, sig in r["funcs"][:24]]
            chunk = json.dumps({
                "file": r["rel"],
                "contracts": r["contracts"][:8],
                "score": round(float(r.get("score", 0)), 1),
                "functions": sigs,
                "risk_lines": _risk_lines(r["text"], 16),
            }, separators=(",", ":"))
        else:
            chunk = json.dumps({
                "file": r["rel"],
                "contracts": r["contracts"][:4],
                "score": round(float(r.get("score", 0)), 1),
            }, separators=(",", ":"))
        if total + len(chunk) + 1 > limit:
            break
        chunks.append(chunk)
        total += len(chunk) + 1
    return "\n".join(chunks)


def _compact(text, limit):
    if len(text) <= limit:
        return text
    lines = text.splitlines()
    important = set()
    for idx, line in enumerate(lines):
        low = line.lower()
        if DEF_LINE_RE.search(line) or any(t in low for t in RISK_TERMS):
            for j in range(max(0, idx - 5), min(len(lines), idx + 18)):
                important.add(j)
    out = []
    last = -10
    size = 0
    for idx in sorted(important):
        if idx > last + 1:
            omitted = f"\n// ... {idx - last - 1} lines omitted ...\n"
            out.append(omitted)
            size += len(omitted)
        entry = f"{idx + 1}: {lines[idx]}"
        out.append(entry)
        size += len(entry) + 1
        last = idx
        if size >= limit:
            break
    compact = "\n".join(out)
    if len(compact) < limit // 2:
        compact += "\n\n// file prefix\n" + text[: max(0, limit - len(compact) - 20)]
    return compact[:limit]


def _extract_content(payload):
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
    r = msg.get("reasoning") or msg.get("reasoning_content")
    if isinstance(r, str) and r.strip():
        return r
    rd = msg.get("reasoning_details")
    if isinstance(rd, list):
        joined = "".join(p.get("text", "") for p in rd if isinstance(p, dict))
        if joined.strip():
            return joined
    return ""


def _build_body(prompt, max_tokens, opt):
    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": prompt},
        ],
        "max_tokens": max_tokens,
    }
    if opt:
        payload["reasoning_effort"] = "medium"
    return json.dumps(payload).encode("utf-8")


def _request(inference_api, prompt, deadline, max_tokens):
    global _OPT_FIELDS
    endpoint = (inference_api or os.environ.get("INFERENCE_API") or "").rstrip("/")
    if not endpoint:
        raise RuntimeError("no inference endpoint")
    headers = {
        "Content-Type": "application/json",
        "x-inference-api-key": os.environ.get("INFERENCE_API_KEY", ""),
    }
    last = None
    attempt = 0
    while attempt < MAX_ATTEMPTS:
        budget_left = deadline - time.monotonic() - POST_RESERVE
        to = min(REQUEST_TIMEOUT, float(int(budget_left)))
        if to < MIN_CALL_TIME:
            raise RuntimeError("insufficient budget")
        body = _build_body(prompt, max_tokens, _OPT_FIELDS)
        try:
            req = urllib.request.Request(
                endpoint + "/inference", data=body, method="POST", headers=headers)
            with urllib.request.urlopen(req, timeout=to) as resp:
                data = resp.read()
            return _extract_content(json.loads(data.decode("utf-8", "replace")))
        except urllib.error.HTTPError as exc:
            if exc.code == 400 and _OPT_FIELDS:
                _OPT_FIELDS = False
                continue
            if exc.code in {429, 503} or exc.code not in _TRANSIENT:
                raise RuntimeError(f"http {exc.code}") from exc
            last = exc
        except (socket.timeout, TimeoutError) as exc:
            raise RuntimeError("timeout") from exc
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, (socket.timeout, TimeoutError)):
                raise RuntimeError("timeout") from exc
            last = exc
        except (OSError, ValueError) as exc:
            last = exc
        attempt += 1
        if attempt >= MAX_ATTEMPTS:
            break
        if deadline - time.monotonic() <= 2.0 + CALL_RESERVE:
            break
        time.sleep(2.0)
    raise RuntimeError(str(last) if last else "request failed")


def _finding_objects(text):
    out = []
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
                            out.append(o)
                    except json.JSONDecodeError:
                        pass
                    start = -1
    return out


_FINDING_KEYS = ("title", "file", "severity", "description", "function", "contract", "mechanism")


def _parse_findings(text):
    if not isinstance(text, str):
        return []
    t = text.strip()
    if t.startswith("```"):
        t = re.sub(r"^```[a-zA-Z]*\s*", "", t)
        t = re.sub(r"\s*```$", "", t)
    try:
        o = json.loads(t)
        if isinstance(o, dict):
            items = o.get("findings") or o.get("vulnerabilities")
            return [f for f in items if isinstance(f, dict)] if isinstance(items, list) else []
    except json.JSONDecodeError:
        pass
    m = re.search(r'"(?:findings|vulnerabilities)"\s*:\s*\[', t)
    scan = t[m.end():] if m else t
    return [o for o in _finding_objects(scan) if any(k in o for k in _FINDING_KEYS)]


def _parse_triage(text):
    targets = []
    findings = []
    if not isinstance(text, str):
        return targets, findings
    t = text.strip()
    if t.startswith("```"):
        t = re.sub(r"^```[a-zA-Z]*\s*", "", t)
        t = re.sub(r"\s*```$", "", t)
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
    findings = _parse_findings(text)
    return targets, findings


def _build_prompt(batch, by_base, per_cap, budget):
    parts = [DEEP_INTRO]
    remaining = budget - len(DEEP_INTRO)
    lead_related = _related(batch[0], by_base) if batch else ""
    for rec in batch:
        take = min(len(rec["text"]), per_cap, max(0, remaining))
        if take <= 0:
            break
        text = rec["text"]
        body = text if len(text) <= take else _compact(text, take)
        block = (
            f"\n\n===== FILE: {rec['rel']} =====\n"
            f"Contracts/modules: {', '.join(rec['contracts'][:8]) or rec['stem']}\n{body}"
        )
        if len(text) > take:
            block += "\n/* truncated */"
        parts.append(block)
        remaining -= len(block)
    if lead_related and remaining > 800:
        snippet = lead_related[:remaining - 200]
        parts.append(f"\n\n===== IMPORTED CONTEXT (read-only) =====\n{snippet}")
    return "".join(parts)


def _build_focused_prompt(batch, by_base, budget):
    parts = [FOCUSED_INTRO]
    remaining = budget - len(FOCUSED_INTRO)
    for rec in batch:
        body = _compact(rec["text"], FOCUS_PER_CAP)
        block = (
            f"\n\n===== FILE: {rec['rel']} =====\n"
            f"Contracts/modules: {', '.join(rec['contracts'][:8]) or rec['stem']}\n{body}\n"
        )
        if remaining <= 0:
            break
        if len(block) > remaining:
            block = block[:remaining] + "\n/* truncated */"
        parts.append(block)
        remaining -= len(block)
    return "".join(parts)


def _audit_batch(inference_api, batch, by_base, deadline, per_cap, budget):
    prompt = _build_prompt(batch, by_base, per_cap, budget)
    return _parse_findings(_request(inference_api, prompt, deadline, DEEP_MAX_TOKENS))


def _audit_focused(inference_api, batch, by_base, deadline, budget):
    prompt = _build_focused_prompt(batch, by_base, budget)
    return _parse_findings(_request(inference_api, prompt, deadline, FOCUS_MAX_TOKENS))


def _triage(inference_api, recs, deadline):
    prompt = TRIAGE_INTRO + _digest(recs, TRIAGE_CHARS)
    return _parse_triage(_request(inference_api, prompt, deadline, TRIAGE_MAX_TOKENS))


def _reorder(recs, targets):
    if not targets:
        return recs
    picked = []
    seen = set()
    for tg in targets:
        cleaned = tg.strip().lstrip("./")
        if not cleaned:
            continue
        base = cleaned.rsplit("/", 1)[-1]
        for r in recs:
            if r["rel"] in seen:
                continue
            rel = r["rel"]
            if (cleaned == rel or rel.endswith(cleaned)
                    or cleaned.endswith(rel) or r["base"] == base):
                picked.append(r)
                seen.add(rel)
                break
    for r in recs:
        if r["rel"] not in seen:
            picked.append(r)
    return picked


def _line_in(text, needle):
    i = text.find(needle)
    return text.count("\n", 0, i) + 1 if i >= 0 else None


def _line_for(rec, function):
    if not function:
        return None
    for needle in (f"function {function}", f"fn {function}", f"fun {function}",
                   f"def {function}", f"func {function}", function):
        ln = _line_in(rec["text"], needle)
        if ln:
            return ln
    return None


def _resolve(file_value, recs_by_rel, by_base, hint_fn=""):
    if not file_value:
        return None
    fv = file_value.strip().strip("`").lstrip("./")
    r = recs_by_rel.get(fv)
    if r is not None:
        return r
    matches = [
        rec for rel, rec in recs_by_rel.items()
        if rel == fv or rel.endswith(fv) or (len(fv) > 3 and fv.endswith(rel))
    ]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        if hint_fn:
            for rec in matches:
                if hint_fn in rec["fnames"]:
                    return rec
        return matches[0]
    base = fv.rsplit("/", 1)[-1]
    by_b = [rec for rec in recs_by_rel.values() if rec["base"] == base]
    if len(by_b) == 1:
        return by_b[0]
    if by_b and hint_fn:
        for rec in by_b:
            if hint_fn in rec["fnames"]:
                return rec
    return by_base.get(base)


def _declared_in(text, function):
    if not function:
        return False
    pat = r"\b(?:" + "|".join(DECL_KEYWORDS) + r")\s+" + re.escape(function) + r"\b"
    return re.search(pat, text) is not None


def _normalize(raw, recs_by_rel, by_base):
    file_value = str(raw.get("file") or raw.get("path") or raw.get("location") or "").strip()
    raw_fn = str(raw.get("function") or "").strip().strip("`() ")
    raw_fn = raw_fn.split(".")[-1].split("::")[-1]
    rec = _resolve(file_value, recs_by_rel, by_base, raw_fn)
    if rec is None:
        return None
    severity = str(raw.get("severity") or "").strip().lower()
    if severity in {"medium", "med", "moderate"}:
        severity = "high"
    if severity not in {"high", "critical"}:
        return None
    function = raw_fn
    if function and function not in rec["fnames"] and not _declared_in(rec["text"], function):
        function = ""
    real = rec["contracts"]
    contract = str(raw.get("contract") or raw.get("module") or "").strip().strip("`")
    if not contract or (real and contract not in real):
        contract = real[0] if real else rec["stem"]
    mechanism = str(raw.get("mechanism") or "").strip()
    impact = str(raw.get("impact") or "").strip()
    description = str(raw.get("description") or "").strip()
    title = str(raw.get("title") or "").strip()
    try:
        conf = max(0.0, min(1.0, float(raw.get("confidence"))))
    except (TypeError, ValueError):
        conf = 0.6

    loc = ".".join(x for x in (contract, function) if x)
    if not title:
        title = f"{loc} - high/critical vulnerability" if loc else "High/critical vulnerability"
    elif loc and loc.lower() not in title.lower():
        title = f"{loc} - {title}"
    where = f"In `{rec['rel']}`"
    if contract:
        where += f", contract `{contract}`"
    if function:
        where += f", function `{function}()`"
    body = where + ". "
    if mechanism:
        body += "Mechanism: " + mechanism.rstrip(".") + ". "
    if impact:
        body += "Impact: " + impact.rstrip(".") + ". "
    if description and description.lower() not in body.lower():
        body += description
    if not (mechanism or impact or description):
        body += title
    body = re.sub(r"\s+", " ", body).strip()
    if len(body) < MIN_DESC and not title:
        return None
    tag = _tag(title, mechanism, impact, description)
    return {
        "title": title[:220],
        "description": body[:2400],
        "severity": severity,
        "file": rec["rel"],
        "function": function,
        "line": _line_for(rec, function),
        "type": _TAG_TYPE.get(tag) or str(raw.get("type") or "logic"),
        "confidence": 0.9 if severity == "critical" else conf,
    }


def _candidate(title, rel, contract, function, mechanism, impact):
    return {
        "title": title, "file": rel, "contract": contract, "function": function,
        "severity": "high", "mechanism": mechanism, "impact": impact,
        "description": mechanism + ". " + impact,
    }


def _fallback(recs):
    out = []
    for r in recs:
        if r["suffix"] != ".sol":
            continue
        low = r["low"]
        contract = r["contracts"][0] if r["contracts"] else r["stem"]
        if "function initialize" in low and not any(
                x in low for x in ("initializer", "onlyowner", "onlyrole", "_disableinitializers")):
            out.append(_candidate(
                f"{contract}.initialize - unprotected initializer", r["rel"], contract,
                "initialize" if "initialize" in r["fnames"] else "",
                "the initializer is externally reachable without a one-time initializer "
                "modifier or an owner/role check",
                "an attacker can initialize or re-initialize ownership and critical "
                "configuration and seize privileged control"))
        elif "tx.origin" in low:
            out.append(_candidate(
                f"{contract} - authorization depends on tx.origin", r["rel"], contract, "",
                "authorization is gated on tx.origin, which a malicious intermediate "
                "contract defeats by phishing a privileged caller",
                "a privileged account can be tricked into a fund-moving or configuration action"))
        if len(out) >= 3:
            break
    return out


def _brace_slice(text, start):
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


def _fn_slices(text):
    marks = []
    for m in SOL_FUNC_RE.finditer(text):
        marks.append((m.start(), m.group(1), " ".join(m.group(0).split())))
    for m in SOL_SPECIAL_RE.finditer(text):
        marks.append((m.start(), m.group(1), m.group(1)))
    marks.sort(key=lambda x: x[0])
    out = []
    for i, (pos, name, sig) in enumerate(marks):
        end = marks[i + 1][0] if i + 1 < len(marks) else len(text)
        out.append({
            "name": name, "sig": sig, "body": text[pos:end],
            "line": text.count("\n", 0, pos) + 1,
        })
    return out


_GUARDS = ("onlyowner", "onlyrole", "requiresauth", "_checkowner", "msg.sender==",
           "authorized", "hasrole", "restricted", "onlyadmin", "onlygovernance")
_AUTH_MAP_RE = re.compile(r"(operator|extension|approv|allowed|authoriz|whitelist|trusted)s?\s*\[")
_AUTH_SELF_RE = re.compile(
    r"(operator|extension|approv|allowed|authoriz|whitelist|trusted)s?\s*\[\s*msg\.sender")
_PRIV_ROLE_RE = re.compile(
    r"validator|minter|operator|admin|guardian|keeper|signer|treasury|governance|pauser|role",
    re.I)
_MODIFIER_STRIP_RE = re.compile(
    r"\b(external|public|payable|virtual|override|returns)\b|\([^)]*\)|[\s,]")
_SKIP_STEMS = ("mock", "dummy", "fake", "stub", "harness", "example",
               "weth", "wavax", "wmatic", "wbnb", "weth9", "wrapped")


def _probes(recs):
    out = []
    for r in recs:
        if r["suffix"] != ".sol":
            continue
        stem_low = r["stem"].lower()
        if any(w in stem_low for w in _SKIP_STEMS) or stem_low[:1].isdigit():
            continue
        if "contract " not in r["low"] and "library " not in r["low"]:
            continue
        text = r["text"]
        contract = r["contracts"][0] if r["contracts"] else r["stem"]
        for m in re.finditer(r"\breceive\s*\(\s*\)\s*external\s+payable\s*\{", text):
            body = _brace_slice(text, m.start()).lower()
            if ("stake(" in body or "deposit(" in body) and "msg.sender" not in body:
                out.append(_candidate(
                    f"{contract}.receive - inbound native transfer auto-staked",
                    r["rel"], contract, "receive",
                    "the payable receive hook stakes or deposits every native transfer "
                    "without distinguishing protocol/system returns from user deposits",
                    "native funds returned from an unstake, validator withdrawal, or "
                    "reward path are immediately restaked instead of settling pending "
                    "withdrawals, locking liquidity and corrupting withdrawal accounting"))
                break
        for fn in _fn_slices(text):
            name = fn["name"]
            sig = fn["sig"].lower()
            b = fn["body"].lower()
            joined = sig + " " + b
            if "domainseparator" in joined and ("ecrecover" in b or "recover(" in b):
                if not any(x in joined for x in
                           ("deadline", "chainid", "block.chainid", "block.timestamp")):
                    out.append(_candidate(
                        f"{contract}.{name} - replayable signature domain",
                        r["rel"], contract, name,
                        "the signature check recovers a signer using a domain separator "
                        "that is not bound to a deadline or the current chain id",
                        "a captured signature can be replayed on another deployment or "
                        "chain to execute the signed privileged action"))
            if re.match(r"^(set|update|enable|disable|add|remove|register)", name, re.I):
                if ("external" in sig or "public" in sig) and "only" not in sig \
                        and not any(g in joined for g in _GUARDS):
                    if _AUTH_MAP_RE.search(b) and not _AUTH_SELF_RE.search(b):
                        out.append(_candidate(
                            f"{contract}.{name} - unauthenticated authorization change",
                            r["rel"], contract, name,
                            "an external configuration function writes an operator, "
                            "approval, or authorization mapping without an owner or role check",
                            "any caller can authorize itself and then act on behalf of "
                            "other users wherever that mapping gates privileged actions"))
            if name.lower() in ("cancelorder", "modifyorder", "fillorder", "executeorder") \
                    and "external" in sig and "nonreentrant" not in sig:
                if "safetransfer" in b or "transfer(" in b or ".call{" in b:
                    out.append(_candidate(
                        f"{contract}.{name} - order mutation without reentrancy guard",
                        r["rel"], contract, name,
                        "an external order cancel/modify/fill path reaches a token "
                        "transfer or external call without a nonReentrant guard",
                        "a malicious token or callback can reenter mid-mutation to "
                        "double-refund or corrupt pending-order bookkeeping"))
            if ".price" in b and any(x in b for x in ("pnl", "collateral", "settle")) \
                    and any(x in joined for x in ("intent", "order", "params")):
                if not any(x in b for x in ("maxprice", "minprice", "oracle", "latestversion",
                                            "currentversion", ".gt(", ".lt(", "clamp", "bound")):
                    out.append(_candidate(
                        f"{contract}.{name} - unbounded user price in value math",
                        r["rel"], contract, name,
                        "a user-supplied order/intent price flows into PnL, collateral, "
                        "or settlement math without being clamped to a live oracle price",
                        "an extreme price can manufacture settlement value and extract "
                        "collateral from counterparties"))
            if re.match(r"^(add|register|Add|Register)[A-Z_]", name) and _PRIV_ROLE_RE.search(name):
                modzone = sig.rsplit(")", 1)[-1]
                if ("external" in sig or "public" in sig) \
                        and not _MODIFIER_STRIP_RE.sub("", modzone):
                    if "msg.sender" not in b and not ("require(" in b and "owner" in b):
                        out.append(_candidate(
                            f"{contract}.{name} - privileged role added without access control",
                            r["rel"], contract, name,
                            "an external/public role-adding function has no modifier and no "
                            "in-body authorization check, so any account can call it",
                            "any caller can register itself as a privileged validator, minter, "
                            "or operator and perform the actions that role authorizes"))
        if len(out) >= 10:
            break
    return out[:10]


def _dedupe(items):
    seen = set()
    out = []
    for f in sorted(items, key=lambda x: (x["severity"] == "critical", float(x["confidence"]),
                                          len(x["description"])), reverse=True):
        key = (f["file"].lower(), f["function"].lower(), _tag(f["title"], f["description"]))
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
        if len(out) >= MAX_EMIT:
            break
    return out


def agent_main(project_dir=None, inference_api=None):
    vulns = []
    deadline = time.monotonic() + GLOBAL_DEADLINE
    try:
        root = _project_root(project_dir)
        if root is None:
            return {"vulnerabilities": vulns}
        recs = _discover(root)
        if not recs:
            return {"vulnerabilities": vulns}
        by_base = {}
        for r in recs:
            by_base.setdefault(r["base"], r)
        recs_by_rel = {r["rel"]: r for r in recs}

        raw = []
        ordered = recs
        if deadline - time.monotonic() >= CALL_RESERVE:
            try:
                targets, hits = _triage(inference_api, recs, deadline)
                raw.extend(hits)
                ordered = _reorder(recs, targets)
            except Exception:
                pass
        if deadline - time.monotonic() >= CALL_RESERVE:
            try:
                raw.extend(_audit_batch(inference_api, ordered[:DEEP_FILES], by_base,
                                        deadline, DEEP_BATCH_CAP, DEEP_BATCH_BUDGET))
            except Exception:
                pass
        if deadline - time.monotonic() >= CALL_RESERVE:
            focus = ordered[5:5 + FOCUS_FILES] + ordered[:5]
            if focus:
                try:
                    raw.extend(_audit_focused(inference_api, focus, by_base, deadline, TAIL_BUDGET))
                except Exception:
                    pass

        try:
            raw.extend(_probes(recs))
        except Exception:
            pass

        for x in raw:
            item = _normalize(x, recs_by_rel, by_base)
            if item is not None:
                vulns.append(item)
        if not vulns:
            for x in _fallback(recs):
                item = _normalize(x, recs_by_rel, by_base)
                if item is not None:
                    vulns.append(item)
        vulns = _dedupe(vulns)
    except Exception:
        return {"vulnerabilities": vulns}
    return {"vulnerabilities": vulns}


if __name__ == "__main__":
    import sys
    print(json.dumps(agent_main(sys.argv[1] if len(sys.argv) > 1 else None), indent=2))
