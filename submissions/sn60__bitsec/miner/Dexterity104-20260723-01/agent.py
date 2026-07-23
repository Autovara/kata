"""Whole-repository security review agent for on-chain code in five languages.

Runs standalone on the Python standard library. All project code is read from
the local project directory; every model call goes through the inference proxy
that the execution environment supplies.
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

LLM_ID = os.environ.get("KATA_MINER_MODEL", "deepseek-ai/DeepSeek-V3.2-TEE")
# Greedy decoding keeps repeated audits of one codebase aligned; breadth comes
# from layering independent passes, not from sampling spread.
SAMPLING_TEMP = 0.0
MAP_TOKENS = 7_000
CORE_TOKENS = 8_000
SECOND_TOKENS = 8_000

# Wall-clock envelope: finish well inside the runner's limit even on slow calls.
WALL_BUDGET = 690.0
HTTP_TIMEOUT = 190.0
FULL_PASS_RESERVE = 205.0
# The closing sweep only needs a slimmer reserve: everything after it is quick
# local computation, so two slow earlier calls should not cancel it.
FINAL_PASS_RESERVE = 150.0
WRAPUP_RESERVE = 12.0
FLOOR_CALL_SECS = 30.0
TRY_LIMIT = 2

RETRYABLE_HTTP = frozenset({500, 502, 504, 408, 409, 425, 520, 522, 524, 529})


def _pluck_text(payload):
    if not isinstance(payload, dict):
        return ""
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        return ""
    msg = choices[0].get("message")
    if not isinstance(msg, dict):
        return ""
    content = msg.get("content")
    if isinstance(content, list):
        content = "".join(p.get("text", "") for p in content if isinstance(p, dict))
    if isinstance(content, str) and content.strip():
        return content
    for alt in ("reasoning", "reasoning_content"):
        val = msg.get(alt)
        if isinstance(val, str) and val.strip():
            return val
    detail = msg.get("reasoning_details")
    if isinstance(detail, list):
        merged = "".join(p.get("text", "") for p in detail if isinstance(p, dict))
        if merged.strip():
            return merged
    return ""


def _call_proxy(inference_api, prompt, deadline, token_cap):
    endpoint = (inference_api or os.environ.get("INFERENCE_API") or "").rstrip("/")
    if not endpoint:
        raise RuntimeError("inference endpoint missing")
    wire = json.dumps({
        "model": LLM_ID,
        "messages": [
            {"role": "system", "content": ROLE_MSG},
            {"role": "user", "content": prompt},
        ],
        "max_tokens": token_cap,
        "temperature": SAMPLING_TEMP,
    }).encode("utf-8")
    hdrs = {
        "Content-Type": "application/json",
        "x-inference-api-key": os.environ.get("INFERENCE_API_KEY", ""),
    }
    failure = None
    tries = 0
    while tries < TRY_LIMIT:
        left = deadline - time.monotonic() - WRAPUP_RESERVE
        wait = min(HTTP_TIMEOUT, float(int(left)))
        if wait < FLOOR_CALL_SECS:
            raise RuntimeError("clock exhausted")
        try:
            req = urllib.request.Request(
                endpoint + "/inference", data=wire, method="POST", headers=hdrs)
            with urllib.request.urlopen(req, timeout=wait) as resp:
                blob = resp.read()
            return _pluck_text(json.loads(blob.decode("utf-8", "replace")))
        except urllib.error.HTTPError as exc:
            if exc.code not in RETRYABLE_HTTP:
                raise RuntimeError(f"http {exc.code}") from exc
            failure = exc
        except (socket.timeout, TimeoutError) as exc:
            raise RuntimeError("timeout") from exc
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, (socket.timeout, TimeoutError)):
                raise RuntimeError("timeout") from exc
            failure = exc
        except (OSError, ValueError) as exc:
            failure = exc
        tries += 1
        if tries >= TRY_LIMIT:
            break
        if deadline - time.monotonic() <= 2.0 + FULL_PASS_RESERVE:
            break
        time.sleep(2.0)
    raise RuntimeError(str(failure) if failure else "proxy call failed")


def _unfence(text):
    t = text.strip()
    if t.startswith("```"):
        t = re.sub(r"^```[a-zA-Z]*\s*", "", t)
        t = re.sub(r"\s*```$", "", t)
    return t


def _scan_objects(text):
    found = []
    nest = 0
    head = -1
    in_str = bs = False
    for i, ch in enumerate(text):
        if in_str:
            if bs:
                bs = False
            elif ch == "\\":
                bs = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            if nest == 0:
                head = i
            nest += 1
        elif ch == "}":
            if nest > 0:
                nest -= 1
                if nest == 0 and head >= 0:
                    try:
                        obj = json.loads(text[head:i + 1])
                        if isinstance(obj, dict):
                            found.append(obj)
                    except json.JSONDecodeError:
                        pass
                    head = -1
    return found


FINDING_MARKS = ("severity", "file", "title", "function", "description", "mechanism", "contract")


def _findings_from(text):
    if not isinstance(text, str):
        return []
    t = _unfence(text)
    try:
        obj = json.loads(t)
        if isinstance(obj, dict):
            rows = obj.get("findings") or obj.get("vulnerabilities")
            return [f for f in rows if isinstance(f, dict)] if isinstance(rows, list) else []
    except json.JSONDecodeError:
        pass
    m = re.search(r'"(?:findings|vulnerabilities)"\s*:\s*\[', t)
    window = t[m.end():] if m else t
    return [o for o in _scan_objects(window) if any(k in o for k in FINDING_MARKS)]


def _map_reply_from(text):
    picks = []
    rows = []
    if not isinstance(text, str):
        return picks, rows
    t = _unfence(text)
    try:
        obj = json.loads(t)
        if isinstance(obj, dict):
            tg = obj.get("target_files")
            if isinstance(tg, list):
                picks = [str(x) for x in tg if isinstance(x, str)]
            fs = obj.get("findings") or obj.get("vulnerabilities")
            if isinstance(fs, list):
                rows = [f for f in fs if isinstance(f, dict)]
            return picks, rows
    except json.JSONDecodeError:
        pass
    m = re.search(r'"target_files"\s*:\s*\[(.*?)\]', t, re.S)
    if m:
        picks = re.findall(r'"([^"]+)"', m.group(1))
    rows = _findings_from(text)
    return picks, rows


LABEL_CUES = {
    "reent": ("callback", "reenter", "re-enter", "reentran"),
    "auth": (
        "unprotected", "missing signer", "permission", "authoriz", "onlyrole",
        "access control", "onlyowner", "is_signer", "missing owner", "info.sender",
    ),
    "px": ("stale", "twap", "slot0", "manipulat", "price", "oracle"),
    "sig": ("replay", "permit", "domain", "nonce", "ecrecover", "signature"),
    "acct": (
        "rounding", "inflat", "insolven", "reserve", "first-deposit",
        "first deposit", "total supply", "totalsupply", "share",
    ),
    "boot": ("proxy", "delegatecall", "upgrade", "initiali"),
    "math": ("underflow", "overflow", "arithmetic", "unchecked"),
}
LABEL_OUT = {
    "reent": "reentrancy",
    "auth": "access-control",
    "px": "price-oracle",
    "sig": "signature-replay",
    "acct": "accounting",
    "boot": "initialization",
    "math": "arithmetic",
}

REPORT_CAP = 14
REPORT_PER_FILE = 4
DESC_FLOOR = 40
BASE_CONF = 0.5
HIGH_CONF_FLOOR = 0.45


def _label(*texts):
    merged = " ".join(x for x in texts if x).lower()
    for key, cues in LABEL_CUES.items():
        if any(c in merged for c in cues):
            return key
    return "other"


def _prune(rows):
    seen = set()
    tally = {}
    kept = []
    ranked = sorted(rows, key=lambda x: (x["severity"] == "critical", float(x["confidence"]),
                                         len(x["description"])), reverse=True)
    for f in ranked:
        fkey = f["file"].lower()
        if tally.get(fkey, 0) >= REPORT_PER_FILE:
            continue
        # Distinguish entries by normalized title rather than a coarse class
        # label: one function may carry two unrelated flaws and both should
        # survive into the final report.
        tkey = re.sub(r"[^a-z0-9]+", " ", f["title"].lower()).strip()[:70]
        sig = (fkey, f["function"].lower(), tkey)
        if sig in seen:
            continue
        seen.add(sig)
        kept.append(f)
        tally[fkey] = tally.get(fkey, 0) + 1
        if len(kept) >= REPORT_CAP:
            break
    return kept


AUTH_MARKS = ("onlyrole", "onlyowner", "_checkowner", "requiresauth", "msg.sender==",
              "hasrole", "authorized", "onlyadmin", "restricted", "onlygovernance")
RX_PERM_MAP = re.compile(r"(operator|extension|approv|allowed|authoriz|whitelist|trusted)s?\s*\[")
RX_PERM_SELF = re.compile(
    r"(operator|extension|approv|allowed|authoriz|whitelist|trusted)s?\s*\[\s*msg\.sender")
RX_ROLE_WORD = re.compile(
    r"validator|minter|operator|admin|guardian|keeper|signer|treasury|governance|pauser|role",
    re.I)
RX_MOD_STRIP = re.compile(
    r"\b(external|public|payable|virtual|override|returns)\b|\([^)]*\)|[\s,]")
BLAND_STEMS = ("harness", "stub", "fake", "dummy", "mock", "example",
               "wrapped", "weth9", "wbnb", "wmatic", "wavax", "weth")


def _block_at(text, start):
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


def _carve_fns(text):
    marks = []
    for m in RX_SOL_FN.finditer(text):
        marks.append((m.start(), m.group(1), " ".join(m.group(0).split())))
    for m in RX_SOL_SPECIAL.finditer(text):
        marks.append((m.start(), m.group(1), m.group(1)))
    marks.sort(key=lambda x: x[0])
    carved = []
    for i, (pos, name, sig) in enumerate(marks):
        stop = marks[i + 1][0] if i + 1 < len(marks) else len(text)
        carved.append({"name": name, "sig": sig, "body": text[pos:stop]})
    return carved


def _stub(title, rp, unit, fn, mechanism, impact):
    return {
        "title": title, "file": rp, "contract": unit, "function": fn,
        "severity": "high", "mechanism": mechanism, "impact": impact,
        "description": mechanism + ". " + impact,
    }


def _sig_replay_probe(r, unit, name, sig, b, joined):
    if "domainseparator" in joined and ("ecrecover" in b or "recover(" in b):
        if not any(x in joined for x in
                   ("deadline", "chainid", "block.chainid", "block.timestamp")):
            return _stub(
                f"{unit}.{name} - replayable signature domain",
                r["rp"], unit, name,
                "the signature check recovers a signer using a domain separator "
                "that is not bound to a deadline or the current chain id",
                "a captured signature can be replayed on another deployment or "
                "chain to execute the signed privileged action")
    return None


def _perm_write_probe(r, unit, name, sig, b, joined):
    if re.match(r"^(set|update|enable|disable|add|remove|register)", name, re.I):
        if ("external" in sig or "public" in sig) and "only" not in sig \
                and not any(g in joined for g in AUTH_MARKS):
            if RX_PERM_MAP.search(b) and not RX_PERM_SELF.search(b):
                return _stub(
                    f"{unit}.{name} - unauthenticated authorization change",
                    r["rp"], unit, name,
                    "an external configuration function writes an operator, "
                    "approval, or authorization mapping without an owner or role check",
                    "any caller can authorize itself and then act on behalf of "
                    "other users wherever that mapping gates privileged actions")
    return None


def _order_reent_probe(r, unit, name, sig, b, joined):
    if name.lower() in ("cancelorder", "modifyorder", "fillorder", "executeorder") \
            and "external" in sig and "nonreentrant" not in sig:
        if "safetransfer" in b or "transfer(" in b or ".call{" in b:
            return _stub(
                f"{unit}.{name} - order mutation without reentrancy guard",
                r["rp"], unit, name,
                "an external order cancel/modify/fill path reaches a token "
                "transfer or external call without a nonReentrant guard",
                "a malicious token or callback can reenter mid-mutation to "
                "double-refund or corrupt pending-order bookkeeping")
    return None


def _free_price_probe(r, unit, name, sig, b, joined):
    if ".price" in b and any(x in b for x in ("pnl", "collateral", "settle")) \
            and any(x in joined for x in ("intent", "order", "params")):
        if not any(x in b for x in ("maxprice", "minprice", "oracle", "latestversion",
                                    "currentversion", ".gt(", ".lt(", "clamp", "bound")):
            return _stub(
                f"{unit}.{name} - unbounded user price in value math",
                r["rp"], unit, name,
                "a user-supplied order/intent price flows into PnL, collateral, "
                "or settlement math without being clamped to a live oracle price",
                "an extreme price can manufacture settlement value and extract "
                "collateral from counterparties")
    return None


def _role_add_probe(r, unit, name, sig, b, joined):
    if re.match(r"^(add|register|Add|Register)[A-Z_]", name) and RX_ROLE_WORD.search(name):
        modzone = sig.rsplit(")", 1)[-1]
        if ("external" in sig or "public" in sig) \
                and not RX_MOD_STRIP.sub("", modzone):
            if "msg.sender" not in b and not ("require(" in b and "owner" in b):
                return _stub(
                    f"{unit}.{name} - privileged role added without access control",
                    r["rp"], unit, name,
                    "an external/public role-adding function has no modifier and no "
                    "in-body authorization check, so any account can call it",
                    "any caller can register itself as a privileged validator, minter, "
                    "or operator and perform the actions that role authorizes")
    return None


_FN_PROBES = (_sig_replay_probe, _perm_write_probe, _order_reent_probe,
              _free_price_probe, _role_add_probe)


def _pattern_scan(corpus):
    hits = []
    for r in corpus:
        if r["ext"] != ".sol":
            continue
        short_low = r["short"].lower()
        if any(w in short_low for w in BLAND_STEMS) or short_low[:1].isdigit():
            continue
        if "contract " not in r["lsrc"] and "library " not in r["lsrc"]:
            continue
        src = r["src"]
        unit = r["units"][0] if r["units"] else r["short"]
        for m in re.finditer(r"\breceive\s*\(\s*\)\s*external\s+payable\s*\{", src):
            body = _block_at(src, m.start()).lower()
            if ("stake(" in body or "deposit(" in body) and "msg.sender" not in body:
                hits.append(_stub(
                    f"{unit}.receive - inbound native transfer auto-staked",
                    r["rp"], unit, "receive",
                    "the payable receive hook stakes or deposits every native transfer "
                    "without distinguishing protocol/system returns from user deposits",
                    "native funds returned from an unstake, validator withdrawal, or "
                    "reward path are immediately restaked instead of settling pending "
                    "withdrawals, locking liquidity and corrupting withdrawal accounting"))
                break
        for fn in _carve_fns(src):
            name = fn["name"]
            sig = fn["sig"].lower()
            b = fn["body"].lower()
            joined = sig + " " + b
            for probe in _FN_PROBES:
                hit = probe(r, unit, name, sig, b, joined)
                if hit:
                    hits.append(hit)
        if len(hits) >= 10:
            break
    return hits[:10]


def _last_resort(corpus):
    picks = []
    for r in corpus:
        if r["ext"] != ".sol":
            continue
        lsrc = r["lsrc"]
        unit = r["units"][0] if r["units"] else r["short"]
        if "function initialize" in lsrc and not any(
                x in lsrc for x in ("initializer", "onlyowner", "onlyrole", "_disableinitializers")):
            picks.append(_stub(
                f"{unit}.initialize - unprotected initializer", r["rp"], unit,
                "initialize" if "initialize" in r["signames"] else "",
                "the initializer is externally reachable without a one-time initializer "
                "modifier or an owner/role check",
                "an attacker can initialize or re-initialize ownership and critical "
                "configuration and seize privileged control"))
        elif "tx.origin" in lsrc:
            picks.append(_stub(
                f"{unit} - authorization depends on tx.origin", r["rp"], unit, "",
                "authorization is gated on tx.origin, which a malicious intermediate "
                "contract defeats by phishing a privileged caller",
                "a privileged account can be tricked into a fund-moving or configuration action"))
        if len(picks) >= 3:
            break
    return picks


CODE_EXTS = (".rs", ".sol", ".cairo", ".move", ".vy")
PRUNE_DIRS = {
    "node_modules", "artifacts", "broadcast", "interfaces", "interface",
    "test", "tests", "mock", "mocks", "fixtures", "fixture", "example",
    "examples", "script", "scripts", "vendor", "vendors", "lib", "libs",
    "out", "cache", "coverage", "target", "docs", ".git", ".github",
    "deps", "dist", "build",
}

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
RX_DECL_LINE = re.compile(
    r"\bfunction\b|\bdef\b|\bfn\b|\bfun\b|\bmodifier\b|\bconstructor\b|\bmodule\b|\bmapping\b"
)
FN_KEYWORDS = ("def", "func", "fn", "function", "fun")

HOT_NAMES = (
    "escrow", "auction", "liquidat", "swap", "stable", "vault", "pool",
    "router", "manager", "controller", "strategy", "market", "lend",
    "borrow", "oracle", "price", "stak", "reward", "treasury", "bridge",
    "factory", "proxy", "govern", "token", "collateral", "vesting",
    "distributor", "minter", "gauge", "farm", "perp", "position", "margin",
    "settle", "clearing", "coin", "account", "program",
)
HOT_TOKENS = (
    "withdraw", "redeem", "deposit", "borrow", "repay", "liquidat",
    "delegatecall", ".call{", ".call.value", "selfdestruct", "tx.origin",
    "assembly", "ecrecover", "permit", "signature", "nonce", "initialize",
    "upgradeto", "onlyowner", "onlyrole", "_mint", "_burn", "mint(", "burn(",
    "collateral", "share", "totalsupply", "balanceof", "oracle", "getprice",
    "latestround", "slot0", "flash", "swap", "reward", "claim", "unchecked",
    "safetransfer", "transferfrom", "approve", "settle", "rebalance",
    "liquidity", "reserve", "invariant", "signer", "authority", "lamports",
    "invoke", "cpi", "checked_", "unwrap", "close_account", "realloc",
    "try_borrow", "deserialize", "next_account", "assert_eq", "owner",
    "is_signer", "wasm", "msg.sender", "info.sender", "transfer", "sub_msg",
    "coin(", "acquires", "borrow_global", "move_to", "move_from",
    "capability", "signer::", "get_caller_address", "get_contract_address",
    "felt", "starknet", "assert(",
)

BYTE_CEILING = 260_000
FILE_CEILING = 90
IMPORT_CTX_CHARS = 3_000
CORE_FILE_CHARS = 15_000
CORE_CALL_CHARS = 47_000
CORE_FILES = 5
SECOND_CALL_CHARS = 46_000
SECOND_FILES = 8
SECOND_FILE_CHARS = 8_000
MAP_CHARS = 40_000


def _locate_root(project_dir):
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
            if any(p.is_file() and p.suffix.lower() in CODE_EXTS for p in root.rglob("*")):
                return root
        except OSError:
            continue
    return None


def _slurp(path):
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


_CODE_SMELLS = {
    ".sol": ("contract ", "library ", "function "),
    ".vy": ("def ", "@external", "@internal"),
    ".rs": ("fn ",),
    ".move": ("fun ", "module "),
    ".cairo": ("fn ", "func ", "mod "),
}


def _smells_like_code(text, ext):
    needles = _CODE_SMELLS.get(ext)
    return any(n in text for n in needles) if needles else False


def _outline(text, ext):
    sigs = []
    if ext == ".sol":
        units = RX_SOL_UNIT.findall(text)
        for m in RX_SOL_FN.finditer(text):
            trail = " ".join(m.group(3).split())
            sigs.append((m.group(1), f"{m.group(1)}({m.group(2).strip()}) {trail}".strip()))
        for m in RX_SOL_SPECIAL.finditer(text):
            sigs.append((m.group(1), m.group(1)))
    elif ext == ".vy":
        units = []
        for m in RX_VY_FN.finditer(text):
            sigs.append((m.group(1), f"{m.group(1)}({m.group(2).strip()})"))
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


def _heat(rp_low, lsrc, nsigs):
    w = min(nsigs, 30)
    for t in HOT_NAMES:
        if t in rp_low:
            w += 8
    for t in HOT_TOKENS:
        w += min(lsrc.count(t), 5) * 3
    if any(x in lsrc for x in ("external", "public", "@external", "pub fn", "entry fun")):
        w += 5
    if any(x in lsrc for x in ("balances", "totalsupply", "total_supply", "reserve", "invariant")):
        w += 6
    if "nonreentrant" not in lsrc and any(x in lsrc for x in ("withdraw", "redeem", ".call{")):
        w += 6
    return w


def _harvest(root):
    corpus = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in CODE_EXTS:
            continue
        try:
            rel = path.relative_to(root)
            if any(part.lower() in PRUNE_DIRS for part in rel.parts[:-1]):
                continue
            if path.stat().st_size > BYTE_CEILING:
                continue
        except OSError:
            continue
        ext = path.suffix.lower()
        text = _slurp(path)
        if not _smells_like_code(text, ext):
            continue
        units, sigs = _outline(text, ext)
        if not units and ext != ".sol":
            units = [path.stem]
        if not units and not sigs:
            continue
        lsrc = text.lower()
        w = _heat(rel.as_posix().lower(), lsrc, len(sigs))
        if ext == ".sol" and "contract " not in lsrc and "library " not in lsrc:
            w *= 0.2
        elif ext != ".vy" and sigs and lsrc.count("{") < max(1, len(sigs) // 3):
            w *= 0.4
        parts = [p.lower() for p in rel.parts]
        short = path.stem.lower()
        if (short in ("test", "tests") or short.startswith("test_")
                or short.endswith(("_test", "_tests", ".t")) or "test" in parts
                or any(p in ("generated", "gen", "bindings", "sim") for p in parts)):
            w *= 0.1
        corpus.append({
            "abs": path, "rp": rel.as_posix(), "leaf": path.name, "src": text,
            "lsrc": lsrc, "short": path.stem, "ext": ext,
            "units": units, "sigs": sigs,
            "signames": {n for n, _ in sigs},
            "heat": w,
        })
    corpus.sort(key=lambda r: (-r["heat"], r["rp"]))
    return corpus[:FILE_CEILING]


def _import_context(rec, leaf_index):
    blocks = []
    seen = set()
    for imp in RX_IMPORT.findall(rec["src"]):
        tail = imp.rsplit("/", 1)[-1]
        for cand in (tail, tail.split(".")[0]):
            other = leaf_index.get(cand)
            if other and other["rp"] != rec["rp"] and other["rp"] not in seen:
                seen.add(other["rp"])
                blocks.append(f"// linked {other['rp']}\n{other['src'][:IMPORT_CTX_CHARS]}")
                break
        if len(blocks) >= 2:
            break
    return "\n\n".join(blocks)


def _hot_lines(text, limit=16):
    picked = []
    for idx, line in enumerate(text.splitlines(), 1):
        low = line.lower()
        if any(t in low for t in HOT_TOKENS):
            squashed = " ".join(line.split())
            if squashed:
                picked.append(f"{idx}: {squashed[:180]}")
        if len(picked) >= limit:
            break
    return picked


def _map_blob(corpus, limit):
    chunks = []
    total = 0
    rich_budget = int(limit * 0.82)
    for r in corpus:
        if total < rich_budget:
            sigs = [sig[:150] for _, sig in r["sigs"][:24]]
            chunk = json.dumps({
                "file": r["rp"],
                "units": r["units"][:8],
                "heat": round(float(r.get("heat", 0)), 1),
                "signatures": sigs,
                "flagged_lines": _hot_lines(r["src"], 16),
            }, separators=(",", ":"))
        else:
            chunk = json.dumps({
                "file": r["rp"],
                "units": r["units"][:4],
                "heat": round(float(r.get("heat", 0)), 1),
            }, separators=(",", ":"))
        if total + len(chunk) + 1 > limit:
            break
        chunks.append(chunk)
        total += len(chunk) + 1
    return "\n".join(chunks)


def _squeeze(text, limit):
    if len(text) <= limit:
        return text
    lines = text.splitlines()
    keep = set()
    for idx, line in enumerate(lines):
        low = line.lower()
        if RX_DECL_LINE.search(line) or any(t in low for t in HOT_TOKENS):
            for j in range(max(0, idx - 5), min(len(lines), idx + 18)):
                keep.add(j)
    rows = []
    last = -10
    size = 0
    for idx in sorted(keep):
        if idx > last + 1:
            gap = f"\n// [{idx - last - 1} lines skipped]\n"
            rows.append(gap)
            size += len(gap)
        entry = f"{idx + 1}: {lines[idx]}"
        rows.append(entry)
        size += len(entry) + 1
        last = idx
        if size >= limit:
            break
    squeezed = "\n".join(rows)
    if len(squeezed) < limit // 2:
        squeezed += "\n\n// leading source\n" + text[: max(0, limit - len(squeezed) - 20)]
    return squeezed[:limit]


def _match_file(file_value, path_index, leaf_index, hint_fn=""):
    if not file_value:
        return None
    fv = file_value.strip().strip("`").lstrip("./")
    r = path_index.get(fv)
    if r is not None:
        return r
    # Match only on a path-segment boundary: a bare "Pool.sol" must not land on
    # "StablePool.sol". Plain basenames still resolve through the leaf index.
    matches = [
        rec for rel, rec in path_index.items()
        if rel == fv or rel.endswith("/" + fv) or (len(fv) > 3 and fv.endswith("/" + rel))
    ]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        if hint_fn:
            for rec in matches:
                if hint_fn in rec["signames"]:
                    return rec
        return matches[0]
    leaf = fv.rsplit("/", 1)[-1]
    same_leaf = [rec for rec in path_index.values() if rec["leaf"] == leaf]
    if len(same_leaf) == 1:
        return same_leaf[0]
    if same_leaf and hint_fn:
        for rec in same_leaf:
            if hint_fn in rec["signames"]:
                return rec
    return leaf_index.get(leaf)


def _defined_in(text, fn):
    if not fn:
        return False
    pat = r"\b(?:" + "|".join(FN_KEYWORDS) + r")\s+" + re.escape(fn) + r"\b"
    return re.search(pat, text) is not None


def _locate_line(rec, fn):
    if not fn:
        return None
    for needle in (f"function {fn}", f"fn {fn}", f"fun {fn}",
                   f"def {fn}", f"func {fn}", fn):
        i = rec["src"].find(needle)
        if i >= 0:
            return rec["src"].count("\n", 0, i) + 1
    return None


def _shape(raw, path_index, leaf_index):
    file_value = str(raw.get("file") or raw.get("path") or raw.get("location") or "").strip()
    fn_raw = str(raw.get("function") or "").strip().strip("`")
    fn_raw = re.sub(r"\(.*$", "", fn_raw).strip()
    fn_raw = fn_raw.split(".")[-1].split("::")[-1].strip()
    rec = _match_file(file_value, path_index, leaf_index, fn_raw)
    if rec is None:
        return None
    severity = str(raw.get("severity") or "").strip().lower()
    if severity in {"medium", "med", "moderate"}:
        severity = "high"
    if severity not in {"high", "critical"}:
        return None
    try:
        conf = max(0.0, min(1.0, float(raw.get("confidence"))))
    except (TypeError, ValueError):
        conf = BASE_CONF
    # Only a high-severity entry that the model itself rated weakly is dropped;
    # criticals always stay. This trims noise without discarding real issues.
    if severity == "high" and conf < HIGH_CONF_FLOOR:
        return None
    fn = fn_raw
    if fn and fn not in rec["signames"] and not _defined_in(rec["src"], fn):
        fn = ""
    declared = rec["units"]
    unit = str(raw.get("contract") or raw.get("module") or "").strip().strip("`")
    if not unit or (declared and unit not in declared):
        unit = declared[0] if declared else rec["short"]
    mechanism = str(raw.get("mechanism") or "").strip()
    impact = str(raw.get("impact") or "").strip()
    description = str(raw.get("description") or "").strip()
    title = str(raw.get("title") or "").strip()

    loc = ".".join(x for x in (unit, fn) if x)
    if not title:
        title = f"{loc} - high/critical vulnerability" if loc else "High/critical vulnerability"
    elif loc and loc.lower() not in title.lower():
        title = f"{loc} - {title}"
    where = f"In `{rec['rp']}`"
    if unit:
        where += f", contract `{unit}`"
    if fn:
        where += f", function `{fn}()`"
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
    if len(body) < DESC_FLOOR and not title:
        return None
    tag = _label(title, mechanism, impact, description)
    return {
        "title": title[:220],
        "description": body[:2400],
        "severity": severity,
        "file": rec["rp"],
        "function": fn,
        "line": _locate_line(rec, fn),
        "type": LABEL_OUT.get(tag) or str(raw.get("type") or "logic"),
        "confidence": 0.9 if severity == "critical" else conf,
    }


ROLE_MSG = (
    "You are a senior security reviewer of on-chain programs written in Solidity, "
    "Vyper, Rust (Anchor/Solana and CosmWasm), Move, and Cairo. Across the files "
    "provided, surface every distinct HIGH or CRITICAL flaw that you can pin to a "
    "specific function - never just the worst single one, yet never fabricate "
    "filler entries. Overlooking a genuine high/critical is the expensive error; "
    "an unsupported guess merely burns a slot and weakens the report. Count as "
    "in scope: stolen or stranded funds, insolvency, unauthorized state writes, "
    "privilege escalation, unrecoverable denial-of-service or lockup, supply or "
    "mint corruption, oracle manipulation, reentrancy, signature or replay "
    "defects, and absent signer/owner/authority validation. Treat as out of "
    "scope: gas usage, style, absent events, plain centralization, and "
    "informational remarks. Think through everything privately; emit exactly one "
    "strict minified JSON object - no prose, no markdown, no code fences."
)

LANG_SHEET = (
    "Per-language failure catalog to sweep. "
    "Solidity/Vyper: reentrancy and ordering of external calls, absent or wrong "
    "access control, delegatecall plus upgrade/initialization mistakes, "
    "first-depositor share inflation and rounding, spot-versus-TWAP and stale or "
    "bendable oracles, permit and signature replay, risky token assumptions and "
    "fee-on-transfer, native-value bookkeeping, and irreversible denial-of-service. "
    "Rust Anchor/Solana: absent is_signer, absent account owner validation, absent "
    "has_one or constraint, unverified program-derived-address seeds, account close "
    "omissions, unchecked math, cross-program invocation into an unvetted program, "
    "and absent discriminator or type confusion. "
    "CosmWasm: info.sender left unchecked and an open migrate entrypoint. "
    "Move: absent signer or capability, a public entry wrapping a privileged "
    "routine, and confusion over resource ownership. "
    "Cairo/Starknet: get_caller_address checks missing, felt over/underflow, "
    "L1-to-L2 handler authentication, and storage-slot collision."
)

BREADTH_RULE = (
    "Push for completeness on GENUINE flaws: write up each distinct high or "
    "critical that you can anchor to a specific function and back with a working "
    "exploit path - typically 3 to 8 for a codebase this size. Never quit after "
    "the first one or two when more plainly exist, and record separate entries "
    "when one function carries unrelated defects; still, never stuff the list "
    "with speculative, minor, or repeated items - a bad entry drags the set "
    "down. For every entry, note briefly why the present modifiers or "
    "require-guards fail to block it."
)

PINPOINT_RULE = (
    "Anchoring rules: file must be one path reproduced exactly from a FILE "
    "header or the repository map, never invented. function must be a real name "
    "occurring in that file - reproduce it exactly, with no argument list and no "
    "contract prefix. contract must be one declared inside that file. Never "
    "fabricate files or functions. mechanism must stay concrete: precondition, "
    "then attacker step, then broken state."
)

OUTPUT_RULE = (
    "Emission rules: produce ONE bare minified JSON object with nothing outside "
    "it; double quotes only and no trailing commas; severity is exactly high or "
    "critical; every description runs two to four sentences; order entries "
    "strongest-first and keep each one fully self-contained; when space runs "
    "short, complete the current object and close the array and object cleanly "
    "instead of opening another."
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

_RULE_BLOCK = BREADTH_RULE + " " + LANG_SHEET + " " + PINPOINT_RULE + " " + OUTPUT_RULE

MAP_PREFACE = (
    "You are given a structured map of an on-chain codebase - per file its "
    "declared units (contracts or modules), function signatures, and flagged "
    "source lines. Perform BOTH tasks. (1) Reproduce exactly the 8 to 12 "
    "richest file paths into target_files. (2) Write up every high or critical "
    "already defensible from the signatures and flagged lines alone, keeping "
    "lower-confidence but precisely-anchored candidates too (give those a "
    "reduced confidence). "
    + _RULE_BLOCK + "\n"
    'Emit strict JSON only, shaped as {"target_files":["exact/path"],"findings":[...]} '
    "with every finding matching: " + SHAPE + "\nRepository map:\n"
)

CORE_PREFACE = (
    "Audit the on-chain source below in depth for HIGH or CRITICAL flaws. A "
    "defensible entry names the precise file and function, the exploitable state "
    "transition, and the material damage. "
    + _RULE_BLOCK + "\n"
    "Emit strict JSON only: " + SHAPE + "\n"
)

SWEEP_PREFACE = (
    "Second sweep with fresh eyes across a wider slice of the codebase. For "
    "every proposed flaw, say why the guards already present fail to stop it. "
    "Concentrate on cross-contract flows, bookkeeping and rounding theft, stale "
    "or bendable prices, authorization holes, reentrancy and callbacks, "
    "liquidation arithmetic, unsafe initialization and upgrades, and signature "
    "replay. "
    + _RULE_BLOCK + "\n"
    "Emit strict JSON only: " + SHAPE + "\n"
)

SECOND_PREFACE = (
    "Fully independent re-audit of the SAME central files below. Derive every "
    "conclusion again from the raw source - treat no earlier pass as right or "
    "complete. The aim is COMPLETENESS on genuine flaws: bring out each distinct "
    "high or critical, above all the kind a first read overlooks - "
    "cross-function and cross-file interplay, initialization and upgrade "
    "takeover, rounding and share inflation, stale or bendable prices, absent "
    "signer/owner/authority validation, and callback/reentrancy sequencing. "
    "Apply the same strict bar: a concrete exploit path, precise file and "
    "function, no speculation. "
    + _RULE_BLOCK + "\n"
    "Emit strict JSON only: " + SHAPE + "\n"
)


def _core_prompt(batch, leaf_index, per_cap, budget):
    parts = [CORE_PREFACE]
    remaining = budget - len(CORE_PREFACE)
    lead_ctx = _import_context(batch[0], leaf_index) if batch else ""
    for rec in batch:
        take = min(len(rec["src"]), per_cap, max(0, remaining))
        if take <= 0:
            break
        src = rec["src"]
        body = src if len(src) <= take else _squeeze(src, take)
        block = (
            f"\n\n### FILE: {rec['rp']} ###\n"
            f"Declared units: {', '.join(rec['units'][:8]) or rec['short']}\n{body}"
        )
        if len(src) > take:
            block += "\n/* trimmed */"
        parts.append(block)
        remaining -= len(block)
    if lead_ctx and remaining > 800:
        snippet = lead_ctx[:remaining - 200]
        parts.append(f"\n\n### LINKED IMPORTS (context only) ###\n{snippet}")
    return "".join(parts)


def _sweep_prompt(batch, leaf_index, budget, preface=SWEEP_PREFACE):
    parts = [preface]
    remaining = budget - len(preface)
    for rec in batch:
        body = _squeeze(rec["src"], SECOND_FILE_CHARS)
        block = (
            f"\n\n### FILE: {rec['rp']} ###\n"
            f"Declared units: {', '.join(rec['units'][:8]) or rec['short']}\n{body}\n"
        )
        if remaining <= 0:
            break
        if len(block) > remaining:
            block = block[:remaining] + "\n/* trimmed */"
        parts.append(block)
        remaining -= len(block)
    return "".join(parts)


def _run_map(inference_api, corpus, deadline):
    prompt = MAP_PREFACE + _map_blob(corpus, MAP_CHARS)
    return _map_reply_from(_call_proxy(inference_api, prompt, deadline, MAP_TOKENS))


def _run_core(inference_api, batch, leaf_index, deadline, per_cap, budget):
    prompt = _core_prompt(batch, leaf_index, per_cap, budget)
    return _findings_from(_call_proxy(inference_api, prompt, deadline, CORE_TOKENS))


def _run_sweep(inference_api, batch, leaf_index, deadline, budget, preface=SWEEP_PREFACE):
    prompt = _sweep_prompt(batch, leaf_index, budget, preface)
    return _findings_from(_call_proxy(inference_api, prompt, deadline, SECOND_TOKENS))


def _bubble_targets(corpus, picks):
    if not picks:
        return corpus
    front = []
    taken = set()
    for tg in picks:
        wanted = tg.strip().lstrip("./")
        if not wanted:
            continue
        leaf = wanted.rsplit("/", 1)[-1]
        for r in corpus:
            if r["rp"] in taken:
                continue
            rp = r["rp"]
            if (wanted == rp or rp.endswith(wanted)
                    or wanted.endswith(rp) or r["leaf"] == leaf):
                front.append(r)
                taken.add(rp)
                break
    for r in corpus:
        if r["rp"] not in taken:
            front.append(r)
    return front


def agent_main(project_dir=None, inference_api=None):
    report = []
    deadline = time.monotonic() + WALL_BUDGET
    try:
        root = _locate_root(project_dir)
        if root is None:
            return {"vulnerabilities": report}
        corpus = _harvest(root)
        if not corpus:
            return {"vulnerabilities": report}
        leaf_index = {}
        for r in corpus:
            leaf_index.setdefault(r["leaf"], r)
        path_index = {r["rp"]: r for r in corpus}

        pool = []
        queue = corpus
        if deadline - time.monotonic() >= FULL_PASS_RESERVE:
            try:
                picks, rows = _run_map(inference_api, corpus, deadline)
                pool.extend(rows)
                queue = _bubble_targets(corpus, picks)
            except Exception:
                pass
        if deadline - time.monotonic() >= FULL_PASS_RESERVE:
            try:
                pool.extend(_run_core(inference_api, queue[:CORE_FILES], leaf_index,
                                      deadline, CORE_FILE_CHARS, CORE_CALL_CHARS))
            except Exception:
                pass
        # Closing sweep: revisit the SAME central files (plus a modest tail)
        # under an independent lens and merge the union. Two careful reads of
        # the core surface more of its genuine flaws than a single read.
        if deadline - time.monotonic() >= FINAL_PASS_RESERVE:
            revisit = queue[:SECOND_FILES]
            if revisit:
                try:
                    pool.extend(_run_sweep(inference_api, revisit, leaf_index,
                                           deadline, SECOND_CALL_CHARS, SECOND_PREFACE))
                except Exception:
                    pass

        try:
            pool.extend(_pattern_scan(corpus))
        except Exception:
            pass

        for x in pool:
            row = _shape(x, path_index, leaf_index)
            if row is not None:
                report.append(row)
        if not report:
            for x in _last_resort(corpus):
                row = _shape(x, path_index, leaf_index)
                if row is not None:
                    report.append(row)
        report = _prune(report)
    except Exception:
        return {"vulnerabilities": report}
    return {"vulnerabilities": report}


if __name__ == "__main__":
    import sys
    print(json.dumps(agent_main(sys.argv[1] if len(sys.argv) > 1 else None), indent=2))
