"""SN60 Bitsec miner — static-first free-tier hunter.

Designed for zero-budget OpenRouter free models: deterministic Solidity/Rust/
Move/Cairo scanners do most of the work; at most one short free-model call
supplements when rate limits allow. Stdlib only; talks only to INFERENCE_API.
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


SUFFIXES = (".sol", ".vy", ".rs", ".move", ".cairo")
SKIP = frozenset({
    ".git", ".github", "node_modules", "vendor", "vendors", "lib", "libs",
    "libraries", "library", "out", "artifacts", "cache", "coverage", "target",
    "dist", "build", "deps", "test", "tests", "mock", "mocks", "example",
    "examples", "script", "scripts", "broadcast", "docs", "fixtures", "fixture",
    "interfaces", "interface", "generated", "bindings", "node",
})

RX_SOL_T = re.compile(
    r"\b(?:abstract\s+contract|contract|library|interface)\s+([A-Za-z_][A-Za-z0-9_]*)"
)
RX_SOL_F = re.compile(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
RX_SOL_S = re.compile(r"\b(constructor|receive|fallback)\b\s*\(")
RX_RS_F = re.compile(
    r"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)"
)
RX_RS_M = re.compile(r"(?m)^\s*(?:pub\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{")
RX_MV_F = re.compile(
    r"(?m)^\s*(?:public\s*(?:\([^)]*\))?\s+)?(?:entry\s+)?(?:native\s+)?fun\s+([A-Za-z_][A-Za-z0-9_]*)"
)
RX_MV_M = re.compile(r"(?m)^\s*module\s+(?:[A-Za-z_0-9]+::)?([A-Za-z_][A-Za-z0-9_]*)")
RX_CA_F = re.compile(r"(?m)^\s*(?:pub\s+)?(?:fn|func)\s+([A-Za-z_][A-Za-z0-9_]*)")
RX_CA_M = re.compile(r"(?m)^\s*(?:pub\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{")
RX_VY_F = re.compile(r"(?m)^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")

NAME_HINTS = (
    "vault", "pool", "router", "manager", "controller", "strategy", "market",
    "lend", "borrow", "oracle", "price", "stak", "reward", "treasury", "bridge",
    "factory", "proxy", "govern", "token", "escrow", "auction", "liquidat",
    "swap", "collateral", "mint", "burn", "farm", "perp", "margin", "settle",
    "rebalance", "vesting", "launch",
)
CODE_HINTS = (
    "delegatecall", ".call{", "selfdestruct", "tx.origin", "assembly",
    "ecrecover", "permit", "initialize", "upgradeto", "onlyowner", "withdraw",
    "redeem", "deposit", "borrow", "repay", "liquidat", "flash", "unchecked",
    "transferfrom", "approve", "mint(", "burn(", "claim", "createpair",
    "msg.value", "nonces", "slippage", "minamount", "deadline",
)

MAX_FILES = 90
PER_FILE_MAX = 80_000
FOCUS_N = 6
FOCUS_CHARS = 7_000
FOCUS_BUDGET = 28_000
EMIT_N = 40
MIN_DESC = 80

# Free OpenRouter model — $0. Paid override via env if funded later.
MODEL = os.environ.get("KATA_MINER_MODEL", "google/gemma-4-31b-it:free")
TOK_FOCUS = 2_500
WALL = 780.0
HTTP_TO = 90.0
TAIL = 8.0
FLOOR = 20.0
RETRIES = 2

_RETRY = frozenset({408, 409, 425, 429, 500, 502, 504, 520, 522, 524, 529})

PERSONA = (
    "Smart-contract auditor. List HIGH/CRITICAL bugs only as bare minified JSON. "
    "Prefer fund theft, auth bypass, DoS, mint bugs, oracle, reentrancy, slippage."
)
ASK = (
    "Audit the sources. Return ONLY: "
    '{"findings":[{"title":"C.f - bug","file":"path","contract":"C","function":"f",'
    '"severity":"high","description":"precondition -> attack -> impact (2 sentences)"}]}'
    "\nSources:\n"
)


def _item(title, severity, file_path, description, function="", contract="", confidence=0.6):
    item = {}
    item["title"] = str(title)[:180]
    item["severity"] = severity
    item["file"] = file_path
    item["description"] = str(description)[:1400]
    item["function"] = function or ""
    item["contract"] = contract or ""
    item["confidence"] = float(confidence)
    return item


def _raw(title, rel, contract, function, severity, description, confidence=0.7):
    hit = {}
    hit["title"] = title
    hit["file"] = rel
    hit["contract"] = contract
    hit["function"] = function
    hit["severity"] = severity
    hit["description"] = description
    hit["confidence"] = confidence
    return hit


def _root(project_dir=None):
    tries = []
    if project_dir:
        tries.append(project_dir)
    for env in ("PROJECT_DIR", "PROJECT_PATH", "PROJECT_ROOT", "PROJECT_CODE"):
        v = os.environ.get(env)
        if v:
            tries.append(v)
    tries.extend(("/app/project_code", "/app/project", "/app", "/project", "/code", "."))
    for raw in tries:
        try:
            path = Path(raw).expanduser().resolve()
        except (OSError, RuntimeError):
            continue
        if not path.is_dir():
            continue
        try:
            for p in path.rglob("*"):
                if p.is_file() and p.suffix.lower() in SUFFIXES:
                    return path
        except OSError:
            continue
    return None


def _read(path):
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _symbols(text, suf):
    types, fns = [], []
    if suf == ".sol":
        types = RX_SOL_T.findall(text)
        fns = RX_SOL_F.findall(text) + RX_SOL_S.findall(text)
    elif suf == ".vy":
        fns = RX_VY_F.findall(text)
    elif suf == ".rs":
        types = RX_RS_M.findall(text)
        fns = RX_RS_F.findall(text)
    elif suf == ".move":
        types = RX_MV_M.findall(text)
        fns = RX_MV_F.findall(text)
    elif suf == ".cairo":
        types = RX_CA_M.findall(text)
        fns = RX_CA_F.findall(text)
    return types, fns


def _rank(rel, text, nfn):
    low = (rel + "\n" + text[:8000]).lower()
    score = nfn * 0.4
    for h in NAME_HINTS:
        if h in low:
            score += 2.0
    for h in CODE_HINTS:
        if h in low:
            score += 1.4
    return score


def _catalog(root):
    rows = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        suf = path.suffix.lower()
        if suf not in SUFFIXES:
            continue
        try:
            rel_path = path.relative_to(root)
            if any(p.lower() in SKIP for p in rel_path.parts[:-1]):
                continue
            size = path.stat().st_size
        except OSError:
            continue
        if size <= 0 or size > PER_FILE_MAX:
            continue
        text = _read(path)
        if len(text) < 40:
            continue
        low = text.lower()
        if suf == ".sol" and "contract " not in low and "library " not in low:
            if "function " not in low:
                continue
        rel = rel_path.as_posix()
        types, fns = _symbols(text, suf)
        if not types and not fns:
            continue
        score = _rank(rel, text, len(fns))
        if suf == ".sol" and "contract " not in low and "library " not in low:
            score *= 0.25
        stem = path.stem.lower()
        if stem.startswith("test") or stem.endswith("test"):
            score *= 0.1
        rows.append({
            "rel": rel,
            "base": path.name,
            "stem": path.stem,
            "suf": suf,
            "text": text,
            "types": types,
            "fns": fns,
            "score": score,
        })
    rows.sort(key=lambda r: (-r["score"], r["rel"]))
    return rows[:MAX_FILES]


def _brace(text, start):
    open_at = text.find("{", start)
    if open_at < 0:
        return text[start:start + 800]
    depth = 0
    for i in range(open_at, min(len(text), open_at + 10000)):
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return text[start:start + 2000]


def _sol_fns(text):
    marks = []
    for m in RX_SOL_F.finditer(text):
        marks.append((m.start(), m.group(1), " ".join(m.group(0).split())))
    for m in RX_SOL_S.finditer(text):
        marks.append((m.start(), m.group(1), m.group(1)))
    marks.sort(key=lambda x: x[0])
    out = []
    for i, (pos, name, sig) in enumerate(marks):
        end = marks[i + 1][0] if i + 1 < len(marks) else len(text)
        out.append({"name": name, "sig": sig, "body": text[pos:end], "pos": pos})
    return out


_GUARDS = (
    "onlyowner", "onlyrole", "onlyadmin", "onlygovernance", "onlykeeper",
    "requiresauth", "authorized", "hasrole", "restricted", "_checkowner",
)


def _static_scan(rows):
    """Broad deterministic scanners — primary signal on free tier."""
    out = []
    for rec in rows:
        suf = rec["suf"]
        text = rec["text"]
        low = text.lower()
        contract = rec["types"][0] if rec["types"] else rec["stem"]
        rel = rec["rel"]

        if suf == ".sol":
            # msg.value mint while amount is the real deposit size
            for m in re.finditer(r"function\s+([A-Za-z_]\w*)\s*\(([^)]*)\)([^{]*)\{", text):
                name, args, mods = m.group(1), m.group(2), m.group(3)
                body = _brace(text, m.start())
                blow = body.lower()
                al = args.lower()
                ml = mods.lower()
                if "amount" in al and re.search(r"_mint\s*\(\s*[^,]+,\s*msg\.value\s*\)", body):
                    out.append(_raw(
                        contract + "." + name + " - mints with msg.value not amount",
                        rel, contract, name, "high",
                        "Function " + name + " accepts an amount and may pull ERC20 for that "
                        "amount, but mints using msg.value. On ERC20 paths msg.value is 0 so "
                        "depositors lose tokens and receive a zero mint.",
                        0.85,
                    ))
                if name.lower() in ("initialize", "init") and ("external" in ml or "public" in ml):
                    if not any(g in blow for g in (
                        "initializer", "onlyowner", "onlyrole", "_disableinitializers", "initialized"
                    )):
                        if any(x in blow for x in ("_mint(", "owner", "name", "symbol")):
                            out.append(_raw(
                                contract + "." + name + " - unprotected initializer",
                                rel, contract, name, "critical",
                                "Initializer is externally callable without a one-time guard. "
                                "An attacker can call first, seize ownership, or mint supply.",
                                0.8,
                            ))
                # missing slippage / minOut on swap-like paths
                if any(k in name.lower() for k in ("swap", "sell", "buy", "redeem", "remove")):
                    if ("external" in ml or "public" in ml) and any(
                        x in blow for x in ("swap", "exactinput", "exactoutput", "getamount")
                    ):
                        if not any(x in blow for x in (
                            "amountoutmin", "minamount", "slippage", "deadline", "amount_out_min"
                        )):
                            out.append(_raw(
                                contract + "." + name + " - missing slippage protection",
                                rel, contract, name, "high",
                                "External swap/sell path lacks min-out / slippage / deadline "
                                "checks, so a sandwich can steal value from the caller.",
                                0.62,
                            ))

            if "createpair" in low and ("clone(" in low or "create2" in low):
                if "getpair" not in low:
                    for fn in _sol_fns(text):
                        blow = fn["body"].lower()
                        if "createpair" in blow or ("clone(" in blow and "pair" in blow):
                            out.append(_raw(
                                contract + "." + fn["name"] + " - createPair frontrun DoS",
                                rel, contract, fn["name"], "high",
                                "CREATE/clone address is predictable and createPair is invoked "
                                "without handling an existing pair, so an attacker pre-creates "
                                "the pair and permanently DoSes launches.",
                                0.82,
                            ))
                            break

            if "tx.origin" in low:
                for fn in _sol_fns(text):
                    if "tx.origin" in fn["body"].lower():
                        out.append(_raw(
                            contract + "." + fn["name"] + " - tx.origin authorization",
                            rel, contract, fn["name"], "high",
                            "Authorization uses tx.origin, which a malicious intermediary "
                            "contract can phish from a privileged EOA to drain or reconfigure.",
                            0.75,
                        ))
                        break

            for fn in _sol_fns(text):
                name = fn["name"]
                sig = fn["sig"].lower()
                blow = fn["body"].lower()
                both = sig + " " + blow
                ext = "external" in sig or "public" in sig

                # permissionless value movers
                if ext and name.lower() in (
                    "rebalance", "settle", "liquidate", "liquidateliquidator",
                    "executetransaction", "execute", "skim", "harvest",
                ):
                    if "only" not in sig and not any(g in both for g in _GUARDS):
                        if any(x in blow for x in ("flash", "swap", "transfer", ".call{", "borrow")):
                            out.append(_raw(
                                contract + "." + name + " - permissionless value path",
                                rel, contract, name, "high",
                                "Externally callable " + name + " moves value via swap/flash/"
                                "transfer without a clear owner/role gate on parameters, so any "
                                "caller can push accounting off the intended peg or settlement.",
                                0.7,
                            ))

                # CEI / reentrancy: external call then state write
                if ext and (".call{" in blow or "transfer(" in blow or "send(" in blow):
                    call_at = max(
                        blow.find(".call{"), blow.find("transfer("), blow.find("send(")
                    )
                    after = blow[call_at:] if call_at >= 0 else ""
                    if call_at >= 0 and "nonreentrant" not in sig:
                        if re.search(r"\b(balances?|shares?|total|debt|collateral)\w*\s*=", after):
                            out.append(_raw(
                                contract + "." + name + " - state update after external call",
                                rel, contract, name, "high",
                                "External call occurs before subsequent accounting writes and "
                                "no nonReentrant guard is present, enabling reentrancy to "
                                "corrupt balances or double-withdraw.",
                                0.68,
                            ))

                # unlimited approve
                if "approve(" in blow and ("type(uint256).max" in blow or "uint256(-1)" in blow or "2**256" in blow):
                    out.append(_raw(
                        contract + "." + name + " - infinite token approval",
                        rel, contract, name, "high",
                        "Function sets an unlimited ERC20 allowance. If the spender is "
                        "compromised or malicious, it can drain the full token balance.",
                        0.55,
                    ))

                # setX without access control writing auth maps
                if ext and re.match(r"^(set|update|add|remove|register|enable|disable)", name, re.I):
                    if "only" not in sig and not any(g in both for g in _GUARDS):
                        if re.search(r"(operator|approv|allowed|authoriz|whitelist|trusted|minter|admin)s?\s*\[", blow):
                            if "msg.sender" not in blow or "require(" not in blow:
                                out.append(_raw(
                                    contract + "." + name + " - unauthenticated config write",
                                    rel, contract, name, "critical",
                                    "External config function writes an authorization/operator "
                                    "mapping without an owner/role check, so any caller can "
                                    "grant itself privileged power.",
                                    0.72,
                                ))

                # first-depositor / share inflation hints
                if "totalsupply" in blow and ("deposit" in name.lower() or "mint" in name.lower()):
                    if "totalsupply() == 0" in blow or "totalsupply()==0" in blow:
                        if "dead" not in blow and "virtual" not in blow and "offset" not in blow:
                            out.append(_raw(
                                contract + "." + name + " - first depositor share risk",
                                rel, contract, name, "high",
                                "Deposit path special-cases zero totalSupply without a dead-share "
                                "or virtual offset, enabling first-depositor share inflation "
                                "against the next depositor.",
                                0.6,
                            ))

        elif suf == ".rs":
            # Anchor-ish missing signer checks
            if "pub fn" in text or "fn " in text:
                for m in RX_RS_F.finditer(text):
                    name = m.group(1)
                    # crude window
                    body = text[m.start(): m.start() + 1200].lower()
                    if "ctx.accounts" in body or "accountinfo" in body:
                        if "is_signer" not in body and "signer" not in body and name not in ("new", "init"):
                            if any(x in body for x in ("lamports", "transfer", "invoke", "token")):
                                out.append(_raw(
                                    contract + "." + name + " - possible missing signer check",
                                    rel, contract, name, "high",
                                    "Account-touching Rust entry appears to move value without an "
                                    "obvious is_signer / Signer constraint in the nearby body.",
                                    0.5,
                                ))

        elif suf == ".move":
            for m in RX_MV_F.finditer(text):
                name = m.group(1)
                window = text[m.start(): m.start() + 800].lower()
                if "public entry" in window or "entry fun" in text[max(0, m.start()-40):m.start()+20].lower():
                    if "signer" not in window and any(x in window for x in ("withdraw", "transfer", "mint", "borrow")):
                        out.append(_raw(
                            contract + "." + name + " - entry without signer gate",
                            rel, contract, name, "high",
                            "Public entry appears to touch funds without a clear signer "
                            "capability check in the prologue.",
                            0.55,
                        ))

        if len(out) >= 28:
            break
    # dedupe titles
    seen = set()
    uniq = []
    for h in out:
        k = (h["file"], h["function"], h["title"][:40])
        if k in seen:
            continue
        seen.add(k)
        uniq.append(h)
    return uniq[:28]


def _strip(text):
    t = text.strip()
    if t.startswith("```"):
        t = re.sub(r"^```[a-zA-Z]*\s*", "", t)
        t = re.sub(r"\s*```$", "", t)
    return t


def _objects(text):
    found = []
    depth = 0
    start = -1
    in_str = esc = False
    for i, ch in enumerate(text):
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
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            if depth:
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


def _findings(text):
    if not isinstance(text, str) or not text.strip():
        return []
    t = _strip(text)
    try:
        obj = json.loads(t)
        if isinstance(obj, dict):
            items = obj.get("findings") or obj.get("vulnerabilities")
            if isinstance(items, list):
                return [x for x in items if isinstance(x, dict)]
    except json.JSONDecodeError:
        pass
    m = re.search(r'"(?:findings|vulnerabilities)"\s*:\s*\[', t)
    tail = t[m.end():] if m else t
    keys = ("title", "file", "severity", "description", "function", "contract")
    return [o for o in _objects(tail) if any(k in o for k in keys)]


def _message(payload):
    try:
        choice = (payload.get("choices") or [{}])[0]
        msg = choice.get("message") or {}
        content = msg.get("content")
        if isinstance(content, list):
            content = "".join(p.get("text", "") for p in content if isinstance(p, dict))
        if isinstance(content, str) and content.strip():
            return content
        for key in ("reasoning", "reasoning_content"):
            val = msg.get(key)
            if isinstance(val, str) and val.strip():
                return val
    except Exception:
        pass
    return ""


def _call(endpoint, prompt, deadline, max_tokens):
    if not endpoint:
        raise RuntimeError("no endpoint")
    headers = {
        "Content-Type": "application/json",
        "x-inference-api-key": os.environ.get("INFERENCE_API_KEY", ""),
    }
    body = json.dumps({
        "model": MODEL,
        "messages": [
            {"role": "system", "content": PERSONA},
            {"role": "user", "content": prompt},
        ],
        "max_tokens": max_tokens,
    }).encode("utf-8")
    err = None
    for attempt in range(RETRIES):
        remain = deadline - time.monotonic() - TAIL
        timeout = min(HTTP_TO, float(int(remain)))
        if timeout < FLOOR:
            raise RuntimeError("budget")
        try:
            req = urllib.request.Request(
                endpoint + "/inference", data=body, method="POST", headers=headers
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return _message(json.loads(resp.read().decode("utf-8", "replace")))
        except urllib.error.HTTPError as exc:
            # Free-tier rate limits: do not burn the wall clock.
            if exc.code == 429:
                time.sleep(1.5 + attempt)
            if exc.code in {401, 402, 403}:
                raise RuntimeError("http " + str(exc.code)) from exc
            if exc.code not in _RETRY and exc.code != 429:
                raise RuntimeError("http " + str(exc.code)) from exc
            err = exc
        except (socket.timeout, TimeoutError) as exc:
            raise RuntimeError("timeout") from exc
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, (socket.timeout, TimeoutError)):
                raise RuntimeError("timeout") from exc
            err = exc
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            err = exc
        if attempt + 1 >= RETRIES:
            break
        if deadline - time.monotonic() < FLOOR + 30:
            break
        time.sleep(1.0 + attempt)
    raise RuntimeError(str(err) if err else "request failed")


def _focus_prompt(batch):
    parts = [ASK]
    left = FOCUS_BUDGET - len(ASK)
    for rec in batch:
        take = min(len(rec["text"]), FOCUS_CHARS, max(0, left))
        if take <= 0:
            break
        body = rec["text"][:take]
        block = "\n\n===== FILE: " + rec["rel"] + " =====\n" + body
        parts.append(block)
        left -= len(block)
    return "".join(parts)


def _resolve(file_value, by_rel, by_base, fn=""):
    if not file_value:
        return None
    cleaned = str(file_value).strip().lstrip("./").replace("\\", "/")
    if cleaned in by_rel:
        return by_rel[cleaned]
    base = cleaned.rsplit("/", 1)[-1]
    if base in by_base:
        return by_base[base]
    low = cleaned.lower()
    for rel, rec in by_rel.items():
        if rel.lower().endswith(low) or low.endswith(rel.lower()):
            return rec
    if fn:
        tip = fn.lower()
        for rec in by_rel.values():
            if tip in [x.lower() for x in rec["fns"]]:
                return rec
    return None


def _normalize(raw, by_rel, by_base):
    if not isinstance(raw, dict):
        return None
    title = str(raw.get("title") or "").strip()
    desc = str(raw.get("description") or raw.get("mechanism") or "").strip()
    if not title and not desc:
        return None
    fn = str(raw.get("function") or "").strip()
    fn = re.sub(r"\(.*$", "", fn).split(".")[-1].strip()
    contract = str(raw.get("contract") or "").strip()
    sev = str(raw.get("severity") or "high").lower()
    if sev.startswith("crit"):
        sev = "critical"
    else:
        sev = "high"
    rec = _resolve(raw.get("file"), by_rel, by_base, fn)
    if rec is None and contract:
        for r in by_rel.values():
            if contract in r["types"] or contract == r["stem"]:
                rec = r
                break
    if rec is None:
        if by_rel:
            rec = next(iter(by_rel.values()))
        else:
            return None
    if not title:
        title = (contract or rec["stem"]) + (("." + fn) if fn else "") + " - issue"
    if len(desc) < MIN_DESC:
        desc = (
            (desc + " ").strip()
            + " Issue in " + rec["rel"]
            + " around " + (fn or "the unit")
            + "; existing guards fail to stop fund loss or privilege escalation."
        )
    try:
        conf = float(raw.get("confidence") or 0.55)
    except (TypeError, ValueError):
        conf = 0.55
    return _item(title, sev, rec["rel"], desc, fn, contract or (rec["types"][0] if rec["types"] else rec["stem"]), conf)


def _klass(item):
    blob = (item.get("title", "") + " " + item.get("description", "")).lower()
    pairs = (
        ("reentrancy", ("reentran", "callback", "reenter")),
        ("access", ("access", "authoriz", "onlyowner", "signer", "permission", "unprotected")),
        ("oracle", ("oracle", "price", "stale", "twap", "slot0")),
        ("sig", ("signature", "replay", "permit", "ecrecover", "nonce")),
        ("account", ("share", "rounding", "inflation", "reserve", "totalsupply", "first deposit")),
        ("init", ("initiali", "upgrade", "delegatecall", "proxy")),
        ("dos", ("dos", "frontrun", "createpair", "permanent")),
        ("slip", ("slippage", "minamount", "sandwich")),
        ("math", ("overflow", "underflow", "unchecked", "msg.value")),
    )
    for name, needles in pairs:
        if any(n in blob for n in needles):
            return name
    return "other"


def _merge(items):
    groups = {}
    for item in items:
        key = (
            item.get("file", "").lower(),
            item.get("function", "").lower(),
            _klass(item),
        )
        cur = groups.get(key)
        if cur is None:
            d = dict(item)
            d["votes"] = 1
            groups[key] = d
            continue
        cur["votes"] += 1
        if item["severity"] == "critical":
            cur["severity"] = "critical"
        if float(item.get("confidence", 0)) > float(cur.get("confidence", 0)):
            cur["confidence"] = item["confidence"]
            cur["title"] = item["title"]
            cur["description"] = item["description"]
        elif len(item.get("description", "")) > len(cur.get("description", "")):
            cur["description"] = item["description"]
            cur["title"] = item["title"]
    merged = list(groups.values())
    merged.sort(
        key=lambda e: (
            float(e.get("confidence", 0)),
            int(e.get("votes", 1)),
            e["severity"] == "critical",
            len(e.get("description", "")),
        ),
        reverse=True,
    )
    out = []
    for e in merged[:EMIT_N]:
        out.append(_item(
            e["title"], e["severity"], e["file"], e["description"],
            e.get("function") or "", e.get("contract") or "", e.get("confidence") or 0.55,
        ))
        out[-1].pop("confidence", None)
    return out


def agent_main(project_dir=None, inference_api=None):
    report = []
    deadline = time.monotonic() + WALL
    try:
        root = _root(project_dir)
        if root is None:
            return {"vulnerabilities": report}
        rows = _catalog(root)
        if not rows:
            return {"vulnerabilities": report}
        by_rel = {r["rel"]: r for r in rows}
        by_base = {}
        for r in rows:
            by_base.setdefault(r["base"], r)

        raw = []
        # Static-first: always run, even if inference is dead / rate-limited.
        try:
            raw.extend(_static_scan(rows))
        except Exception:
            pass

        endpoint = (inference_api or os.environ.get("INFERENCE_API") or "").rstrip("/")
        # Single lean free-model pass only if budget remains and static found little.
        if endpoint and deadline - time.monotonic() > FLOOR + 50:
            if len(raw) < 4:
                try:
                    batch = rows[:FOCUS_N]
                    text = _call(endpoint, _focus_prompt(batch), deadline, TOK_FOCUS)
                    raw.extend(_findings(text))
                except Exception:
                    pass

        cleaned = []
        for item in raw:
            norm = _normalize(item, by_rel, by_base)
            if norm is not None:
                cleaned.append(norm)
        report = _merge(cleaned)
    except Exception:
        return {"vulnerabilities": report}
    return {"vulnerabilities": report}


if __name__ == "__main__":
    import sys
    print(json.dumps(agent_main(sys.argv[1] if len(sys.argv) > 1 else None), indent=2))
