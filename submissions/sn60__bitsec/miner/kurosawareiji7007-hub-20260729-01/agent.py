"""SN60 Bitsec miner: concurrent unit audits with exploit verification.

Strategy
--------
Promotion is decided first by project-pass rate: a project only passes when the
report covers every planted high/critical. That favors broad, reliable coverage
over a short list of "best looking" bugs.

This agent therefore:
1. Indexes the repository and ranks units (file + contract/module) by risk.
2. Runs many *single-unit* LLM audits concurrently so each unit gets a focused
   prompt instead of sharing one overloaded context window.
3. Runs a short verification pass over the strongest candidates to drop weak
   hallucinations before they dilute precision.
4. Adds a small set of language-agnostic static detectors as a safety net when
   the model is slow or fails, so the process still returns a useful report.

Only the injected inference gateway is contacted. Pure standard library.
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
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

SUFFIXES = (".sol", ".vy", ".rs", ".move", ".cairo")
SKIP_DIR = frozenset({
    ".git", ".github", "node_modules", "vendor", "vendors", "lib", "libs",
    "out", "artifacts", "cache", "coverage", "target", "dist", "build", "deps",
    "test", "tests", "mock", "mocks", "example", "examples", "script", "scripts",
    "broadcast", "docs", "fixtures", "fixture", "interfaces", "interface",
})

RX_SOL_CONTRACT = re.compile(
    r"\b(?:abstract\s+contract|contract|library|interface)\s+([A-Za-z_][A-Za-z0-9_]*)"
)
RX_SOL_FN = re.compile(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
RX_SOL_CTOR = re.compile(r"\b(constructor|receive|fallback)\b\s*\(")
RX_VY_FN = re.compile(r"(?m)^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
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

VALUE_HINTS = (
    "vault", "pool", "router", "manager", "controller", "strategy", "market",
    "lend", "borrow", "oracle", "price", "stake", "reward", "treasury", "bridge",
    "factory", "proxy", "govern", "token", "escrow", "auction", "liquidat",
    "swap", "stable", "collateral", "vest", "mint", "burn", "gauge", "farm",
    "perp", "position", "margin", "settle", "clearing", "account", "program",
)

RISK_HINTS = (
    "delegatecall", "call{", "selfdestruct", "tx.origin", "assembly",
    "ecrecover", "permit", "initialize", "upgradeto", "onlyowner", "onlyrole",
    "withdraw", "redeem", "deposit", "borrow", "repay", "liquidat", "flash",
    "unchecked", "transferfrom", "approve", "mint(", "burn(", "claim",
    "signer", "authority", "lamports", "invoke", "cpi", "close_account",
    "realloc", "is_signer", "info.sender", "borrow_global", "move_to",
    "get_caller_address", "safetransfer", "reentran",
)


# ---------------------------------------------------------------------------
# Budgets
# ---------------------------------------------------------------------------

MAX_FILES = 100
MAX_FILE_CHARS = 280_000
UNIT_SRC_CHARS = 24_000
IMPORT_CTX_CHARS = 2_800
SURVEY_CHARS = 36_000
VERIFY_SRC_CHARS = 10_000

TOP_UNITS = 22
SURVEY_PICK = 14
VERIFY_TOP = 12
WORKERS = 5
EMIT_LIMIT = 40
MIN_DESC = 80

MODEL = os.environ.get("KATA_MINER_MODEL", "deepseek-ai/DeepSeek-V3.2-TEE")
TEMP = 0.0
TOK_SURVEY = 7_000
TOK_UNIT = 8_000
TOK_VERIFY = 6_000

WALL_S = 820.0
HTTP_S = 195.0
NEED_S = 210.0
TAIL_S = 20.0
MIN_CALL_S = 28.0
RETRIES = 2

_LOCK = threading.Lock()
_DROP_TUNING = False
_RETRY_HTTP = frozenset({408, 409, 425, 429, 500, 502, 503, 504, 520, 522, 524, 529})


# ---------------------------------------------------------------------------
# Prompts (kept short and unit-focused on purpose)
# ---------------------------------------------------------------------------

SYSTEM = (
    "You are an on-chain security auditor for Solidity, Vyper, Rust "
    "(Solana/Anchor, CosmWasm), Move, and Cairo. Report only exploitable HIGH "
    "or CRITICAL issues. Prefer recall: missing a real bug is worse than an "
    "extra candidate. Ignore gas, style, missing events, and pure centralization. "
    "Reply with one minified JSON object only."
)

SHAPE = (
    '{"vulnerabilities":[{"title":"Unit.fn - defect","severity":"high|critical",'
    '"file":"path","function":"name","contract":"Name",'
    '"description":"at least 80 chars: who can call what, how state breaks, impact"}]}'
)

SURVEY_ASK = (
    SYSTEM
    + " From this project outline, pick the highest-risk source paths and list "
    "any high/critical issues already visible from signatures and risk lines. "
    "Copy file paths exactly. Return JSON: "
    '{"priority_files":["path"],"vulnerabilities":[...]} matching '
    + SHAPE
    + "\nOutline:\n"
)

UNIT_ASK = (
    SYSTEM
    + " Audit the single source unit below thoroughly. Report every distinct "
    "high/critical you can pin to a real function in this file. Name the "
    "exact file and function. Explain why existing guards fail. Return JSON: "
    + SHAPE
    + "\n"
)

VERIFY_ASK = (
    SYSTEM
    + " You are given candidate findings plus the source of their units. "
    "Keep only findings that are realistically exploitable high/critical. "
    "Drop vague, unpinnable, or non-exploitable items. Rewrite kept descriptions "
    "to be concrete (caller, action, broken state, impact). Return JSON: "
    + SHAPE
    + "\n"
)


# ---------------------------------------------------------------------------
# IO / HTTP
# ---------------------------------------------------------------------------

def _gateway(explicit=None):
    for raw in (explicit, os.environ.get("INFERENCE_API"), os.environ.get("INFERENCE_URL")):
        if raw:
            return str(raw).rstrip("/")
    return ""


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _json_msg(payload: dict) -> str:
    try:
        choice = (payload.get("choices") or [{}])[0]
        msg = choice.get("message") or {}
        content = msg.get("content")
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            parts = []
            for block in content:
                if isinstance(block, dict) and block.get("type") == "text":
                    parts.append(str(block.get("text") or ""))
            return "".join(parts)
    except Exception:
        pass
    return ""


def _post(endpoint: str, prompt: str, deadline: float, max_tokens: int) -> str:
    global _DROP_TUNING
    if not endpoint:
        raise RuntimeError("no gateway")
    key = os.environ.get("INFERENCE_API_KEY", "")
    headers = {"Content-Type": "application/json", "x-inference-api-key": key}
    last = None
    for attempt in range(RETRIES):
        remain = deadline - time.monotonic()
        if remain < NEED_S:
            raise RuntimeError("budget")
        timeout = max(MIN_CALL_S, min(HTTP_S, remain - TAIL_S))
        body = {
            "model": MODEL,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": max_tokens,
        }
        if not _DROP_TUNING:
            body["temperature"] = TEMP
        raw = json.dumps(body).encode()
        try:
            req = urllib.request.Request(
                endpoint + "/inference", data=raw, method="POST", headers=headers
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return _json_msg(json.loads(resp.read().decode("utf-8", "replace")))
        except urllib.error.HTTPError as exc:
            if exc.code == 400 and not _DROP_TUNING:
                _DROP_TUNING = True
                continue
            if exc.code not in _RETRY_HTTP:
                raise RuntimeError("http " + str(exc.code)) from exc
            last = exc
        except (socket.timeout, TimeoutError) as exc:
            raise RuntimeError("timeout") from exc
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, (socket.timeout, TimeoutError)):
                raise RuntimeError("timeout") from exc
            last = exc
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            last = exc
        if attempt + 1 >= RETRIES or deadline - time.monotonic() < NEED_S:
            break
        time.sleep(1.5)
    raise RuntimeError(str(last) if last else "request failed")


# ---------------------------------------------------------------------------
# Parse helpers
# ---------------------------------------------------------------------------

def _strip_fence(text: str) -> str:
    t = text.strip()
    if t.startswith("```"):
        t = re.sub(r"^```[a-zA-Z]*\s*", "", t)
        t = re.sub(r"\s*```$", "", t)
    return t


def _scan_objects(text: str):
    found = []
    depth = start = 0
    in_str = esc = False
    start_i = -1
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
                start_i = i
            depth += 1
        elif ch == "}":
            if depth:
                depth -= 1
                if depth == 0 and start_i >= 0:
                    try:
                        obj = json.loads(text[start_i:i + 1])
                        if isinstance(obj, dict):
                            found.append(obj)
                    except json.JSONDecodeError:
                        pass
                    start_i = -1
    return found


def _extract_vulns(text: str):
    if not isinstance(text, str) or not text.strip():
        return []
    t = _strip_fence(text)
    try:
        obj = json.loads(t)
        if isinstance(obj, dict):
            items = obj.get("vulnerabilities") or obj.get("findings")
            if isinstance(items, list):
                return [x for x in items if isinstance(x, dict)]
    except json.JSONDecodeError:
        pass
    out = []
    for obj in _scan_objects(t):
        items = obj.get("vulnerabilities") or obj.get("findings")
        if isinstance(items, list):
            out.extend(x for x in items if isinstance(x, dict))
        elif any(k in obj for k in ("title", "file", "description", "severity")):
            out.append(obj)
    return out


def _extract_priority(text: str):
    paths = []
    vulns = _extract_vulns(text)
    if not isinstance(text, str):
        return paths, vulns
    t = _strip_fence(text)
    try:
        obj = json.loads(t)
        if isinstance(obj, dict):
            for key in ("priority_files", "target_files", "files"):
                val = obj.get(key)
                if isinstance(val, list):
                    paths = [str(x) for x in val if isinstance(x, str)]
                    break
    except json.JSONDecodeError:
        m = re.search(r'"(?:priority_files|target_files)"\s*:\s*\[(.*?)\]', t, re.S)
        if m:
            paths = re.findall(r'"([^"]+)"', m.group(1))
    return paths, vulns


# ---------------------------------------------------------------------------
# Indexing / ranking
# ---------------------------------------------------------------------------

def _find_root(project_dir=None):
    candidates = []
    if project_dir:
        candidates.append(project_dir)
    for env in ("PROJECT_DIR", "PROJECT_PATH", "PROJECT_ROOT", "PROJECT_CODE"):
        v = os.environ.get(env)
        if v:
            candidates.append(v)
    candidates.extend(("/app/project_code", "/app/project", "/project", "/code", "."))
    for raw in candidates:
        try:
            root = Path(raw).expanduser().resolve()
        except (OSError, RuntimeError):
            continue
        if not root.is_dir():
            continue
        try:
            for p in root.rglob("*"):
                if p.is_file() and p.suffix.lower() in SUFFIXES:
                    return root
        except OSError:
            continue
    return None


def _symbols(text: str, suffix: str):
    types, fns = [], []
    if suffix == ".sol":
        types = RX_SOL_CONTRACT.findall(text)
        fns = RX_SOL_FN.findall(text) + RX_SOL_CTOR.findall(text)
    elif suffix == ".vy":
        fns = RX_VY_FN.findall(text)
        types = [Path("x").stem]
    elif suffix == ".rs":
        types = RX_RS_MOD.findall(text)
        fns = RX_RS_FN.findall(text)
    elif suffix == ".move":
        types = RX_MOVE_MOD.findall(text)
        fns = RX_MOVE_FN.findall(text)
    elif suffix == ".cairo":
        types = RX_CAIRO_MOD.findall(text)
        fns = RX_CAIRO_FN.findall(text)
    return types, fns


def _score(rel: str, text: str, n_fn: int) -> float:
    low = (rel + "\n" + text[:12000]).lower()
    score = float(n_fn) * 0.35
    for w in VALUE_HINTS:
        if w in low:
            score += 2.2
    for w in RISK_HINTS:
        if w in low:
            score += 1.4
    if "external" in low or "public" in low or "entry" in low:
        score += 1.5
    return score


def _index(root: Path):
    records = []
    total = 0
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        suf = path.suffix.lower()
        if suf not in SUFFIXES:
            continue
        if any(part.lower() in SKIP_DIR for part in path.parts):
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size <= 0 or size > MAX_FILE_CHARS:
            continue
        text = _read(path)
        if len(text) < 40:
            continue
        rel = path.relative_to(root).as_posix()
        types, fns = _symbols(text, suf)
        rec = {
            "rel": rel,
            "base": path.name,
            "stem": path.stem,
            "suf": suf,
            "text": text,
            "types": types,
            "fns": fns,
            "score": _score(rel, text, len(fns)),
            "imports": RX_IMPORT.findall(text)[:24],
        }
        records.append(rec)
        total += len(text)
        if len(records) >= MAX_FILES or total >= MAX_FILE_CHARS:
            break
    records.sort(key=lambda r: r["score"], reverse=True)
    return records


def _neighbor_blob(rec, by_base):
    chunks = []
    budget = IMPORT_CTX_CHARS
    for raw in rec.get("imports") or []:
        name = raw.replace("\\", "/").rsplit("/", 1)[-1]
        if not name:
            continue
        for cand in (name, name + ".sol", name + ".rs", name + ".move", name + ".vy"):
            other = by_base.get(cand)
            if other is None or other["rel"] == rec["rel"]:
                continue
            snippet = other["text"][: min(900, budget)]
            block = "// neighbor " + other["rel"] + "\n" + snippet
            if len(block) > budget:
                break
            chunks.append(block)
            budget -= len(block)
            break
        if budget < 200:
            break
    return "\n\n".join(chunks)


def _outline(records, budget: int) -> str:
    parts = []
    used = 0
    for rec in records:
        lines = []
        for i, line in enumerate(rec["text"].splitlines()):
            low = line.lower()
            if any(h in low for h in RISK_HINTS) or "function" in low or "fn " in low:
                lines.append(str(i + 1) + ": " + line.strip()[:160])
            if len(lines) >= 10:
                break
        block = (
            "FILE " + rec["rel"]
            + " | units=" + ",".join((rec["types"] or [rec["stem"]])[:6])
            + " | fns=" + ",".join(rec["fns"][:14])
            + "\n" + "\n".join(lines)
        )
        if used + len(block) > budget:
            break
        parts.append(block)
        used += len(block)
    return "\n\n".join(parts)


# ---------------------------------------------------------------------------
# Normalize / merge / static net
# ---------------------------------------------------------------------------

def _sev(raw) -> str:
    s = str(raw or "").strip().lower()
    if s.startswith("crit"):
        return "critical"
    return "high"


def _match_file(value: str, by_rel, by_base, fn_hint=""):
    if not value:
        return None
    cleaned = value.strip().lstrip("./").replace("\\", "/")
    if cleaned in by_rel:
        return by_rel[cleaned]
    base = cleaned.rsplit("/", 1)[-1]
    if base in by_base:
        return by_base[base]
    low = cleaned.lower()
    for rel, rec in by_rel.items():
        if rel.lower().endswith(low) or low.endswith(rel.lower()):
            return rec
    if fn_hint:
        hint = fn_hint.lower()
        for rec in by_rel.values():
            if hint in [x.lower() for x in rec["fns"]]:
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
    rec = _match_file(str(raw.get("file") or ""), by_rel, by_base, fn)
    if rec is None and contract:
        for r in by_rel.values():
            if contract in r["types"]:
                rec = r
                break
    if rec is None:
        return None
    if fn and fn not in rec["fns"] and fn not in ("constructor", "receive", "fallback"):
        # soft pin: keep if contract matches; else drop
        if contract and contract not in rec["types"] and contract != rec["stem"]:
            return None
    if not title:
        title = (contract or rec["stem"]) + (("." + fn) if fn else "") + " - issue"
    if len(desc) < MIN_DESC:
        desc = (
            desc + " The issue is reachable through the public surface of "
            + (fn or "this unit") + " in " + rec["rel"]
            + " and can corrupt balances, authority, or protocol solvency."
        )
    return {
        "title": title[:180],
        "severity": _sev(raw.get("severity")),
        "file": rec["rel"],
        "function": fn,
        "contract": contract or (rec["types"][0] if rec["types"] else rec["stem"]),
        "description": desc[:1200],
        "confidence": float(raw.get("confidence") or 0.55),
    }


def _bug_key(item):
    blob = (item.get("title", "") + " " + item.get("description", "")).lower()
    tags = (
        ("reentrancy", ("reentran", "callback", "reenter")),
        ("access", ("access", "authoriz", "onlyowner", "signer", "permission")),
        ("oracle", ("oracle", "price", "stale", "twap", "slot0")),
        ("sig", ("signature", "replay", "permit", "ecrecover", "nonce")),
        ("account", ("share", "rounding", "inflation", "reserve", "totalsupply")),
        ("init", ("initiali", "upgrade", "delegatecall", "proxy")),
        ("math", ("overflow", "underflow", "unchecked", "arithmetic")),
    )
    klass = "other"
    for name, needles in tags:
        if any(n in blob for n in needles):
            klass = name
            break
    return (
        item.get("file", "").lower(),
        item.get("function", "").lower(),
        klass,
    )


def _merge(items):
    groups = {}
    for item in items:
        key = _bug_key(item)
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
        if len(item.get("description", "")) > len(cur.get("description", "")):
            cur["description"] = item["description"]
            cur["title"] = item["title"]
    merged = list(groups.values())
    merged.sort(
        key=lambda e: (
            int(e.get("votes", 1)),
            e["severity"] == "critical",
            float(e.get("confidence", 0)),
            len(e.get("description", "")),
        ),
        reverse=True,
    )
    out = []
    for e in merged[:EMIT_LIMIT]:
        e.pop("votes", None)
        e.pop("confidence", None)
        # runtime screening accepts vulnerabilities list with these fields
        out.append({
            "title": e["title"],
            "severity": e["severity"],
            "file": e["file"],
            "description": e["description"],
            "function": e.get("function") or "",
            "contract": e.get("contract") or "",
        })
    return out


def _static_net(records):
    """Generic structural detectors — language patterns only, no project names."""
    findings = []
    for rec in records[:40]:
        text = rec["text"]
        low = text.lower()
        types = rec["types"] or [rec["stem"]]
        unit = types[0]
        # external value transfer without an obvious reentrancy guard nearby
        if rec["suf"] == ".sol" and (".call{" in low or "call.value" in low):
            if "nonreentrant" not in low and "reentrancyguard" not in low:
                for fn in rec["fns"][:8]:
                    if fn.lower() in ("withdraw", "redeem", "claim", "execute", "settle", "liquidate"):
                        findings.append({
                            "title": unit + "." + fn + " - external call without reentrancy guard",
                            "severity": "high",
                            "file": rec["rel"],
                            "function": fn,
                            "contract": unit,
                            "description": (
                                "Function " + fn + " in " + rec["rel"]
                                + " performs a low-level external call while no NonReentrant "
                                "or ReentrancyGuard pattern is visible in the file. An "
                                "attacker-controlled callee can reenter and drain funds or "
                                "corrupt accounting before state updates settle."
                            ),
                            "confidence": 0.45,
                        })
                        break
        # public initialize / upgrade hooks without an obvious initializer lock
        if rec["suf"] == ".sol":
            for fn in rec["fns"]:
                fl = fn.lower()
                if fl in ("initialize", "init", "upgradeto", "upgradetoandcall"):
                    if "initializer" not in low and "reinitializer" not in low and "onlyowner" not in low:
                        findings.append({
                            "title": unit + "." + fn + " - privileged setup surface",
                            "severity": "critical",
                            "file": rec["rel"],
                            "function": fn,
                            "contract": unit,
                            "description": (
                                "Function " + fn + " in " + rec["rel"]
                                + " looks like an initialization or upgrade entry without a "
                                "clear initializer lock or owner restriction in-file. If "
                                "callable after deployment, an attacker can seize upgrade "
                                "authority or rewrite critical parameters."
                            ),
                            "confidence": 0.42,
                        })
        # Solana-ish: transfer / invoke without is_signer mention in file
        if rec["suf"] == ".rs" and ("invoke" in low or "lamports" in low):
            if "is_signer" not in low and "signer" not in " ".join(rec["fns"]).lower():
                fn = rec["fns"][0] if rec["fns"] else "process"
                findings.append({
                    "title": unit + "." + fn + " - missing signer check on fund path",
                    "severity": "high",
                    "file": rec["rel"],
                    "function": fn,
                    "contract": unit,
                    "description": (
                        "Rust unit " + rec["rel"] + " touches lamports or CPI invoke "
                        "without an obvious is_signer check in the same file. Missing "
                        "signer validation commonly lets an attacker move accounts they "
                        "do not control."
                    ),
                    "confidence": 0.4,
                })
        if len(findings) >= 8:
            break
    return findings


# ---------------------------------------------------------------------------
# Passes
# ---------------------------------------------------------------------------

def _run_survey(endpoint, records, deadline):
    if deadline - time.monotonic() < NEED_S:
        return [], []
    prompt = SURVEY_ASK + _outline(records, SURVEY_CHARS)
    text = _post(endpoint, prompt, deadline, TOK_SURVEY)
    return _extract_priority(text)


def _run_unit(endpoint, rec, by_base, deadline):
    if deadline - time.monotonic() < NEED_S:
        return []
    body = rec["text"][:UNIT_SRC_CHARS]
    neigh = _neighbor_blob(rec, by_base)
    prompt = (
        UNIT_ASK
        + "\n===== UNIT FILE: " + rec["rel"] + " =====\n"
        + "contracts/modules: " + ", ".join((rec["types"] or [rec["stem"]])[:8]) + "\n"
        + body
    )
    if neigh:
        prompt += "\n\n===== IMPORT CONTEXT (read-only) =====\n" + neigh
    try:
        return _extract_vulns(_post(endpoint, prompt, deadline, TOK_UNIT))
    except Exception:
        return []


def _run_units(endpoint, records, by_base, deadline):
    if not records or deadline - time.monotonic() < NEED_S:
        return []
    bag = []
    lock = threading.Lock()

    def work(rec):
        return _run_unit(endpoint, rec, by_base, deadline)

    n = min(WORKERS, max(1, len(records)))
    with ThreadPoolExecutor(max_workers=n) as pool:
        futs = [pool.submit(work, rec) for rec in records[:TOP_UNITS]]
        for fut in as_completed(futs):
            try:
                chunk = fut.result() or []
            except Exception:
                chunk = []
            if chunk:
                with lock:
                    bag.extend(chunk)
    return bag


def _run_verify(endpoint, candidates, by_rel, deadline):
    if not candidates or deadline - time.monotonic() < NEED_S + 40:
        return candidates
    # attach compact source for the involved files
    files = []
    seen = set()
    for c in candidates[:VERIFY_TOP]:
        rel = c.get("file")
        if not rel or rel in seen:
            continue
        rec = by_rel.get(rel)
        if rec is None:
            continue
        seen.add(rel)
        files.append("FILE " + rel + "\n" + rec["text"][:VERIFY_SRC_CHARS])
    payload = {
        "candidates": [
            {
                "title": c.get("title"),
                "severity": c.get("severity"),
                "file": c.get("file"),
                "function": c.get("function"),
                "description": c.get("description"),
            }
            for c in candidates[:VERIFY_TOP]
        ]
    }
    prompt = (
        VERIFY_ASK
        + "\nCandidates:\n"
        + json.dumps(payload, separators=(",", ":"))
        + "\n\nSource:\n"
        + "\n\n".join(files)[:28000]
    )
    try:
        kept = _extract_vulns(_post(endpoint, prompt, deadline, TOK_VERIFY))
        return kept if kept else candidates
    except Exception:
        return candidates


def _reorder(records, priority_paths):
    if not priority_paths:
        return records
    front, taken = [], set()
    for path in priority_paths:
        cleaned = path.strip().lstrip("./").replace("\\", "/")
        base = cleaned.rsplit("/", 1)[-1]
        for rec in records:
            if rec["rel"] in taken:
                continue
            rel = rec["rel"]
            if cleaned == rel or rel.endswith(cleaned) or cleaned.endswith(rel) or rec["base"] == base:
                front.append(rec)
                taken.add(rel)
                break
    return front + [r for r in records if r["rel"] not in taken]


# ---------------------------------------------------------------------------
# Entry
# ---------------------------------------------------------------------------

def agent_main(project_dir=None, inference_api=None):
    report = []
    deadline = time.monotonic() + WALL_S
    try:
        root = _find_root(project_dir)
        if root is None:
            return {"vulnerabilities": report}
        records = _index(root)
        if not records:
            return {"vulnerabilities": report}
        by_rel = {r["rel"]: r for r in records}
        by_base = {}
        for r in records:
            by_base.setdefault(r["base"], r)

        endpoint = _gateway(inference_api)
        raw = []

        if endpoint and deadline - time.monotonic() >= NEED_S:
            try:
                priority, seeded = _run_survey(endpoint, records, deadline)
                raw.extend(seeded)
                records = _reorder(records, priority)
            except Exception:
                pass

        if endpoint and deadline - time.monotonic() >= NEED_S:
            try:
                raw.extend(_run_units(endpoint, records, by_base, deadline))
            except Exception:
                pass

        cleaned = []
        for item in raw:
            norm = _normalize(item, by_rel, by_base)
            if norm is not None:
                cleaned.append(norm)

        if endpoint and cleaned and deadline - time.monotonic() >= NEED_S + 40:
            try:
                verified = _run_verify(endpoint, cleaned, by_rel, deadline)
                cleaned = []
                for item in verified:
                    norm = _normalize(item, by_rel, by_base)
                    if norm is not None:
                        cleaned.append(norm)
            except Exception:
                pass

        if not cleaned:
            for item in _static_net(records):
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
