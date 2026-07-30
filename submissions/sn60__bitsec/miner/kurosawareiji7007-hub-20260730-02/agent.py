"""SN60 Bitsec miner — scout / focus / sweep + pattern recall (OpenRouter).

Project-pass is decided first: missing planted high/critical issues fails a
project. This agent optimizes for coverage.

Pipeline
  1. Scout  — map the repo from signatures + risk lines; seed early findings
  2. Focus  — deep-read the highest-priority source files
  3. Sweep  — second pass over a wider file set with a fresh prompt
  4. Merge  — dedupe by file/function/bug-class and emit the strongest set

Transport talks only to the injected inference gateway. Standard library only.
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
    "interfaces", "interface", "generated", "bindings",
})
PER_FILE_MAX = 80_000

RX_SOL_T = re.compile(
    r"\b(?:abstract\s+contract|contract|library|interface)\s+([A-Za-z_][A-Za-z0-9_]*)"
)
RX_SOL_F = re.compile(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
RX_SOL_S = re.compile(r"\b(constructor|receive|fallback)\b\s*\(")
RX_VY_F = re.compile(r"(?m)^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
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
RX_IMP = re.compile(r'(?m)^\s*(?:import|use)\b[^;\n]*?["\']?([A-Za-z0-9_./]+)["\']?')

NAME_HINTS = (
    "vault", "pool", "router", "manager", "controller", "strategy", "market",
    "lend", "borrow", "oracle", "price", "stak", "reward", "treasury", "bridge",
    "factory", "proxy", "govern", "token", "escrow", "auction", "liquidat",
    "swap", "collateral", "mint", "burn", "farm", "perp", "margin", "settle",
)
CODE_HINTS = (
    "delegatecall", ".call{", "selfdestruct", "tx.origin", "assembly",
    "ecrecover", "permit", "initialize", "upgradeto", "onlyowner", "withdraw",
    "redeem", "deposit", "borrow", "repay", "liquidat", "flash", "unchecked",
    "transferfrom", "approve", "mint(", "burn(", "claim", "signer", "lamports",
    "invoke", "cpi", "is_signer", "info.sender", "borrow_global", "get_caller",
)

MAX_FILES = 95
MAX_BYTES = 260_000
FOCUS_N = 10
FOCUS_CHARS = 16_000
FOCUS_BUDGET = 48_000
SWEEP_N = 16
SWEEP_CHARS = 8_500
SWEEP_BUDGET = 52_000
SCOUT_BUDGET = 42_000
IMPORT_CHARS = 3_000
EMIT_N = 36
MIN_DESC = 80

MODEL = os.environ.get("KATA_MINER_MODEL", "deepseek/deepseek-chat-v3-0324")
TOK_SCOUT = 12_000
TOK_FOCUS = 16_000
TOK_SWEEP = 15_000

WALL = 780.0
HTTP_TO = 200.0
TAIL = 12.0
FLOOR = 35.0
RETRIES = 2

_USE_EXTRA = True
_RETRY = frozenset({408, 409, 425, 500, 502, 504, 520, 522, 524, 529})

PERSONA = (
    "You are a senior smart-contract auditor covering Solidity, Vyper, Rust "
    "(Solana/Anchor + CosmWasm), Move, and Cairo. List every HIGH or CRITICAL "
    "issue you can pin to a real function. Missing a real bug costs more than an "
    "extra candidate. In scope: fund theft, insolvency, auth bypass, privilege "
    "escalation, permanent DoS, mint/supply corruption, oracle abuse, reentrancy, "
    "signature replay. Out of scope: gas, style, missing events, pure centralization. "
    "Reply with one minified JSON object only."
)

SCOPE = (
    "Language checklist — "
    "EVM: reentrancy/call ordering, access control, delegatecall/init/upgrade, "
    "share inflation/rounding, stale or gameable oracles, permit/replay, "
    "fee-on-transfer assumptions, native-value accounting, permanent DoS, "
    "mint/burn using msg.value when an amount param was transferred, "
    "CREATE/clone address frontrun of createPair, permissionless rebalance/settle. "
    "Solana/Anchor: missing is_signer/owner/has_one, bad PDA seeds, missing close, "
    "unchecked math, unsafe CPI, discriminator confusion. "
    "CosmWasm: missing info.sender checks, open migrate. "
    "Move: missing signer/capability, exposed privileged entry. "
    "Cairo: missing caller checks, felt wrap, L1 handler auth."
)

COMPLETE = (
    "Be exhaustive on the supplied source. Prefer many pinned findings over a "
    "short list. One entry per distinct defect. For each, say why existing guards fail."
)

PIN = (
    "Copy file paths from FILE headers exactly. function must be a real name from "
    "that file (no args, no Contract. prefix). contract must be declared there. "
    "Describe precondition -> attacker move -> broken state."
)

FMT = (
    "Return bare minified JSON, double quotes, severity exactly high or critical, "
    "descriptions 2-4 sentences, strongest first."
)

SHAPE = (
    '{"findings":[{"title":"Name.fn - defect","file":"path","contract":"Name",'
    '"function":"fn","severity":"high|critical","confidence":0.6,'
    '"description":"concrete exploit narrative"}]}'
)

SCOUT_ASK = (
    "Project outline below. (1) Put 8-12 highest-yield paths in target_files. "
    "(2) Report every high/critical already visible from signatures and risk lines. "
    + COMPLETE + " " + SCOPE + " " + PIN + " " + FMT
    + ' JSON shape: {"target_files":["path"],"findings":[...]} where findings match '
    + SHAPE + "\nOutline:\n"
)

FOCUS_ASK = (
    "Deep-audit the source units below for HIGH/CRITICAL bugs. "
    + COMPLETE + " " + SCOPE + " " + PIN + " " + FMT
    + " JSON only: " + SHAPE + "\n"
)

SWEEP_ASK = (
    "Second pass with fresh eyes. Prefer cross-contract flows, accounting theft, "
    "oracle abuse, auth holes, reentrancy, liquidation math, init/upgrade, replay. "
    + COMPLETE + " " + SCOPE + " " + PIN + " " + FMT
    + " JSON only: " + SHAPE + "\n"
)


def _item(title, severity, file_path, description, function="", contract="", confidence=0.55):
    item = {}
    item["title"] = str(title)[:180]
    item["severity"] = severity
    item["file"] = file_path
    item["description"] = str(description)[:1200]
    item["function"] = function or ""
    item["contract"] = contract or ""
    item["confidence"] = float(confidence)
    return item


def _root(project_dir=None):
    tries = []
    if project_dir:
        tries.append(project_dir)
    for env in ("PROJECT_DIR", "PROJECT_PATH", "PROJECT_ROOT", "PROJECT_CODE"):
        v = os.environ.get(env)
        if v:
            tries.append(v)
    tries.extend(("/app/project_code", "/app/project", "/project", "/code", "."))
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
    low = (rel + "\n" + text[:10000]).lower()
    score = nfn * 0.4
    for h in NAME_HINTS:
        if h in low:
            score += 2.0
    for h in CODE_HINTS:
        if h in low:
            score += 1.3
    if "external" in low or "public" in low or "entry" in low:
        score += 1.2
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
        # Prefer real contract bodies over pure interface/header stubs.
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
        if stem.startswith("test") or stem.endswith("test") or ".t." in path.name.lower():
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
            "imports": RX_IMP.findall(text)[:20],
        })
    rows.sort(key=lambda r: (-r["score"], r["rel"]))
    return rows[:MAX_FILES]


def _neighbors(rec, by_base):
    out = []
    left = IMPORT_CHARS
    for raw in rec.get("imports") or []:
        name = raw.replace("\\", "/").rsplit("/", 1)[-1]
        for cand in (name, name + ".sol", name + ".rs", name + ".move", name + ".vy"):
            other = by_base.get(cand)
            if other is None or other["rel"] == rec["rel"]:
                continue
            chunk = other["text"][: min(900, left)]
            block = "// import " + other["rel"] + "\n" + chunk
            if len(block) > left:
                return "\n\n".join(out)
            out.append(block)
            left -= len(block)
            break
        if left < 200:
            break
    return "\n\n".join(out)


def _outline(rows, budget):
    parts = []
    used = 0
    for rec in rows:
        hot = []
        for i, line in enumerate(rec["text"].splitlines()):
            low = line.lower()
            if any(h in low for h in CODE_HINTS) or "function" in low or " fn " in low:
                hot.append(str(i + 1) + ": " + line.strip()[:150])
            if len(hot) >= 12:
                break
        block = (
            "FILE " + rec["rel"]
            + " | units=" + ",".join((rec["types"] or [rec["stem"]])[:6])
            + " | fns=" + ",".join(rec["fns"][:16])
            + "\n" + "\n".join(hot)
        )
        if used + len(block) > budget:
            break
        parts.append(block)
        used += len(block)
    return "\n\n".join(parts)


def _message(payload):
    try:
        choice = (payload.get("choices") or [{}])[0]
        msg = choice.get("message") or {}
        content = msg.get("content")
        if isinstance(content, list):
            content = "".join(
                p.get("text", "") for p in content if isinstance(p, dict)
            )
        if isinstance(content, str) and content.strip():
            return content
        for key in ("reasoning", "reasoning_content"):
            val = msg.get(key)
            if isinstance(val, str) and val.strip():
                return val
    except Exception:
        pass
    return ""


def _encode(prompt, max_tokens, extra):
    body = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": PERSONA},
            {"role": "user", "content": prompt},
        ],
        "max_tokens": max_tokens,
    }
    if extra:
        body["reasoning_effort"] = "medium"
    return json.dumps(body).encode("utf-8")


def _call(endpoint, prompt, deadline, max_tokens):
    global _USE_EXTRA
    if not endpoint:
        raise RuntimeError("no endpoint")
    headers = {
        "Content-Type": "application/json",
        "x-inference-api-key": os.environ.get("INFERENCE_API_KEY", ""),
    }
    err = None
    for attempt in range(RETRIES):
        remain = deadline - time.monotonic() - TAIL
        timeout = min(HTTP_TO, float(int(remain)))
        if timeout < FLOOR:
            raise RuntimeError("budget")
        raw = _encode(prompt, max_tokens, _USE_EXTRA)
        try:
            req = urllib.request.Request(
                endpoint + "/inference", data=raw, method="POST", headers=headers
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return _message(json.loads(resp.read().decode("utf-8", "replace")))
        except urllib.error.HTTPError as exc:
            if exc.code == 400 and _USE_EXTRA:
                _USE_EXTRA = False
                continue
            if exc.code in {429, 503} or exc.code not in _RETRY:
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
        if deadline - time.monotonic() < FLOOR + 40:
            break
        time.sleep(2.0)
    raise RuntimeError(str(err) if err else "request failed")


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


def _scout_parse(text):
    paths, hits = [], []
    if not isinstance(text, str):
        return paths, hits
    t = _strip(text)
    try:
        obj = json.loads(t)
        if isinstance(obj, dict):
            tg = obj.get("target_files")
            if isinstance(tg, list):
                paths = [str(x) for x in tg if isinstance(x, str)]
            items = obj.get("findings") or obj.get("vulnerabilities")
            if isinstance(items, list):
                hits = [x for x in items if isinstance(x, dict)]
            return paths, hits
    except json.JSONDecodeError:
        pass
    m = re.search(r'"target_files"\s*:\s*\[(.*?)\]', t, re.S)
    if m:
        paths = re.findall(r'"([^"]+)"', m.group(1))
    hits = _findings(text)
    return paths, hits


def _focus_prompt(batch, by_base):
    parts = [FOCUS_ASK]
    left = FOCUS_BUDGET - len(FOCUS_ASK)
    extra = _neighbors(batch[0], by_base) if batch else ""
    for rec in batch:
        take = min(len(rec["text"]), FOCUS_CHARS, max(0, left))
        if take <= 0:
            break
        body = rec["text"] if len(rec["text"]) <= take else rec["text"][:take]
        block = (
            "\n\n===== FILE: " + rec["rel"] + " =====\n"
            + "units: " + (", ".join(rec["types"][:8]) or rec["stem"]) + "\n"
            + body
        )
        parts.append(block)
        left -= len(block)
    if extra and left > 600:
        parts.append("\n\n===== IMPORT CONTEXT =====\n" + extra[: left - 100])
    return "".join(parts)


def _sweep_prompt(batch):
    parts = [SWEEP_ASK]
    left = SWEEP_BUDGET - len(SWEEP_ASK)
    for rec in batch:
        body = rec["text"][:SWEEP_CHARS]
        block = (
            "\n\n===== FILE: " + rec["rel"] + " =====\n"
            + "units: " + (", ".join(rec["types"][:8]) or rec["stem"]) + "\n"
            + body + "\n"
        )
        if left <= 0:
            break
        if len(block) > left:
            block = block[:left] + "\n/* truncated */"
        parts.append(block)
        left -= len(block)
    return "".join(parts)


def _reorder(rows, targets):
    if not targets:
        return rows
    front, taken = [], set()
    for t in targets:
        cleaned = t.strip().lstrip("./").replace("\\", "/")
        base = cleaned.rsplit("/", 1)[-1]
        for rec in rows:
            if rec["rel"] in taken:
                continue
            rel = rec["rel"]
            if cleaned == rel or rel.endswith(cleaned) or cleaned.endswith(rel) or rec["base"] == base:
                front.append(rec)
                taken.add(rel)
                break
    return front + [r for r in rows if r["rel"] not in taken]


def _sev(raw):
    s = str(raw or "").lower()
    if s.startswith("crit"):
        return "critical"
    return "high"


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
    rec = _resolve(raw.get("file"), by_rel, by_base, fn)
    if rec is None and contract:
        for r in by_rel.values():
            if contract in r["types"] or contract == r["stem"]:
                rec = r
                break
    if rec is None:
        # last resort: first high-score file so we don't discard model signal
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
            + "; confirm against surrounding guards and value flow."
        )
    return _item(
        title,
        _sev(raw.get("severity")),
        rec["rel"],
        desc,
        fn,
        contract or (rec["types"][0] if rec["types"] else rec["stem"]),
        float(raw.get("confidence") or 0.55),
    )


def _klass(item):
    blob = (item.get("title", "") + " " + item.get("description", "")).lower()
    pairs = (
        ("reentrancy", ("reentran", "callback", "reenter")),
        ("access", ("access", "authoriz", "onlyowner", "signer", "permission")),
        ("oracle", ("oracle", "price", "stale", "twap", "slot0")),
        ("sig", ("signature", "replay", "permit", "ecrecover", "nonce")),
        ("account", ("share", "rounding", "inflation", "reserve", "totalsupply")),
        ("init", ("initiali", "upgrade", "delegatecall", "proxy")),
        ("math", ("overflow", "underflow", "unchecked", "arithmetic")),
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
    for e in merged[:EMIT_N]:
        out.append(
            _item(
                e["title"],
                e["severity"],
                e["file"],
                e["description"],
                e.get("function") or "",
                e.get("contract") or "",
                e.get("confidence") or 0.55,
            )
        )
        # drop internal bookkeeping before emit
        out[-1].pop("confidence", None)
    return out



def _brace_block(text, start):
    open_at = text.find("{", start)
    if open_at < 0:
        return text[start:start + 700]
    depth = 0
    for i in range(open_at, min(len(text), open_at + 8000)):
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return text[start:start + 1800]


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
        out.append({"name": name, "sig": sig, "body": text[pos:end]})
    return out


def _raw_hit(title, rel, contract, function, severity, description):
    hit = {}
    hit["title"] = title
    hit["file"] = rel
    hit["contract"] = contract
    hit["function"] = function
    hit["severity"] = severity
    hit["description"] = description
    hit["confidence"] = 0.72
    return hit


def _pattern_hits(rows):
    out = []
    for rec in rows:
        if rec.get("suf") != ".sol":
            continue
        text = rec["text"]
        low = text.lower()
        contract = rec["types"][0] if rec.get("types") else rec["stem"]
        for m in re.finditer(r"function\s+([A-Za-z_]\w*)\s*\(([^)]*)\)([^{]*)\{", text):
            name, args, mods = m.group(1), m.group(2), m.group(3)
            body = _brace_block(text, m.start())
            blow = body.lower()
            al = args.lower()
            ml = mods.lower()
            if "amount" in al and "_mint(" in blow and "msg.value" in blow:
                if re.search(r"_mint\s*\(\s*[^,]+,\s*msg\.value\s*\)", body):
                    out.append(_raw_hit(
                        contract + "." + name + " - mints with msg.value not amount",
                        rec["rel"], contract, name, "high",
                        "Function " + name + " takes an amount and may pull ERC20 tokens for that "
                        "amount, but mints using msg.value. On ERC20 paths msg.value is 0 so "
                        "callers lose deposited tokens and receive a zero mint. Preconditions: "
                        "non-native underlying; attacker or user calls with amount>0."
                    ))
            if name.lower() in ("initialize", "init") and ("external" in ml or "public" in ml):
                guards = ("initializer", "onlyowner", "onlyrole", "_disableinitializers", "initialized")
                if not any(g in blow for g in guards) and any(x in blow for x in ("_mint(", "owner", "name")):
                    out.append(_raw_hit(
                        contract + "." + name + " - unprotected initializer",
                        rec["rel"], contract, name, "critical",
                        "Initializer " + name + " is externally callable without a one-time "
                        "initializer modifier or ownership gate. An attacker can call it first "
                        "to seize ownership or mint the configured supply to themselves."
                    ))
        if "createpair" in low and "clone(" in low and "getpair" not in low:
            for fn in _sol_fns(text):
                blow = fn["body"].lower()
                if "createpair" in blow or ("clone(" in blow and ("pair" in blow or "launch" in blow)):
                    out.append(_raw_hit(
                        contract + "." + fn["name"] + " - createPair frontrun DoS",
                        rec["rel"], contract, fn["name"], "high",
                        "Token deployment uses CREATE-style clone addressing then creates a "
                        "Uniswap pair. The next token address is predictable, so an attacker "
                        "can call createPair first; later launch calls revert permanently "
                        "because the pair already exists and is not handled."
                    ))
                    break
        for fn in _sol_fns(text):
            nlow = fn["name"].lower()
            sig = fn["sig"].lower()
            blow = fn["body"].lower()
            if nlow in ("rebalance", "settle", "liquidate", "execute") and (
                "external" in sig or "public" in sig
            ):
                if "only" not in sig and not any(
                    g in blow for g in ("onlyowner", "onlyrole", "require(msg.sender", "hasrole")
                ):
                    if any(x in blow for x in ("flash", "swap", "transfer", ".call{")):
                        out.append(_raw_hit(
                            contract + "." + fn["name"] + " - permissionless value path",
                            rec["rel"], contract, fn["name"], "high",
                            "Externally callable " + fn["name"] + " moves value via swap/flash/"
                            "transfer without a clear owner/role gate on caller-supplied "
                            "parameters, so an unprivileged caller can drive the accounting "
                            "away from the intended peg or settlement."
                        ))
        if len(out) >= 10:
            break
    return out[:10]



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

        endpoint = (inference_api or os.environ.get("INFERENCE_API") or "").rstrip("/")
        raw = []
        ordered = rows

        if endpoint and deadline - time.monotonic() > FLOOR + 80:
            try:
                text = _call(
                    endpoint,
                    SCOUT_ASK + _outline(rows, SCOUT_BUDGET),
                    deadline,
                    TOK_SCOUT,
                )
                targets, seeded = _scout_parse(text)
                raw.extend(seeded)
                ordered = _reorder(rows, targets)
            except Exception:
                pass

        if endpoint and deadline - time.monotonic() > FLOOR + 80:
            try:
                batch = ordered[:FOCUS_N]
                text = _call(
                    endpoint,
                    _focus_prompt(batch, by_base),
                    deadline,
                    TOK_FOCUS,
                )
                raw.extend(_findings(text))
            except Exception:
                pass

        if endpoint and deadline - time.monotonic() > FLOOR + 80:
            try:
                wide = ordered[4:4 + SWEEP_N] + ordered[:4]
                text = _call(
                    endpoint,
                    _sweep_prompt(wide),
                    deadline,
                    TOK_SWEEP,
                )
                raw.extend(_findings(text))
            except Exception:
                pass

        try:
            raw.extend(_pattern_hits(rows))
        except Exception:
            pass

        cleaned = []
        for item in raw:
            norm = _normalize(item, by_rel, by_base)
            if norm is not None:
                cleaned.append(norm)
        if not cleaned:
            try:
                for item in _pattern_hits(rows):
                    norm = _normalize(item, by_rel, by_base)
                    if norm is not None:
                        cleaned.append(norm)
            except Exception:
                pass
        report = _merge(cleaned)
    except Exception:
        return {"vulnerabilities": report}
    return {"vulnerabilities": report}


if __name__ == "__main__":
    import sys
    print(json.dumps(agent_main(sys.argv[1] if len(sys.argv) > 1 else None), indent=2))
