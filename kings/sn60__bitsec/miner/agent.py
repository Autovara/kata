"""SN60 miner: multi-language triage + deep contiguous + wide second pass.

Built to challenge Dexterity104 (PR #160): full sol/vy/rs/move/cairo coverage,
risk-window compaction for large files, 3 timed LLM calls under the TEE
screener budget, plus high-precision structural supplements. No fingerprint
branches or canned benchmark answers.
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

EXTS = (".sol", ".vy", ".rs", ".move", ".cairo")
MAX_FILES = 90
MAX_BYTES = 280_000
MAP_CHARS = 28_000
DEEP_CHARS = 48_000
WIDE_CHARS = 52_000
PER_FILE_DEEP = 16_000
PER_FILE_WIDE = 7_500
RELATED_CHARS = 3_000
MAX_FINDINGS = 14
RUN_CAP = 760.0
HTTP_TIMEOUT = 195
CALL_RESERVE = 200.0
MAX_CALLS = 3
# Strong Chutes TEE model; override with KATA_MINER_MODEL if needed.
MODEL = os.environ.get("KATA_MINER_MODEL", "deepseek-ai/DeepSeek-V3.2-TEE")

SKIP_DIRS = frozenset({
    ".git", ".github", ".venv", "artifacts", "broadcast", "cache", "coverage",
    "dist", "docs", "example", "examples", "lib", "libs", "node_modules", "out",
    "script", "scripts", "target", "test", "tests", "vendor", "vendors",
    "mock", "mocks", "fixtures", "fixture", "deps", "build", "interfaces",
    "interface",
})

RISK_WORDS = (
    "delegatecall", ".call{", "selfdestruct", "tx.origin", "assembly",
    "ecrecover", "permit", "signature", "nonce", "initialize", "upgrade",
    "onlyowner", "onlyrole", "mint", "burn", "withdraw", "redeem", "deposit",
    "borrow", "repay", "liquidat", "collateral", "share", "totalsupply",
    "oracle", "getprice", "latestround", "slot0", "flash", "swap", "claim",
    "unchecked", "transferfrom", "approve", "settle", "rebalance", "invoke",
    "cpi", "signer", "authority", "lamports", "borrow_global", "move_to",
    "capability", "get_caller_address", "felt", "starknet",
)

NAME_WORDS = (
    "vault", "pool", "router", "manager", "controller", "strategy", "market",
    "oracle", "bridge", "staking", "reward", "treasury", "govern", "proxy",
    "liquidat", "borrow", "token", "perp", "position", "lending", "escrow",
    "auction", "amm", "pair", "adapter", "clearing", "margin", "program",
    "module", "account", "factory",
)

FUNC_SOL = re.compile(
    r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*([^{};]*)(?:;|\{)",
    re.MULTILINE,
)
FUNC_VY = re.compile(r"^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", re.MULTILINE)
FUNC_RS = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
FUNC_MOVE = re.compile(
    r"^\s*(?:public\s*(?:\([^)]*\))?\s+)?(?:entry\s+)?(?:native\s+)?fun\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
FUNC_CAIRO = re.compile(r"^\s*(?:pub\s+)?(?:fn|func)\s+([A-Za-z_][A-Za-z0-9_]*)", re.MULTILINE)
CONTRACT_SOL = re.compile(
    r"^\s*(?:abstract\s+contract|contract|library|interface)\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
CONTRACT_RS = re.compile(
    r"^\s*(?:pub\s+)?(?:mod|struct|enum)\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
CONTRACT_MOVE = re.compile(
    r"^\s*module\s+(?:[A-Za-z_0-9]+::)?([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
CONTRACT_CAIRO = re.compile(r"^\s*(?:pub\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)", re.MULTILINE)
IMPORT_RE = re.compile(r'^\s*(?:import|use)\b[^;\n]*?["\']?([A-Za-z0-9_./:]+)["\']?', re.MULTILINE)
DEF_LINE_RE = re.compile(
    r"\bfunction\b|\bdef\b|\bfn\b|\bfun\b|\bmodifier\b|\bconstructor\b|\bmodule\b|\bmapping\b"
)

SYSTEM = (
    "You are a senior smart-contract security auditor for Solidity, Vyper, "
    "Rust/Solana, Move, and Cairo. Report only REAL exploitable HIGH or CRITICAL "
    "bugs with a concrete on-chain exploit path and material impact, localized to "
    "exact file and function. Reject gas, style, missing events, and trusted-admin "
    "notes. Prefer precision. Return strict JSON only."
)

PRIORITIES = (
    "Prioritize: value/share/reserve accounting, rounding and first-depositor "
    "issues, manipulable or stale oracle/price feeds, missing access control, "
    "reentrancy and external-call ordering, signature/nonce/replay, unsafe "
    "external calls, init/upgrade flaws, liquidation edges. For Rust/Move/Cairo "
    "also check missing signer/authority and account-ownership confusion."
)


def agent_main(project_dir: str | None = None, inference_api: str | None = None) -> dict:
    started = time.monotonic()
    findings: list[dict[str, Any]] = []
    try:
        root = project_root(project_dir)
        if root is None:
            return {"vulnerabilities": findings}
        records = discover(root)
        if not records:
            return {"vulnerabilities": findings}

        rel_map = {r["rel"]: r for r in records}
        by_name = {Path(r["rel"]).name: r for r in records}
        raw: list[dict[str, Any]] = []
        calls = 0
        ordered = records

        if time_left(started, CALL_RESERVE):
            targets, mapped = triage(inference_api, records, started)
            raw.extend(mapped)
            ordered = order_targets(targets, records)
            calls = 1

        # Call 2: deep contiguous audit on the hottest files.
        if calls < MAX_CALLS and time_left(started, CALL_RESERVE):
            deep = ordered[:4]
            raw.extend(audit_batch(
                inference_api, deep, by_name, started,
                per_file=PER_FILE_DEEP, budget=DEEP_CHARS, mode="deep-contiguous",
            ))
            calls += 1

        # Call 3: wide risk-windowed pass over mid-tier + top.
        if calls < MAX_CALLS and time_left(started, CALL_RESERVE):
            wide = ordered[3:3 + 10] + ordered[:3]
            # unique preserve order
            seen: set[str] = set()
            uniq: list[dict[str, Any]] = []
            for rec in wide:
                if rec["rel"] not in seen:
                    seen.add(rec["rel"])
                    uniq.append(rec)
            raw.extend(audit_batch(
                inference_api, uniq[:12], by_name, started,
                per_file=PER_FILE_WIDE, budget=WIDE_CHARS, mode="wide-risk-window",
                compact=True,
            ))
            calls += 1

        raw.extend(structural_probes(records))

        for item in raw:
            norm = normalize(item, rel_map)
            if norm is not None:
                findings.append(norm)
    except Exception:
        pass
    return {"vulnerabilities": dedupe(findings)}


def time_left(started: float, need: float = 0.0) -> bool:
    return time.monotonic() - started < RUN_CAP - need


def project_root(project_dir: str | None) -> Path | None:
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
        if path.is_dir() and has_sources(path):
            return path
    return None


def has_sources(root: Path) -> bool:
    try:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [
                d for d in dirnames if d.lower() not in SKIP_DIRS and not d.startswith(".")
            ]
            for name in filenames:
                if Path(name).suffix.lower() in EXTS:
                    return True
    except OSError:
        return False
    return False


def should_skip(rel: Path) -> bool:
    for part in rel.parts[:-1]:
        low = part.lower()
        if low in SKIP_DIRS or low.startswith("."):
            return True
    name = rel.name.lower()
    return name.endswith((
        ".t.sol", ".s.sol", "_test.sol", ".test.sol", "_test.rs", ".test.rs", "_tests.move",
    ))


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def parse_functions(text: str, ext: str) -> list[dict[str, Any]]:
    if ext == ".vy":
        patterns = [FUNC_VY]
    elif ext == ".rs":
        patterns = [FUNC_RS]
    elif ext == ".move":
        patterns = [FUNC_MOVE]
    elif ext == ".cairo":
        patterns = [FUNC_CAIRO]
    else:
        patterns = [FUNC_SOL]
    out: list[dict[str, Any]] = []
    for pat in patterns:
        for match in pat.finditer(text):
            out.append({
                "name": match.group(1),
                "line": text.count("\n", 0, match.start()) + 1,
                "sig": " ".join(match.group(0).strip().split())[:180],
            })
    return out


def contracts_for(text: str, ext: str, stem: str) -> list[str]:
    if ext == ".rs":
        found = CONTRACT_RS.findall(text)
    elif ext == ".move":
        found = CONTRACT_MOVE.findall(text)
    elif ext == ".cairo":
        found = CONTRACT_CAIRO.findall(text)
    else:
        found = CONTRACT_SOL.findall(text)
    seen: list[str] = []
    for name in found:
        if name not in seen:
            seen.append(name)
    return seen or [stem]


def risk_lines(text: str) -> list[str]:
    lines: list[str] = []
    terms = tuple(w.lower() for w in RISK_WORDS)
    for num, line in enumerate(text.splitlines(), start=1):
        low = line.lower().replace(" ", "")
        if any(t in low for t in terms):
            compact = " ".join(line.strip().split())
            if compact:
                lines.append(f"{num}: {compact[:160]}")
        if len(lines) >= 16:
            break
    return lines


def score_file(rel: str, text: str, ext: str) -> int:
    ln, body = rel.lower(), text.lower()
    compact = body.replace(" ", "")
    score = min(
        body.count("function ") + body.count("\ndef ") + body.count("\nfn ")
        + body.count("\nfun ") + body.count(" pub fn"),
        50,
    )
    for word in NAME_WORDS:
        if word in ln:
            score += 10
        elif word in body:
            score += 2
    for word in RISK_WORDS:
        if word.lower().replace(" ", "") in compact:
            score += 3
    if any(tok in body for tok in ("external", "public", "entry", "pub fn", "#[external")):
        score += 6
    if "delegatecall" in compact:
        score += 9
    if "tx.origin" in compact:
        score += 7
    if ext in {".rs", ".move", ".cairo"}:
        score += 5
    if "interface" in ln:
        score -= 10
    return score


def discover(root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [
                d for d in dirnames if d.lower() not in SKIP_DIRS and not d.startswith(".")
            ]
            for fname in filenames:
                path = Path(dirpath) / fname
                ext = path.suffix.lower()
                if ext not in EXTS:
                    continue
                try:
                    rel = path.relative_to(root)
                    if should_skip(rel):
                        continue
                    if path.stat().st_size > MAX_BYTES:
                        continue
                except OSError:
                    continue
                text = read_text(path)
                markers = (
                    "function", "contract ", "library ", "\ndef ", "\nfn ", " fun ",
                    "pub fn", "module ", "mod ", "struct ",
                )
                if not any(tok in text for tok in markers):
                    continue
                rel_s = rel.as_posix()
                rows.append({
                    "rel": rel_s,
                    "text": text,
                    "ext": ext,
                    "contracts": contracts_for(text, ext, path.stem),
                    "functions": parse_functions(text, ext),
                    "risk": risk_lines(text),
                    "score": score_file(rel_s, text, ext),
                })
                if len(rows) >= MAX_FILES * 2:
                    break
            if len(rows) >= MAX_FILES * 2:
                break
    except OSError:
        return []
    rows.sort(key=lambda r: (-int(r["score"]), str(r["rel"])))
    return rows[:MAX_FILES]


def line_at(text: str, offset: int) -> int:
    return 1 if offset < 0 else text.count("\n", 0, offset) + 1


def compact_source(text: str, limit: int) -> str:
    """Keep function/risk neighborhoods so large files stay informative."""
    if len(text) <= limit:
        return text
    lines = text.splitlines()
    important: set[int] = set()
    terms = tuple(w.lower() for w in RISK_WORDS)
    for idx, line in enumerate(lines):
        low = line.lower()
        if DEF_LINE_RE.search(line) or any(t in low for t in terms):
            for j in range(max(0, idx - 4), min(len(lines), idx + 16)):
                important.add(j)
    if not important:
        return text[:limit]
    out: list[str] = []
    last = -3
    size = 0
    for idx in sorted(important):
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


def repo_map(records: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    for rec in records:
        parts.append(json.dumps({
            "file": rec["rel"],
            "kind": rec["ext"].lstrip("."),
            "score": rec["score"],
            "contracts": rec["contracts"][:6],
            "functions": [f"{f['line']}:{f['sig']}" for f in rec["functions"][:20]],
            "risk_lines": rec["risk"][:12],
        }, separators=(",", ":")))
    return "\n".join(parts)[:MAP_CHARS]


def infer(api: str | None, messages: list[dict[str, str]], max_tokens: int, started: float) -> str:
    if not time_left(started, 5):
        return ""
    endpoint = (api or os.environ.get("INFERENCE_API") or "").rstrip("/")
    if not endpoint:
        return ""
    remaining = max(8.0, RUN_CAP - (time.monotonic() - started) - 8.0)
    timeout = min(HTTP_TIMEOUT, int(remaining))
    body = json.dumps({
        "model": MODEL,
        "temperature": 0.05,
        "messages": messages,
        "max_tokens": max_tokens,
    }).encode()
    headers = {
        "Content-Type": "application/json",
        "x-inference-api-key": os.environ.get("INFERENCE_API_KEY", ""),
    }
    for attempt in range(2):
        if not time_left(started, 5):
            return ""
        try:
            req = urllib.request.Request(
                endpoint + "/inference", data=body, method="POST", headers=headers,
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return pull_text(json.loads(resp.read().decode("utf-8", "replace")))
        except urllib.error.HTTPError as exc:
            if exc.code in {429, 503}:
                return ""
            if attempt == 0:
                time.sleep(0.4)
        except (OSError, TimeoutError, ValueError):
            if attempt == 0:
                time.sleep(0.4)
    return ""


def pull_text(payload: dict[str, Any]) -> str:
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


def load_json(text: str) -> dict[str, Any]:
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
        "Review this repository map. (1) Pick the highest-yield files to deep-audit. "
        "(2) Report every REAL high/critical bug already justified by signatures and "
        "risk lines.\n"
        + PRIORITIES
        + "\nReturn strict JSON:\n"
        '{"target_files":["path"],"findings":[{"title":"Contract.function - bug","file":"path",'
        '"contract":"Name","function":"fn","line":1,"severity":"high|critical","type":"logic",'
        '"mechanism":"pre -> attack -> effect","impact":"harm","description":"2-4 sentences"}]}\n\n'
        + repo_map(records)
    )
    obj = load_json(infer(
        api,
        [{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt}],
        5000,
        started,
    ))
    targets = obj.get("target_files")
    items = obj.get("findings") or obj.get("vulnerabilities") or []
    return (
        [str(x) for x in targets if isinstance(x, str)] if isinstance(targets, list) else [],
        [x for x in items if isinstance(x, dict)] if isinstance(items, list) else [],
    )


def order_targets(targets: list[str], records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for target in targets:
        tl = target.lower().strip()
        for rec in records:
            rl = str(rec["rel"]).lower()
            if tl == rl or rl.endswith(tl) or tl.endswith(rl):
                if rec not in out:
                    out.append(rec)
                break
    for rec in records:
        if rec not in out:
            out.append(rec)
    return out


def related_context(rec: dict[str, Any], by_name: dict[str, dict[str, Any]]) -> str:
    chunks: list[str] = []
    for imp in IMPORT_RE.findall(str(rec["text"])):
        name = imp.rsplit("/", 1)[-1].rsplit("::", 1)[-1]
        other = (
            by_name.get(name)
            or by_name.get(name + ".sol")
            or by_name.get(name + ".rs")
            or by_name.get(name + ".move")
        )
        if other and other["rel"] != rec["rel"]:
            chunks.append(f"\n--- RELATED {other['rel']} ---\n{str(other['text'])[:RELATED_CHARS]}")
        if len(chunks) >= 2:
            break
    return "".join(chunks)


def audit_batch(
    api: str | None,
    batch: list[dict[str, Any]],
    by_name: dict[str, dict[str, Any]],
    started: float,
    *,
    per_file: int,
    budget: int,
    mode: str,
    compact: bool = False,
) -> list[dict[str, Any]]:
    if not batch:
        return []
    header = (
        f"Audit mode={mode}. {PRIORITIES}\n"
        "Return strict JSON:\n"
        '{"findings":[{"title":"Contract.function - bug","file":"path","contract":"C",'
        '"function":"fn","line":1,"severity":"high|critical","type":"logic",'
        '"mechanism":"pre->attack->effect","impact":"harm",'
        '"description":"2-5 sentences with exploit path"}]}\n'
        "Max 6 findings. Name real functions. Omit weak speculation.\n"
    )
    parts, room = [header], budget - len(header)
    for rec in batch:
        text = str(rec["text"])
        body = compact_source(text, per_file) if compact else text[:per_file]
        sigs = [f"{f['line']}:{f['sig']}" for f in rec["functions"][:24]]
        block = (
            f"\n\n=== {rec['rel']} ===\nContracts: {', '.join(rec['contracts'][:8])}\n"
            f"Functions: {json.dumps(sigs)}\nRisk: {json.dumps(rec['risk'][:12])}\n"
            f"{body}\n{related_context(rec, by_name)}\n"
        )
        if room <= 0:
            break
        if len(block) > room:
            block = block[:room] + "\n/* truncated */\n"
        parts.append(block)
        room -= len(block)
    obj = load_json(infer(
        api,
        [{"role": "system", "content": SYSTEM}, {"role": "user", "content": "".join(parts)}],
        7000,
        started,
    ))
    items = obj.get("findings") or obj.get("vulnerabilities") or []
    return [x for x in items if isinstance(x, dict)] if isinstance(items, list) else []


def make_probe(
    rec: dict[str, Any],
    title: str,
    kind: str,
    mechanism: str,
    impact: str,
    *,
    function: str = "",
    line: int | None = None,
) -> dict[str, Any]:
    contract = str(rec["contracts"][0]) if rec.get("contracts") else Path(str(rec["rel"])).stem
    return {
        "title": title,
        "file": rec["rel"],
        "contract": contract,
        "function": function,
        "line": line,
        "severity": "high",
        "type": kind,
        "mechanism": mechanism,
        "impact": impact,
        "description": (
            f"In `{rec['rel']}`"
            + (f", function `{function}`" if function else "")
            + f". Mechanism: {mechanism.rstrip('.')}. Impact: {impact.rstrip('.')}."
        ),
    }


def function_slices(text: str) -> list[dict[str, Any]]:
    matches = list(FUNC_SOL.finditer(text))
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


def structural_probes(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """High-precision Solidity smell detectors — supplements, not a report bank."""
    hits: list[dict[str, Any]] = []
    for rec in records:
        if rec["ext"] != ".sol":
            continue
        text = str(rec["text"])
        low = text.lower()
        if "contract " not in low and "library " not in low:
            continue

        if "function initialize" in low and not any(
            x in low for x in ("initializer", "onlyowner", "onlyrole", "_disableinitializers")
        ):
            fnames = {f["name"] for f in rec["functions"]}
            hits.append(make_probe(
                rec,
                "Unprotected initializer",
                "access-control",
                "The initialize entrypoint is externally reachable without a one-time "
                "initializer modifier or owner/role gate.",
                "An attacker can seize ownership or critical configuration on first call.",
                function="initialize" if "initialize" in fnames else "",
            ))

        if "tx.origin" in low and any(x in low for x in ("require", "if ", "assert", "revert")):
            hits.append(make_probe(
                rec,
                "Authorization relies on tx.origin",
                "access-control",
                "A security branch authenticates with tx.origin rather than msg.sender.",
                "Phishing contracts can bypass checks and act as the victim.",
                line=line_at(text, low.find("tx.origin")),
            ))

        for fn in function_slices(text):
            body, sig = fn["body"].lower(), fn["sig"].lower()
            name = fn["name"]
            if "delegatecall" in body and ("external" in sig or "public" in sig):
                if not any(g in sig + body for g in ("onlyowner", "onlyrole", "requiresauth")):
                    hits.append(make_probe(
                        rec,
                        "Unprotected delegatecall in external entrypoint",
                        "access-control",
                        "An external function performs delegatecall without a hard "
                        "owner/role gate.",
                        "Callers can execute attacker logic in the contract storage context.",
                        function=name,
                        line=fn["line"],
                    ))
            if ("external" in sig or "public" in sig) and "nonreentrant" not in sig + body:
                call_m = re.search(r"\.call\s*\{|\.call\(|transfer\(|safetransfer", body)
                write_m = re.search(r"\b(balances?|shares?|deposits?|allowances?|total)\b.*=", body)
                if call_m and write_m and call_m.start() < write_m.start():
                    hits.append(make_probe(
                        rec,
                        "External call before state update enables reentrancy",
                        "reentrancy",
                        "The function performs an external call/transfer before updating "
                        "balances/shares and has no reentrancy guard.",
                        "A malicious receiver can re-enter and drain funds against "
                        "stale accounting.",
                        function=name,
                        line=fn["line"],
                    ))
            if ("ecrecover" in body or "recover(" in body) and not any(
                x in body + sig for x in ("nonce", "deadline", "block.timestamp", "chainid")
            ):
                if "external" in sig or "public" in sig:
                    hits.append(make_probe(
                        rec,
                        "Signature path lacks replay / freshness binding",
                        "signature",
                        "Signature recovery accepts a signer without nonce, deadline, "
                        "or chain id binding.",
                        "Valid signatures can be replayed across time or deployments.",
                        function=name,
                        line=fn["line"],
                    ))
        if len(hits) >= 8:
            break
    return hits[:8]


def match_file(
    file_value: str,
    rel_map: dict[str, dict[str, Any]],
) -> tuple[str | None, dict[str, Any] | None]:
    low = file_value.lower().strip().strip("`")
    if not low:
        return None, None
    for rel, rec in rel_map.items():
        rl = rel.lower()
        if low == rl or rl.endswith(low) or low.endswith(rl):
            return rel, rec
    base = Path(low).name
    if base:
        hits = [(rel, rec) for rel, rec in rel_map.items() if Path(rel).name.lower() == base]
        if len(hits) == 1:
            return hits[0]
    return None, None


def normalize(raw: dict[str, Any], rel_map: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    rel, rec = match_file(str(raw.get("file") or raw.get("path") or ""), rel_map)
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
    valid = {str(f["name"]) for f in rec["functions"]}
    if fn and fn not in valid:
        fn = ""
    contract = str(raw.get("contract") or raw.get("module") or "").strip().strip("`")
    if not contract and rec["contracts"]:
        contract = str(rec["contracts"][0])
    elif contract and rec["contracts"] and contract not in rec["contracts"]:
        contract = str(rec["contracts"][0])
    mech = clean(raw.get("mechanism"))
    impact = clean(raw.get("impact"))
    desc = clean(raw.get("description"))
    title = clean(raw.get("title")) or f"{contract}.{fn or 'logic'} - high-impact bug"
    if len(mech) < 20 and len(desc) < 100:
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
    if len(rebuilt) < 110:
        return None
    line = raw.get("line")
    if not isinstance(line, int) and fn:
        for needle in (f"function {fn}", f"def {fn}", f"fn {fn}", f"fun {fn}"):
            idx = str(rec["text"]).find(needle)
            if idx >= 0:
                line = line_at(str(rec["text"]), idx)
                break
    base = rel.rsplit("/", 1)[-1]
    loc = f" Affected location: `{rel}`, `{base}`" + (f", `{fn}()`" if fn else "") + "."
    if loc.strip() not in rebuilt:
        rebuilt += loc
    return {
        "title": title[:220],
        "description": rebuilt[:3000],
        "severity": sev,
        "file": rel,
        "function": fn,
        "line": line if isinstance(line, int) else None,
        "type": str(raw.get("type") or "logic"),
        "confidence": 0.9 if sev == "critical" else 0.84,
    }


def clean(value: object) -> str:
    return " ".join(str(value or "").strip().split())


def dedupe(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
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
            str(item.get("title") or "").lower()[:100],
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
        if len(out) >= MAX_FINDINGS:
            break
    return out


if __name__ == "__main__":
    import sys
    print(json.dumps(agent_main(sys.argv[1] if len(sys.argv) > 1 else None), indent=2))
