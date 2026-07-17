from __future__ import annotations

"""SN60 miner for Phala TEE: risk-ranked map triage + dual deep audits.

Tuned for the post-reset rules: miner-paid inference, 840s process budget,
180s per gateway call. Static heuristics only rank files; all findings come
from LLM reasoning over source (no canned reports / fingerprint branches).
"""

import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

EXTS = (".sol", ".vy", ".cairo")
MAX_FILES = 70
MAX_BYTES = 320_000
MAP_CHARS = 20_000
AUDIT_CHARS = 48_000
RELATED_CHARS = 4_000
MAX_FINDINGS = 10
RUN_CAP = 780.0
HTTP_TIMEOUT = 195
MAX_CALLS = 3
# Must match a live Chutes model id (see https://llm.chutes.ai/v1/models).
MODEL = os.environ.get("KATA_MINER_MODEL", "zai-org/GLM-5.2-TEE")

SKIP_DIRS = frozenset({
    ".git", ".github", ".venv", "artifacts", "broadcast", "cache", "coverage", "dist",
    "docs", "example", "examples", "lib", "node_modules", "out", "script", "scripts",
    "target", "test", "tests", "vendor", "interfaces", "mock", "mocks",
})

RISK_WORDS = (
    "withdraw", "redeem", "borrow", "repay", "liquidat", "claim", "stake", "unstake",
    "deposit", "mint", "burn", "swap", "bridge", "permit", "delegatecall", "call{",
    ".call", "assembly", "unchecked", "tx.origin", "selfdestruct", "upgrade",
    "initialize", "onlyowner", "onlyrole", "oracle", "price", "share", "ratio",
    "rounding", "fee", "collateral", "solvency", "signature", "ecrecover", "nonce",
    "reentr", "slippage", "flash", "transferfrom",
)
NAME_WORDS = (
    "vault", "pool", "router", "manager", "controller", "strategy", "market", "oracle",
    "bridge", "staking", "reward", "treasury", "govern", "proxy", "liquidat", "borrow",
    "token", "perp", "position", "lending", "escrow", "auction",
)

FUNC_SOL = re.compile(
    r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*([^{};]*)(?:;|\{)",
    re.MULTILINE,
)
FUNC_VY = re.compile(r"^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", re.MULTILINE)
FUNC_CAIRO = re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*[<(]", re.MULTILINE)
CONTRACT_SOL = re.compile(
    r"^\s*(?:abstract\s+contract|contract|library|interface)\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
CONTRACT_CAIRO = re.compile(
    r"^\s*(?:#\[starknet::contract\]\s*)?(?:mod|impl|trait)\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
IMPORT_RE = re.compile(r'^\s*import\b[^;{]*?["\']([^"\']+)["\']', re.MULTILINE)

SYSTEM = (
    "You are a senior smart-contract auditor. Return only exploitable high or critical "
    "issues with concrete attacker steps and material impact. Ignore gas, style, events, "
    "and speculation. Return strict JSON only."
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
        targets, mapped = map_repo(inference_api, records, started)
        raw.extend(mapped)
        calls = 1

        ordered = order_records(targets, records)
        first = ordered[:3]
        second = diverse_batch(ordered, first)

        if time_left(started, 200) and calls < MAX_CALLS:
            raw.extend(audit_batch(inference_api, first, by_name, started, mode="critical-path"))
            calls += 1
        if time_left(started, 200) and calls < MAX_CALLS:
            raw.extend(audit_batch(inference_api, second, by_name, started, mode="cross-contract"))

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
            p = Path(raw).expanduser().resolve()
        except (OSError, RuntimeError):
            continue
        if p.is_dir() and has_sources(p):
            return p
    return None


def has_sources(root: Path) -> bool:
    try:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d.lower() not in SKIP_DIRS and not d.startswith(".")]
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
    return name.endswith((".t.sol", ".s.sol", "_test.sol", ".test.sol"))


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def parse_functions(text: str, ext: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    patterns = [FUNC_SOL]
    if ext == ".vy":
        patterns = [FUNC_VY]
    elif ext == ".cairo":
        patterns = [FUNC_CAIRO, FUNC_SOL]
    for pat in patterns:
        for m in pat.finditer(text):
            name = m.group(1)
            start = text.count("\n", 0, m.start()) + 1
            sig = " ".join(m.group(0).strip().split())
            out.append({"name": name, "line": start, "sig": sig[:180]})
    return out


def contracts_for(text: str, ext: str, stem: str) -> list[str]:
    found = CONTRACT_SOL.findall(text)
    if ext == ".cairo":
        found.extend(CONTRACT_CAIRO.findall(text))
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
            c = " ".join(line.strip().split())
            if c:
                lines.append(f"{num}: {c[:170]}")
        if len(lines) >= 16:
            break
    return lines


def score_file(rel: str, text: str, ext: str) -> int:
    ln, body = rel.lower(), text.lower()
    compact = body.replace(" ", "")
    s = min(body.count("function ") + body.count("\ndef ") + body.count(" fn "), 40)
    for w in NAME_WORDS:
        if w in ln:
            s += 9
        elif w in body:
            s += 2
    for w in RISK_WORDS:
        if w in compact:
            s += 3
    if "external" in body or "public" in body or "#[external" in body:
        s += 6
    if "nonreentrant" not in body and (".call" in body or "call{" in compact):
        s += 5
    if "delegatecall" in compact:
        s += 8
    if "tx.origin" in compact:
        s += 6
    if ext == ".cairo":
        s += 3
    if "interface" in ln or "interface" in body[:200].lower():
        s -= 6
    return s


def discover(root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d.lower() not in SKIP_DIRS and not d.startswith(".")]
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
                if not any(tok in text for tok in ("function", "contract ", "library ", "\ndef ", " fn ")):
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


def repo_map(records: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    for rec in records:
        parts.append(json.dumps({
            "file": rec["rel"],
            "kind": rec["ext"].lstrip("."),
            "score": rec["score"],
            "contracts": rec["contracts"][:6],
            "functions": [f"{f['line']}:{f['sig']}" for f in rec["functions"][:22]],
            "risk_lines": rec["risk"][:12],
        }, separators=(",", ":")))
    return "\n".join(parts)[:MAP_CHARS]


def infer(api: str | None, messages: list[dict[str, str]], max_tokens: int, started: float) -> str:
    if not time_left(started, 5):
        return ""
    endpoint = (api or os.environ.get("INFERENCE_API") or "").rstrip("/")
    if not endpoint:
        return ""
    body = json.dumps({
        "model": MODEL,
        "temperature": 0.1,
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
            req = urllib.request.Request(endpoint + "/inference", data=body, method="POST", headers=headers)
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                return pull_text(json.loads(resp.read().decode("utf-8", "replace")))
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                return ""
        except (OSError, TimeoutError, ValueError):
            pass
        if attempt == 0:
            time.sleep(0.6)
    return ""


def pull_text(payload: dict[str, Any]) -> str:
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        return ""
    msg = choices[0].get("message") if isinstance(choices[0], dict) else None
    if not isinstance(msg, dict):
        return ""
    content = msg.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(str(p.get("text") or "") for p in content if isinstance(p, dict))
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


def map_repo(
    api: str | None,
    records: list[dict[str, Any]],
    started: float,
) -> tuple[list[str], list[dict[str, Any]]]:
    prompt = (
        "Analyze this repository map. Pick files with exploitable high/critical bugs.\n"
        '{"target_files":["path"],"findings":[{"title":"bug","file":"path","contract":"Name",'
        '"function":"fn","line":1,"severity":"high|critical","type":"logic",'
        '"mechanism":"pre -> attack -> effect","impact":"harm","description":"2-4 sentences"}]}\n'
        "Prioritize value movement, accounting, access control, oracle, signatures, liquidation.\n\n"
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


def order_records(targets: list[str], records: list[dict[str, Any]]) -> list[dict[str, Any]]:
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


def diverse_batch(ordered: list[dict[str, Any]], first: list[dict[str, Any]]) -> list[dict[str, Any]]:
    chosen: list[dict[str, Any]] = []
    used = {str(Path(r["rel"]).parent) for r in first}
    for rec in ordered:
        if rec in first:
            continue
        parent = str(Path(rec["rel"]).parent)
        if parent not in used or len(chosen) < 2:
            chosen.append(rec)
            used.add(parent)
        if len(chosen) >= 4:
            break
    for rec in ordered:
        if rec not in first and rec not in chosen:
            chosen.append(rec)
        if len(chosen) >= 4:
            break
    return chosen


def related_context(rec: dict[str, Any], by_name: dict[str, dict[str, Any]]) -> str:
    chunks: list[str] = []
    for imp in IMPORT_RE.findall(str(rec["text"])):
        name = imp.rsplit("/", 1)[-1]
        other = by_name.get(name)
        if other and other["rel"] != rec["rel"]:
            chunks.append(f"\n--- RELATED {other['rel']} ---\n{str(other['text'])[:RELATED_CHARS]}")
        if len(chunks) >= 2:
            break
    return "".join(chunks)


def audit_prompt(batch: list[dict[str, Any]], by_name: dict[str, dict[str, Any]], mode: str) -> str:
    header = (
        f"Deep audit ({mode}). Return strict JSON:\n"
        '{"findings":[{"title":"Contract.function - bug","file":"path","contract":"C","function":"fn",'
        '"line":1,"severity":"high|critical","type":"logic","mechanism":"pre->attack->effect",'
        '"impact":"harm","description":"2-5 sentences with exploit path"}]}\n'
        "Max 5 findings. Name real functions from the source. Focus on access control, reentrancy, "
        "oracle/price manipulation, share/accounting inflation, signature replay, init/upgrade, "
        "liquidation, and unprotected privileged calls.\n"
    )
    parts, room = [header], AUDIT_CHARS - len(header)
    for rec in batch:
        sigs = [f"{f['line']}:{f['sig']}" for f in rec["functions"][:24]]
        block = (
            f"\n\n=== {rec['rel']} ===\nContracts: {', '.join(rec['contracts'][:6])}\n"
            f"Functions: {json.dumps(sigs)}\nRisk: {json.dumps(rec['risk'][:12])}\n"
            f"{rec['text']}\n{related_context(rec, by_name)}\n"
        )
        if room <= 0:
            break
        if len(block) > room:
            block = block[:room] + "\n/* truncated */\n"
        parts.append(block)
        room -= len(block)
    return "".join(parts)


def audit_batch(
    api: str | None,
    batch: list[dict[str, Any]],
    by_name: dict[str, dict[str, Any]],
    started: float,
    *,
    mode: str,
) -> list[dict[str, Any]]:
    if not batch:
        return []
    obj = load_json(infer(
        api,
        [{"role": "system", "content": SYSTEM}, {"role": "user", "content": audit_prompt(batch, by_name, mode)}],
        7000,
        started,
    ))
    items = obj.get("findings") or obj.get("vulnerabilities") or []
    return [x for x in items if isinstance(x, dict)] if isinstance(items, list) else []


def match_file(file_value: str, rel_map: dict[str, dict[str, Any]]) -> tuple[str | None, dict[str, Any] | None]:
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
    valid = {str(f["name"]) for f in rec["functions"]}
    if fn and fn not in valid:
        fn = ""
    contract = str(raw.get("contract") or "").strip().strip("`")
    if not contract and rec["contracts"]:
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
    if len(rebuilt) < 100:
        return None
    line = raw.get("line")
    if not isinstance(line, int) and fn:
        for needle in (f"function {fn}", f"def {fn}", f"fn {fn}"):
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
        "confidence": 0.9 if sev == "critical" else 0.85,
    }


def clean(value: object) -> str:
    return " ".join(str(value or "").strip().split())


def dedupe(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str]] = set()
    out: list[dict[str, Any]] = []
    for item in sorted(
        items,
        key=lambda f: (f.get("severity") == "critical", float(f.get("confidence") or 0), len(str(f.get("description")))),
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
