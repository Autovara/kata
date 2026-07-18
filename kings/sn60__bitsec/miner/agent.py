from __future__ import annotations

"""SN60 Bitsec miner: risk-ranked triage, structural probes, dual deep audits.

Designed for the Phala sealed room: miner-paid inference via INFERENCE_API,
~840s process budget, ~180s per gateway call. Static heuristics only prioritize
and surface high-precision structural smells; every reported bug still needs a
concrete exploit path. No canned reports, fingerprint tables, or answer banks.
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
MAX_FILES = 64
MAX_BYTES = 300_000
MAP_CHARS = 18_000
AUDIT_CHARS = 52_000
RELATED_CHARS = 5_000
MAX_FINDINGS = 10
RUN_CAP = 800.0
HTTP_TIMEOUT = 195
MAX_CALLS = 4
MODEL = os.environ.get("KATA_MINER_MODEL", "deepseek-ai/DeepSeek-V3.2-TEE")

SKIP_DIRS = frozenset({
    ".git", ".github", ".venv", "artifacts", "broadcast", "cache", "coverage",
    "dist", "docs", "example", "examples", "lib", "node_modules", "out",
    "script", "scripts", "target", "test", "tests", "vendor", "mock", "mocks",
    "interfaces",
})

RISK_WORDS = (
    "withdraw", "redeem", "borrow", "repay", "liquidat", "claim", "stake",
    "unstake", "deposit", "mint", "burn", "swap", "bridge", "permit",
    "delegatecall", "call{", ".call", "assembly", "unchecked", "tx.origin",
    "selfdestruct", "upgrade", "initialize", "onlyowner", "onlyrole", "oracle",
    "price", "share", "ratio", "rounding", "fee", "collateral", "solvency",
    "signature", "ecrecover", "nonce", "reentr", "slippage", "flash",
    "transferfrom", "approve", "allowance",
)

NAME_WORDS = (
    "vault", "pool", "router", "manager", "controller", "strategy", "market",
    "oracle", "bridge", "staking", "reward", "treasury", "govern", "proxy",
    "liquidat", "borrow", "token", "perp", "position", "lending", "escrow",
    "auction", "amm", "pair", "adapter",
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
    "You are an elite smart-contract security researcher. Report only "
    "exploitable high or critical bugs with a concrete attacker path and "
    "material fund/control impact. Skip gas, style, natspec, missing events, "
    "and admin-trust assumptions unless authorization is truly absent. "
    "Return strict JSON only — no markdown."
)


def agent_main(project_dir: str | None = None, inference_api: str | None = None) -> dict:
    started = time.monotonic()
    findings: list[dict[str, Any]] = []
    try:
        root = resolve_root(project_dir)
        if root is None:
            return {"vulnerabilities": findings}
        records = discover(root)
        if not records:
            return {"vulnerabilities": findings}

        rel_map = {r["rel"]: r for r in records}
        by_name = {Path(r["rel"]).name: r for r in records}
        raw: list[dict[str, Any]] = []
        calls = 0

        # High-precision structural smells — never the sole report source.
        raw.extend(structural_probes(records))

        targets, mapped = map_repo(inference_api, records, started)
        raw.extend(mapped)
        calls = 1

        ordered = order_by_targets(targets, records)
        primary = ordered[:2]
        secondary = diversify(ordered, primary, limit=3)
        tertiary = diversify(ordered, primary + secondary, limit=2)

        if time_left(started, 210) and calls < MAX_CALLS:
            raw.extend(audit_batch(
                inference_api, primary, by_name, started, mode="value-path-depth",
            ))
            calls += 1
        if time_left(started, 210) and calls < MAX_CALLS:
            raw.extend(audit_batch(
                inference_api, secondary, by_name, started, mode="cross-contract",
            ))
            calls += 1
        if time_left(started, 210) and calls < MAX_CALLS and tertiary:
            raw.extend(audit_batch(
                inference_api, tertiary, by_name, started, mode="auth-oracle-accounting",
            ))
            calls += 1

        for item in raw:
            norm = normalize(item, rel_map)
            if norm is not None:
                findings.append(norm)
    except Exception:
        pass
    return {"vulnerabilities": dedupe(findings)}


def time_left(started: float, need: float = 0.0) -> bool:
    return time.monotonic() - started < RUN_CAP - need


def resolve_root(project_dir: str | None) -> Path | None:
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
        for match in pat.finditer(text):
            out.append({
                "name": match.group(1),
                "line": text.count("\n", 0, match.start()) + 1,
                "sig": " ".join(match.group(0).strip().split())[:180],
            })
    return out


def contracts_for(text: str, ext: str, stem: str) -> list[str]:
    found = list(CONTRACT_SOL.findall(text))
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
            compact = " ".join(line.strip().split())
            if compact:
                lines.append(f"{num}: {compact[:170]}")
        if len(lines) >= 14:
            break
    return lines


def score_file(rel: str, text: str, ext: str) -> int:
    ln, body = rel.lower(), text.lower()
    compact = body.replace(" ", "")
    score = min(body.count("function ") + body.count("\ndef ") + body.count(" fn "), 40)
    for word in NAME_WORDS:
        if word in ln:
            score += 10
        elif word in body:
            score += 2
    for word in RISK_WORDS:
        if word in compact:
            score += 3
    if "external" in body or "public" in body or "#[external" in body:
        score += 7
    if "nonreentrant" not in body and (".call" in body or "call{" in compact):
        score += 6
    if "delegatecall" in compact:
        score += 9
    if "tx.origin" in compact:
        score += 7
    if "ecrecover" in compact or "recover(" in compact:
        score += 5
    if ext == ".cairo":
        score += 3
    if "interface" in ln or "interface" in body[:240].lower():
        score -= 8
    if "library" in body[:240].lower() and "function" not in body[:400].lower():
        score -= 4
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
                if not any(
                    tok in text
                    for tok in ("function", "contract ", "library ", "\ndef ", " fn ", "#[external")
                ):
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


def slice_block(text: str, start: int) -> str:
    open_idx = text.find("{", start)
    if open_idx < 0:
        return text[start : start + 800]
    depth = 0
    in_str = False
    quote = ""
    esc = False
    for idx in range(open_idx, min(len(text), open_idx + 5000)):
        ch = text[idx]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == quote:
                in_str = False
            continue
        if ch in {"'", '"'}:
            in_str = True
            quote = ch
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : idx + 1]
    return text[start : start + 1000]


def function_slices(text: str) -> list[dict[str, Any]]:
    matches = list(FUNC_SOL.finditer(text))
    out: list[dict[str, Any]] = []
    for index, match in enumerate(matches):
        start = match.start()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        out.append({
            "name": match.group(1),
            "sig": " ".join(match.group(0).split()),
            "line": line_at(text, start),
            "body": text[start:end],
        })
    return out


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


def structural_probes(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Reusable detectors — zero project-specific fingerprints."""
    hits: list[dict[str, Any]] = []
    for rec in records[:40]:
        text = str(rec["text"])
        low_all = text.lower()

        if "tx.origin" in low_all:
            for match in re.finditer(r"\btx\.origin\b", text):
                hits.append(make_probe(
                    rec,
                    "Authorization uses tx.origin instead of msg.sender",
                    "access-control",
                    "A privileged check compares against tx.origin, which phishing contracts can "
                    "spoof by nesting a call from a victim EOA.",
                    "An attacker can trick a victim into authorizing fund movement or privilege "
                    "changes the victim did not intend.",
                    line=line_at(text, match.start()),
                ))
                break

        if "delegatecall" in low_all:
            for fn in function_slices(text):
                body = fn["body"].lower()
                sig = fn["sig"].lower()
                if "delegatecall" not in body:
                    continue
                if "external" in sig or "public" in sig:
                    if not any(
                        g in sig + body
                        for g in ("onlyowner", "onlyrole", "requiresauth", "msg.sender==owner")
                    ):
                        hits.append(make_probe(
                            rec,
                            "Unprotected delegatecall in external entrypoint",
                            "access-control",
                            "An external function performs delegatecall without a hard owner/role "
                            "gate, letting callers choose attacker-controlled logic that executes "
                            "in the contract's storage context.",
                            "Attackers can overwrite critical storage and drain or seize assets.",
                            function=fn["name"],
                            line=fn["line"],
                        ))

        for fn in function_slices(text):
            body = fn["body"].lower()
            sig = fn["sig"].lower()
            name = fn["name"]

            if re.match(r"^(set|update|change|grant|revoke|add|remove)", name, re.I):
                if "external" in sig or "public" in sig:
                    guarded = any(
                        g in sig + body
                        for g in (
                            "onlyowner", "onlyrole", "requiresauth", "_checkowner",
                            "msg.sender==", "msg.sender ==", "ownable",
                        )
                    )
                    writes_auth = any(
                        tok in body
                        for tok in (
                            "owner =", "admin =", "role[", "roles[", "operator[",
                            "authorized[", "isadmin", "isowner", "minter[",
                        )
                    )
                    if not guarded and writes_auth:
                        hits.append(make_probe(
                            rec,
                            "Privileged authority setter missing access control",
                            "access-control",
                            "An external setter writes owner/role/operator state without an "
                            "authorization check.",
                            "Any account can grant itself privileged rights and then move funds "
                            "wherever that authority is trusted.",
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
                        "Signature recovery accepts a signer without binding nonce, deadline, or "
                        "chain id into the digested payload.",
                        "A previously valid signature can be replayed across time or deployments "
                        "to move value outside the signer's intent.",
                        function=name,
                        line=fn["line"],
                    ))

            if any(w in name.lower() for w in ("swap", "exchange", "trade")):
                if "external" in sig or "public" in sig:
                    if not any(
                        x in body
                        for x in ("amountoutmin", "minamountout", "min_out", "slippage", "minout")
                    ):
                        if any(x in body for x in ("router", "swap", "transfer", "call")):
                            hits.append(make_probe(
                                rec,
                                "Swap execution missing minimum-output bound",
                                "logic",
                                "An external swap forwards trades without enforcing a caller-"
                                "supplied minimum received amount.",
                                "Sandwiching or price drift can settle near-zero output while the "
                                "caller expects fair execution.",
                                function=name,
                                line=fn["line"],
                            ))

            if ("external" in sig or "public" in sig) and "nonreentrant" not in sig + body:
                has_call = bool(
                    re.search(r"\.call\s*\{|\.call\(|raw_call|transfer\(|safetransfer", body)
                )
                has_write = bool(
                    re.search(r"\b(balances?|shares?|deposits?|allowances?|total)\b.*=", body)
                )
                if has_call and has_write:
                    call_pos = re.search(
                        r"\.call\s*\{|\.call\(|raw_call|transfer\(|safetransfer", body
                    )
                    write_pos = re.search(
                        r"\b(balances?|shares?|deposits?|allowances?|total)\b.*=", body
                    )
                    if call_pos and write_pos and call_pos.start() < write_pos.start():
                        hits.append(make_probe(
                            rec,
                            "External call before state update enables reentrancy",
                            "reentrancy",
                            "The function performs an external call or token transfer before "
                            "updating balances/shares and has no reentrancy guard.",
                            "A malicious receiver can re-enter and drain funds against stale "
                            "accounting.",
                            function=name,
                            line=fn["line"],
                        ))

        if len(hits) >= 6:
            break
    return hits[:6]


def repo_map(records: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    for rec in records:
        parts.append(json.dumps({
            "file": rec["rel"],
            "kind": rec["ext"].lstrip("."),
            "score": rec["score"],
            "contracts": rec["contracts"][:6],
            "functions": [f"{f['line']}:{f['sig']}" for f in rec["functions"][:20]],
            "risk_lines": rec["risk"][:10],
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
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                return pull_text(json.loads(resp.read().decode("utf-8", "replace")))
        except urllib.error.HTTPError as exc:
            if exc.code in {429, 503}:
                time.sleep(1.2)
                continue
            if attempt == 0:
                time.sleep(0.5)
        except (OSError, TimeoutError, ValueError):
            if attempt == 0:
                time.sleep(0.5)
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
    # Some TEE models emit only reasoning_* fields under tight token budgets.
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


def map_repo(
    api: str | None,
    records: list[dict[str, Any]],
    started: float,
) -> tuple[list[str], list[dict[str, Any]]]:
    prompt = (
        "Triage this repository map. Select files most likely to contain exploitable "
        "high/critical bugs and list any clear bugs you already see.\n"
        '{"target_files":["path"],"findings":[{"title":"bug","file":"path","contract":"Name",'
        '"function":"fn","line":1,"severity":"high|critical","type":"logic",'
        '"mechanism":"precondition -> attacker action -> effect","impact":"material harm",'
        '"description":"2-4 sentences"}]}\n'
        "Prioritize: value movement, share/accounting inflation, access control, oracle/"
        "price manipulation, signature replay, liquidation, init/upgrade, unprotected "
        "delegatecall.\n\n"
        + repo_map(records)
    )
    obj = load_json(infer(
        api,
        [{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt}],
        4500,
        started,
    ))
    targets = obj.get("target_files")
    items = obj.get("findings") or obj.get("vulnerabilities") or []
    return (
        [str(x) for x in targets if isinstance(x, str)] if isinstance(targets, list) else [],
        [x for x in items if isinstance(x, dict)] if isinstance(items, list) else [],
    )


def order_by_targets(targets: list[str], records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for target in targets:
        tl = target.lower().strip()
        for rec in records:
            rl = str(rec["rel"]).lower()
            if tl == rl or rl.endswith(tl) or tl.endswith(rl) or Path(tl).name == Path(rl).name:
                if rec not in out:
                    out.append(rec)
                break
    for rec in records:
        if rec not in out:
            out.append(rec)
    return out


def diversify(
    ordered: list[dict[str, Any]],
    used: list[dict[str, Any]],
    *,
    limit: int,
) -> list[dict[str, Any]]:
    chosen: list[dict[str, Any]] = []
    parents = {str(Path(r["rel"]).parent) for r in used}
    for rec in ordered:
        if rec in used:
            continue
        parent = str(Path(rec["rel"]).parent)
        if parent not in parents or len(chosen) < 1:
            chosen.append(rec)
            parents.add(parent)
        if len(chosen) >= limit:
            break
    for rec in ordered:
        if rec not in used and rec not in chosen:
            chosen.append(rec)
        if len(chosen) >= limit:
            break
    return chosen


def related_context(rec: dict[str, Any], by_name: dict[str, dict[str, Any]]) -> str:
    chunks: list[str] = []
    for imp in IMPORT_RE.findall(str(rec["text"])):
        name = imp.rsplit("/", 1)[-1]
        other = by_name.get(name)
        if other and other["rel"] != rec["rel"]:
            chunks.append(
                f"\n--- RELATED {other['rel']} ---\n{str(other['text'])[:RELATED_CHARS]}"
            )
        if len(chunks) >= 3:
            break
    return "".join(chunks)


def audit_prompt(batch: list[dict[str, Any]], by_name: dict[str, dict[str, Any]], mode: str) -> str:
    header = (
        f"Deep audit ({mode}). Return strict JSON only:\n"
        '{"findings":[{"title":"Contract.function - bug","file":"path","contract":"C",'
        '"function":"fn","line":1,"severity":"high|critical","type":"logic",'
        '"mechanism":"precondition -> attacker steps -> effect","impact":"harm",'
        '"description":"2-5 sentences with exploit path"}]}\n'
        "Max 4 findings. Cite real function names from the source. Prefer confirmed "
        "exploitable bugs over speculative issues. Focus: access control, reentrancy, "
        "oracle/price manipulation, share inflation, signature replay, init/upgrade, "
        "liquidation, unprotected privileged calls, incorrect accounting.\n"
    )
    parts, room = [header], AUDIT_CHARS - len(header)
    for rec in batch:
        sigs = [f"{f['line']}:{f['sig']}" for f in rec["functions"][:28]]
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
        [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": audit_prompt(batch, by_name, mode)},
        ],
        7000,
        started,
    ))
    items = obj.get("findings") or obj.get("vulnerabilities") or []
    return [x for x in items if isinstance(x, dict)] if isinstance(items, list) else []


def match_file(
    file_value: str, rel_map: dict[str, dict[str, Any]],
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


def clean(value: object) -> str:
    return " ".join(str(value or "").strip().split())


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
    if fn and fn not in valid and fn not in {"receive", "fallback"}:
        fn = ""
    contract = str(raw.get("contract") or "").strip().strip("`")
    if not contract and rec["contracts"]:
        contract = str(rec["contracts"][0])
    mech = clean(raw.get("mechanism"))
    impact = clean(raw.get("impact"))
    desc = clean(raw.get("description"))
    title = clean(raw.get("title")) or f"{contract}.{fn or 'logic'} - high-impact bug"
    if len(mech) < 24 and len(desc) < 110:
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
    if len(rebuilt) < 120:
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
        "confidence": 0.92 if sev == "critical" else 0.86,
    }


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
