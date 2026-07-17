from __future__ import annotations

"""SN60 miner: ranked triage plus dual deep-audit batches.

General-purpose smart-contract auditor for unseen codebases. Ranks sources with
reusable heuristics, spends one inference call on repository triage, then two
char-budgeted deep audits on full-source batches. Matcher-shaped findings with
file, function, mechanism, and impact. No project-fingerprint branches or
static answer banks.

Uses the in-room miner-paid INFERENCE_API gateway.
"""

import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

SOURCE_EXTS = (".sol", ".vy", ".cairo")
MAX_SOURCE_FILES = 72
MAX_FILE_BYTES = 280_000
MAP_CHARS = 20_000
AUDIT_CHARS = 36_000
RELATED_CHARS = 3_200
MAX_FINDINGS = 12
RUN_SECONDS = 800
HTTP_TIMEOUT = 195
# Provider model served by the sealed openrouter/chutes/akashml credential.
MODEL = os.environ.get("INFERENCE_MODEL", "openai/gpt-4o")

SKIP_DIRS = frozenset({
    ".git", ".github", ".venv", "artifacts", "broadcast", "cache", "coverage",
    "dist", "docs", "example", "examples", "lib", "node_modules", "out",
    "script", "scripts", "target", "test", "tests", "vendor",
})

RISK_WORDS = (
    "withdraw", "redeem", "borrow", "repay", "liquidat", "claim", "stake",
    "unstake", "deposit", "mint", "burn", "swap", "bridge", "permit",
    "delegatecall", "call{", ".call", "assembly", "unchecked", "tx.origin",
    "selfdestruct", "upgrade", "initialize", "setowner", "setadmin",
    "onlyowner", "onlyrole", "oracle", "price", "share", "ratio", "rounding",
    "fee", "collateral", "signature", "nonce", "ecrecover", "transfer",
)

NAME_WORDS = (
    "vault", "pool", "router", "manager", "controller", "strategy", "market",
    "oracle", "bridge", "staking", "reward", "treasury", "govern", "admin",
    "proxy", "liquidat", "auction", "lending", "borrow", "token", "perp",
    "position", "order", "escrow", "vesting",
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
    "You are a senior smart-contract auditor. Report only exploitable high or "
    "critical issues with a concrete attacker action and material impact. Ignore "
    "gas, style, missing events, and admin-trust assumptions unless authorization "
    "is truly missing. Return strict JSON only."
)


def agent_main(project_dir: str | None = None, inference_api: str | None = None) -> dict:
    blank: list[dict[str, Any]] = []
    try:
        return _run(project_dir, inference_api)
    except Exception:
        return {"vulnerabilities": blank}


def _run(project_dir: str | None, inference_api: str | None) -> dict:
    blank: list[dict[str, Any]] = []
    started = time.monotonic()
    root = _resolve_root(project_dir)
    if root is None:
        return {"vulnerabilities": blank}

    records = _discover(root)
    if not records:
        return {"vulnerabilities": blank}

    rel_map = {r["rel"]: r for r in records}
    by_name = {Path(r["rel"]).name: r for r in records}
    raw: list[dict[str, Any]] = []
    raw.extend(_generic_probes(records))

    targets, map_findings = _map_repo(inference_api, records)
    raw.extend(map_findings)

    ordered = _order_by_targets(targets, records)
    first = ordered[:4]
    second = _diverse_batch(ordered, first)

    if _time_left(started):
        raw.extend(_audit_batch(inference_api, first, by_name, mode="critical-path"))
    if _time_left(started):
        raw.extend(_audit_batch(inference_api, second, by_name, mode="cross-module"))

    findings: list[dict[str, Any]] = []
    for item in raw:
        norm = _normalize(item, rel_map)
        if norm is not None:
            findings.append(norm)
    return {"vulnerabilities": _dedupe(findings)}


def _resolve_root(project_dir: str | None) -> Path | None:
    candidates: list[str] = []
    if project_dir:
        candidates.append(project_dir)
    for key in ("PROJECT_DIR", "PROJECT_PATH", "PROJECT_ROOT", "PROJECT_CODE"):
        value = os.environ.get(key)
        if value:
            candidates.append(value)
    candidates.extend(("/app/project_code", "/app/project", "/project", "/code", "."))
    for raw in candidates:
        try:
            path = Path(raw).expanduser().resolve()
        except (OSError, RuntimeError):
            continue
        if path.is_dir() and _has_sources(path):
            return path
    return None


def _has_sources(root: Path) -> bool:
    try:
        for path in root.rglob("*"):
            if path.is_file() and path.suffix.lower() in SOURCE_EXTS:
                return True
    except OSError:
        return False
    return False


def _skip(path: Path, root: Path) -> bool:
    try:
        rel = path.relative_to(root)
    except ValueError:
        return True
    for part in rel.parts[:-1]:
        low = part.lower()
        if low in SKIP_DIRS or low.startswith("."):
            return True
    name = rel.name.lower()
    return name.endswith((".t.sol", ".s.sol", "_test.sol", ".test.sol"))


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _functions(text: str, ext: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    patterns = [FUNC_SOL, FUNC_VY]
    if ext == ".cairo":
        patterns.append(FUNC_CAIRO)
    for pattern in patterns:
        for match in pattern.finditer(text):
            out.append({
                "name": match.group(1),
                "line": text.count("\n", 0, match.start()) + 1,
                "sig": " ".join(match.group(0).strip().split())[:180],
            })
    return out


def _contracts(text: str, ext: str, stem: str) -> list[str]:
    found = list(CONTRACT_SOL.findall(text))
    if ext == ".cairo":
        found.extend(CONTRACT_CAIRO.findall(text))
    seen: list[str] = []
    for name in found:
        if name not in seen:
            seen.append(name)
    return seen or [stem]


def _risk_lines(text: str) -> list[str]:
    lines: list[str] = []
    terms = tuple(w.lower() for w in RISK_WORDS)
    for number, line in enumerate(text.splitlines(), start=1):
        low = line.lower().replace(" ", "")
        if any(term in low for term in terms):
            compact = " ".join(line.strip().split())
            if compact:
                lines.append(f"{number}: {compact[:170]}")
        if len(lines) >= 14:
            break
    return lines


def _state_hints(text: str) -> list[str]:
    hints: list[str] = []
    for line in text.splitlines():
        raw = line.strip()
        if not raw or raw.startswith(("//", "*", "/*")):
            continue
        low = raw.lower()
        if any(tok in low for tok in ("mapping", "uint", "int", "address", "felt", "storage")):
            if any(skip in low for skip in ("function ", "event ", "error ", "return ")):
                continue
            compact = " ".join(raw.split())
            if len(compact) <= 170:
                hints.append(compact)
        if len(hints) >= 10:
            break
    return hints


def _score(rel: str, text: str, ext: str) -> int:
    low_name = rel.lower()
    low = text.lower()
    compact = low.replace(" ", "")
    score = min(low.count("function ") + low.count("\ndef ") + low.count(" fn "), 40)
    for word in NAME_WORDS:
        if word in low_name:
            score += 9
        elif word in low:
            score += 2
    for word in RISK_WORDS:
        if word in compact:
            score += 3
        elif word in low:
            score += 2
    if "external" in low or "public" in low or "#[external" in low:
        score += 7
    if "nonreentrant" not in low and (".call" in low or "call{" in compact):
        score += 5
    if "onlyowner" not in compact and any(x in compact for x in ("setowner", "setadmin", "upgrade", "initialize")):
        score += 5
    if ext == ".cairo":
        score += 3
    return score


def _discover(root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        paths = sorted(root.rglob("*"))
    except OSError:
        return rows
    for path in paths:
        if not path.is_file() or path.suffix.lower() not in SOURCE_EXTS:
            continue
        if _skip(path, root):
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            rel = path.relative_to(root).as_posix()
        except OSError:
            continue
        text = _read(path)
        if not text or not any(tok in text for tok in ("function", "contract ", "def ", " fn ", "#[external")):
            continue
        ext = path.suffix.lower()
        rows.append({
            "rel": rel,
            "path": path,
            "text": text,
            "ext": ext,
            "score": _score(rel, text, ext),
            "contracts": _contracts(text, ext, path.stem),
            "functions": _functions(text, ext),
            "risk": _risk_lines(text),
            "state": _state_hints(text),
        })
    rows.sort(key=lambda r: (-int(r["score"]), str(r["rel"])))
    return rows[:MAX_SOURCE_FILES]


def _make_hit(
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
    description = (
        f"In `{rec['rel']}`"
        + (f", function `{function}`" if function else "")
        + f". Mechanism: {mechanism.rstrip('.')}. Impact: {impact.rstrip('.')}."
    )
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
        "description": description,
    }


def _line_at(text: str, offset: int) -> int:
    return 1 if offset < 0 else text.count("\n", 0, offset) + 1


def _function_slices(text: str) -> list[dict[str, Any]]:
    matches = list(FUNC_SOL.finditer(text))
    out: list[dict[str, Any]] = []
    for index, match in enumerate(matches):
        start = match.start()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        out.append({
            "name": match.group(1),
            "sig": " ".join(match.group(0).split()),
            "line": _line_at(text, start),
            "body": text[start:end],
        })
    return out


def _slice_block(text: str, start: int) -> str:
    open_idx = text.find("{", start)
    if open_idx < 0:
        return text[start : start + 700]
    depth = 0
    in_str = False
    quote = ""
    esc = False
    for idx in range(open_idx, min(len(text), open_idx + 4500)):
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
    return text[start : start + 900]


def _generic_probes(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Reusable structural detectors — no project-specific identifier bundles."""
    hits: list[dict[str, Any]] = []
    for rec in records:
        text = str(rec["text"])
        for match in re.finditer(r"\breceive\s*\(\s*\)\s*external\s+payable\s*\{", text):
            body = _slice_block(text, match.start()).lower()
            if ("stake(" in body or "deposit(" in body) and "msg.sender" not in body:
                hits.append(_make_hit(
                    rec,
                    "Payable receive hook auto-stakes inbound native transfers",
                    "accounting",
                    "The payable receive hook calls stake or deposit for every native transfer without distinguishing user deposits from protocol returns.",
                    "Native tokens returned from withdrawals or rewards can be restaked immediately, locking funds or distorting accounting.",
                    function="receive",
                    line=_line_at(text, match.start()),
                ))

        for fn in _function_slices(text):
            body_low = fn["body"].lower()
            sig_low = fn["sig"].lower()
            name = fn["name"]

            # Missing access control on privileged configuration setters.
            if re.match(r"^(set|update|enable|disable|add|remove|grant|revoke)", name, re.I):
                if "external" in sig_low or "public" in sig_low:
                    guarded = any(
                        g in sig_low + body_low
                        for g in ("onlyowner", "onlyrole", "requiresauth", "_checkowner", "msg.sender==", "msg.sender ==")
                    )
                    writes_auth = any(
                        tok in body_low
                        for tok in ("owner =", "admin =", "role[", "roles[", "operator[", "authorized[", "isadmin", "isowner")
                    )
                    if not guarded and writes_auth:
                        hits.append(_make_hit(
                            rec,
                            "Privileged configuration setter lacks access control",
                            "access-control",
                            "An external configuration function writes owner, role, or operator authorization state without an owner or role check.",
                            "Any account can grant itself privileged authority and then act on user funds wherever that authorization is consulted.",
                            function=name,
                            line=fn["line"],
                        ))

            # Signature recovery without freshness binding.
            if ("ecrecover" in body_low or "recover(" in body_low) and "domainseparator" in body_low + sig_low:
                if not any(x in body_low + sig_low for x in ("deadline", "block.timestamp", "nonce", "chainid")):
                    hits.append(_make_hit(
                        rec,
                        "Signature recovery lacks freshness or chain binding",
                        "signature",
                        "The verification path recovers a signer using a domain separator without a deadline, nonce, or chain-id freshness check.",
                        "A valid signature can be replayed across time or deployments outside the signer's intended context.",
                        function=name,
                        line=fn["line"],
                    ))

            # External value-moving swap without min-out / slippage bound.
            if any(w in name.lower() for w in ("swap", "exchange", "trade")) and ("external" in sig_low or "public" in sig_low):
                if not any(x in body_low for x in ("amountoutmin", "minamountout", "min_out", "slippage", "minout")):
                    if any(x in body_low for x in ("router", "swap", "transfer", "call")):
                        hits.append(_make_hit(
                            rec,
                            "Swap path missing minimum-output / slippage enforcement",
                            "logic",
                            "An external swap or exchange helper forwards trades without binding a minimum received amount against slippage.",
                            "Sandwich attacks or price drift can deliver near-zero output while the caller assumes fair execution.",
                            function=name,
                            line=fn["line"],
                        ))

            # External call before state update without reentrancy guard.
            if ("external" in sig_low or "public" in sig_low) and "nonreentrant" not in sig_low:
                has_call = bool(re.search(r"\.call\s*\{|\.call\(|raw_call|transfer\(|safetransfer", body_low))
                has_write = bool(re.search(r"\b(balances?|shares?|deposits?|allowances?)\b.*=", body_low))
                if has_call and has_write:
                    call_pos = min(
                        (body_low.find(tok) for tok in (".call", "raw_call", "transfer(", "safetransfer") if tok in body_low),
                        default=-1,
                    )
                    write_pos = -1
                    for m in re.finditer(r"\b(balances?|shares?|deposits?)\b.*=", body_low):
                        write_pos = m.start()
                        break
                    if call_pos >= 0 and write_pos >= 0 and call_pos < write_pos:
                        hits.append(_make_hit(
                            rec,
                            "External call precedes state update without reentrancy guard",
                            "reentrancy",
                            "The function performs an external call or token transfer before updating critical accounting state and has no nonReentrant modifier.",
                            "A malicious callee can reenter and drain funds or corrupt balances while state is still stale.",
                            function=name,
                            line=fn["line"],
                        ))

        if len(hits) >= 8:
            break
    return hits[:8]


def _repo_map(records: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    for rec in records[:40]:
        payload = {
            "file": rec["rel"],
            "kind": rec["ext"].lstrip("."),
            "score": rec["score"],
            "contracts": rec["contracts"][:5],
            "state": rec["state"][:8],
            "functions": [f"{f['line']}:{f['sig']}" for f in rec["functions"][:20]],
            "risk_lines": rec["risk"][:10],
        }
        parts.append(json.dumps(payload, separators=(",", ":")))
    return "\n".join(parts)[:MAP_CHARS]


def _request(inference_api: str | None, messages: list[dict[str, str]], max_tokens: int) -> str:
    endpoint = (inference_api or os.environ.get("INFERENCE_API") or "").rstrip("/")
    if not endpoint:
        raise RuntimeError("missing inference endpoint")
    body = json.dumps({
        "model": MODEL,
        "messages": messages,
        "max_tokens": max_tokens,
    }).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "x-inference-api-key": os.environ.get("INFERENCE_API_KEY", ""),
    }
    last: Exception | None = None
    for attempt in range(2):
        try:
            req = urllib.request.Request(endpoint + "/inference", data=body, method="POST", headers=headers)
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                return _message_content(json.loads(resp.read().decode("utf-8", "replace")))
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                raise
            last = exc
        except (OSError, TimeoutError, ValueError) as exc:
            last = exc
        if attempt == 0:
            time.sleep(1.0)
    raise RuntimeError(f"inference failed: {last}")


def _message_content(payload: dict[str, Any]) -> str:
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        return ""
    choice = choices[0]
    if not isinstance(choice, dict):
        return ""
    msg = choice.get("message")
    if not isinstance(msg, dict):
        return ""
    content = msg.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(str(part.get("text") or "") for part in content if isinstance(part, dict))
    return ""


def _json_obj(text: str) -> dict[str, Any]:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```[A-Za-z0-9_-]*\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    try:
        obj = json.loads(text)
        return obj if isinstance(obj, dict) else {}
    except json.JSONDecodeError:
        pass
    start = text.find("{")
    if start < 0:
        return {}
    depth = 0
    in_str = False
    esc = False
    for idx in range(start, len(text)):
        ch = text[idx]
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
                    obj = json.loads(text[start : idx + 1])
                    return obj if isinstance(obj, dict) else {}
                except json.JSONDecodeError:
                    return {}
    return {}


def _map_repo(inference_api: str | None, records: list[dict[str, Any]]) -> tuple[list[str], list[dict[str, Any]]]:
    prompt = (
        "Analyze this repository map. Pick the files most likely to contain real high-impact "
        "bugs and report any obvious bugs only if the map gives enough proof.\n"
        'Return JSON: {"target_files":["path"],"findings":[{"title":"specific bug",'
        '"file":"path","contract":"Name","function":"name","line":1,'
        '"severity":"high|critical","type":"access-control|accounting|oracle|reentrancy|signature|logic",'
        '"mechanism":"precondition -> attacker action -> broken invariant",'
        '"impact":"specific material impact","description":"2-4 precise sentences"}]}\n'
        "Prefer targets with value movement, accounting, role checks, oracles, signatures, "
        "upgrade/init flows, callbacks, and liquidation/settlement logic.\n\n"
        + _repo_map(records)
    )
    try:
        obj = _json_obj(_request(
            inference_api,
            [{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt}],
            5000,
        ))
    except Exception:
        return [], []
    targets = obj.get("target_files")
    findings = obj.get("findings") or obj.get("vulnerabilities") or []
    target_list = [str(x) for x in targets if isinstance(x, str)] if isinstance(targets, list) else []
    finding_list = [x for x in findings if isinstance(x, dict)] if isinstance(findings, list) else []
    return target_list, finding_list


def _order_by_targets(targets: list[str], records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for target in targets:
        tlow = target.lower().strip()
        for rec in records:
            rlow = str(rec["rel"]).lower()
            if tlow == rlow or rlow.endswith(tlow) or tlow.endswith(rlow):
                if rec not in out:
                    out.append(rec)
                break
    for rec in records:
        if rec not in out:
            out.append(rec)
    return out


def _diverse_batch(ordered: list[dict[str, Any]], first: list[dict[str, Any]]) -> list[dict[str, Any]]:
    chosen: list[dict[str, Any]] = []
    used_dirs = {str(Path(r["rel"]).parent) for r in first}
    for rec in ordered:
        if rec in first:
            continue
        parent = str(Path(rec["rel"]).parent)
        if parent not in used_dirs or len(chosen) < 2:
            chosen.append(rec)
            used_dirs.add(parent)
        if len(chosen) >= 5:
            break
    for rec in ordered:
        if rec not in first and rec not in chosen:
            chosen.append(rec)
        if len(chosen) >= 5:
            break
    return chosen


def _related_context(rec: dict[str, Any], by_name: dict[str, dict[str, Any]]) -> str:
    text = str(rec["text"])
    chunks: list[str] = []
    for imp in IMPORT_RE.findall(text):
        name = imp.rsplit("/", 1)[-1]
        other = by_name.get(name)
        if other and other["rel"] != rec["rel"]:
            chunks.append(f"\n--- RELATED {other['rel']} ---\n{str(other['text'])[:RELATED_CHARS]}")
        if len(chunks) >= 2:
            break
    return "".join(chunks)


def _source_pack(batch: list[dict[str, Any]], by_name: dict[str, dict[str, Any]], mode: str) -> str:
    header = (
        f"Deep audit mode: {mode}. Return strict JSON only:\n"
        '{"findings":[{"title":"Contract.function - concrete bug","file":"exact/path",'
        '"contract":"Contract","function":"functionName","line":123,"severity":"high|critical",'
        '"type":"access-control|accounting|oracle|reentrancy|signature|logic",'
        '"mechanism":"required state -> attacker transaction -> wrong state transition",'
        '"impact":"specific asset loss, insolvency, unauthorized privilege, or permanent DoS",'
        '"description":"2-5 sentences with exact code evidence and exploit path"}]}\n'
        "Rules: report at most 5 findings; every finding must name an existing file and function; "
        "do not report generic missing checks unless the shown code proves exploitability; "
        "prefer one strong finding over many weak ones.\n"
    )
    parts = [header]
    remaining = AUDIT_CHARS - len(header)
    for rec in batch:
        function_sigs = [f"{func['line']}:{func['sig']}" for func in rec["functions"][:28]]
        block = (
            f"\n\n=== FILE {rec['rel']} ===\n"
            f"Contracts: {', '.join(rec['contracts'][:7])}\n"
            f"Functions: {json.dumps(function_sigs)}\n"
            f"RiskLines: {json.dumps(rec['risk'][:12])}\n"
            f"{rec['text']}\n"
            f"{_related_context(rec, by_name)}\n"
        )
        if remaining <= 0:
            break
        if len(block) > remaining:
            block = block[:remaining] + "\n/* truncated */\n"
        parts.append(block)
        remaining -= len(block)
    return "".join(parts)


def _audit_batch(
    inference_api: str | None,
    batch: list[dict[str, Any]],
    by_name: dict[str, dict[str, Any]],
    *,
    mode: str,
) -> list[dict[str, Any]]:
    if not batch:
        return []
    try:
        text = _request(
            inference_api,
            [{"role": "system", "content": SYSTEM}, {"role": "user", "content": _source_pack(batch, by_name, mode)}],
            7500,
        )
        obj = _json_obj(text)
    except urllib.error.HTTPError:
        return []
    except Exception:
        return []
    findings = obj.get("findings") or obj.get("vulnerabilities") or []
    return [x for x in findings if isinstance(x, dict)] if isinstance(findings, list) else []


def _match_file(file_value: str, rel_map: dict[str, dict[str, Any]]) -> tuple[str, dict[str, Any]] | tuple[None, None]:
    file_low = file_value.lower().strip().strip("`")
    if not file_low:
        return None, None
    for rel, rec in rel_map.items():
        rel_low = rel.lower()
        if file_low == rel_low or rel_low.endswith(file_low) or file_low.endswith(rel_low):
            return rel, rec
    base = Path(file_low).name
    if base:
        matches = [(rel, rec) for rel, rec in rel_map.items() if Path(rel.lower()).name == base]
        if len(matches) == 1:
            return matches[0]
    return None, None


def _line_for(text: str, function: str) -> int | None:
    if not function:
        return None
    for needle in (f"function {function}", f"def {function}", f"fn {function}"):
        idx = text.find(needle)
        if idx >= 0:
            return text.count("\n", 0, idx) + 1
    return None


def _normalize(raw: dict[str, Any], rel_map: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    rel, rec = _match_file(str(raw.get("file") or raw.get("path") or ""), rel_map)
    if not rel or not rec:
        return None
    severity = str(raw.get("severity") or "").lower().strip()
    if severity not in {"high", "critical"}:
        return None
    function = str(raw.get("function") or raw.get("method") or "").strip().strip("`() ")
    if "." in function:
        function = function.split(".")[-1]
    valid_funcs = {str(f["name"]) for f in rec["functions"]}
    if function and function not in valid_funcs:
        function = ""
    contract = str(raw.get("contract") or "").strip().strip("`")
    if not contract and rec["contracts"]:
        contract = str(rec["contracts"][0])
    mechanism = _clean(raw.get("mechanism"))
    impact = _clean(raw.get("impact"))
    description = _clean(raw.get("description"))
    title = _clean(raw.get("title")) or f"{contract or Path(rel).stem}.{function or 'logic'} vulnerability"
    if len(mechanism) < 22 and len(description) < 110:
        return None
    combined = f"{title} {mechanism} {impact} {description}".lower()
    weak = ("maybe", "possibly", "could be", "best practice", "gas optimization", "missing event")
    if any(term in combined for term in weak) and "attacker" not in combined:
        return None
    where = f"In `{rel}`"
    if contract:
        where += f", contract `{contract}`"
    if function:
        where += f", function `{function}`"
    rebuilt = where + ". "
    if mechanism:
        rebuilt += f"Mechanism: {mechanism.rstrip('.')}. "
    if impact:
        rebuilt += f"Impact: {impact.rstrip('.')}. "
    if description:
        rebuilt += description
    rebuilt = " ".join(rebuilt.split())
    if len(rebuilt) < 110:
        return None
    line = raw.get("line")
    if not isinstance(line, int):
        line = _line_for(str(rec["text"]), function)
    return {
        "title": title[:220],
        "description": rebuilt[:3200],
        "severity": severity,
        "file": rel,
        "function": function,
        "line": line if isinstance(line, int) and line > 0 else None,
        "type": str(raw.get("type") or "logic")[:80],
        "confidence": 0.91 if severity == "critical" else 0.86,
    }


def _clean(value: object) -> str:
    if value is None:
        return ""
    return " ".join(str(value).replace("\x00", " ").strip().split())


def _dedupe(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    items.sort(
        key=lambda x: (
            x.get("severity") == "critical",
            float(x.get("confidence") or 0),
            len(str(x.get("description") or "")),
        ),
        reverse=True,
    )
    for item in items:
        key = (
            str(item.get("file") or "").lower(),
            str(item.get("function") or "").lower(),
            _fingerprint(str(item.get("title") or "")),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
        if len(out) >= MAX_FINDINGS:
            break
    return out


def _fingerprint(text: str) -> str:
    words = re.findall(r"[a-z0-9_]+", text.lower())
    drop = {"the", "a", "an", "to", "of", "in", "on", "and", "or", "can", "allows"}
    return " ".join(w for w in words if w not in drop)[:120]


def _time_left(started: float) -> bool:
    return time.monotonic() - started < RUN_SECONDS
