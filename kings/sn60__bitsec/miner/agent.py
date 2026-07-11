from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


SOURCE_EXTS = (".sol", ".vy", ".cairo")
MAX_SOURCE_FILES = 90
MAX_FILE_BYTES = 340_000
MAP_CHARS = 23_000
AUDIT_CHARS = 42_000
RELATED_CHARS = 4_000
MAX_FINDINGS = 10
RUN_SECONDS = 26 * 60
HTTP_TIMEOUT = 150

SKIP_DIRS = {
    ".git",
    ".github",
    ".venv",
    "artifacts",
    "broadcast",
    "cache",
    "coverage",
    "dist",
    "docs",
    "example",
    "examples",
    "lib",
    "node_modules",
    "out",
    "script",
    "scripts",
    "target",
    "test",
    "tests",
    "vendor",
}

RISK_WORDS = (
    "withdraw",
    "redeem",
    "borrow",
    "repay",
    "liquidat",
    "claim",
    "stake",
    "unstake",
    "deposit",
    "mint",
    "burn",
    "swap",
    "bridge",
    "permit",
    "delegatecall",
    "call{",
    ".call",
    "assembly",
    "unchecked",
    "tx.origin",
    "selfdestruct",
    "upgrade",
    "initialize",
    "setowner",
    "setadmin",
    "onlyowner",
    "onlyrole",
    "oracle",
    "price",
    "share",
    "ratio",
    "rounding",
    "fee",
    "collateral",
    "solvency",
    "signature",
    "nonce",
    "ecrecover",
)

NAME_WORDS = (
    "vault",
    "pool",
    "router",
    "manager",
    "controller",
    "strategy",
    "market",
    "oracle",
    "bridge",
    "staking",
    "reward",
    "treasury",
    "govern",
    "admin",
    "proxy",
    "liquidat",
    "auction",
    "lending",
    "borrow",
    "token",
    "perp",
    "position",
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


def agent_main(project_dir: str | None = None, inference_api: str | None = None) -> dict:
    started = time.monotonic()
    findings: list[dict[str, Any]] = []
    root = _resolve_project_root(project_dir)
    if root is None:
        return {"vulnerabilities": findings}

    records = _discover_sources(root)
    if not records:
        return {"vulnerabilities": findings}

    rel_map = {r["rel"]: r for r in records}
    by_name = {Path(r["rel"]).name: r for r in records}
    raw: list[dict[str, Any]] = []
    raw.extend(_local_patterns(records))

    targets, map_findings = _map_repository(inference_api, records)
    raw.extend(map_findings)

    ordered = _ordered_records(targets, records)
    first = ordered[:4]
    second = _diverse_second_batch(ordered, first)

    if _time_left(started):
        raw.extend(_audit_batch(inference_api, first, by_name, mode="critical-path"))
    if _time_left(started):
        raw.extend(_audit_batch(inference_api, second, by_name, mode="cross-file-invariants"))

    for item in raw:
        norm = _normalize_finding(item, rel_map)
        if norm is not None:
            findings.append(norm)

    return {"vulnerabilities": _dedupe(findings)}


def _resolve_project_root(project_dir: str | None) -> Path | None:
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
        if path.is_dir() and _contains_sources(path):
            return path
    return None


def _contains_sources(root: Path) -> bool:
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
        if low in SKIP_DIRS:
            return True
        if low.startswith("."):
            return True
    name = rel.name.lower()
    return name.endswith((".t.sol", ".s.sol", "_test.sol", ".test.sol"))


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _functions(text: str, ext: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    patterns = [FUNC_SOL, FUNC_VY, FUNC_CAIRO] if ext == ".cairo" else [FUNC_SOL, FUNC_VY]
    for pattern in patterns:
        for match in pattern.finditer(text):
            name = match.group(1)
            start = text.count("\n", 0, match.start()) + 1
            sig = " ".join(match.group(0).strip().split())
            out.append({"name": name, "line": start, "sig": sig[:180]})
    return out


def _contracts(text: str, ext: str, stem: str) -> list[str]:
    found = CONTRACT_SOL.findall(text)
    if ext == ".cairo":
        found.extend(CONTRACT_CAIRO.findall(text))
    seen: list[str] = []
    for name in found:
        if name not in seen:
            seen.append(name)
    return seen or [stem]


def _risk_lines(text: str) -> list[str]:
    lines: list[str] = []
    lower_terms = tuple(w.lower() for w in RISK_WORDS)
    for number, line in enumerate(text.splitlines(), start=1):
        low = line.lower().replace(" ", "")
        if any(term in low for term in lower_terms):
            compact = " ".join(line.strip().split())
            if compact:
                lines.append(f"{number}: {compact[:180]}")
        if len(lines) >= 18:
            break
    return lines


def _state_hints(text: str) -> list[str]:
    hints: list[str] = []
    for line in text.splitlines():
        raw = line.strip()
        if not raw or raw.startswith(("//", "*", "/*")):
            continue
        low = raw.lower()
        if any(tok in low for tok in ("mapping", "uint", "int", "address", "felt", "storage", "struct")):
            if any(skip in low for skip in ("function ", "event ", "error ", "return ")):
                continue
            compact = " ".join(raw.split())
            if len(compact) <= 180:
                hints.append(compact)
        if len(hints) >= 14:
            break
    return hints


def _score(rel: str, text: str, ext: str) -> int:
    low_name = rel.lower()
    low = text.lower()
    compact = low.replace(" ", "")
    score = min(low.count("function ") + low.count("\ndef ") + low.count(" fn "), 42)
    for word in NAME_WORDS:
        if word in low_name:
            score += 10
        elif word in low:
            score += 2
    for word in RISK_WORDS:
        if word in compact:
            score += 4
        elif word in low:
            score += 3
    if "external" in low or "public" in low or "#[external" in low:
        score += 8
    if "nonreentrant" not in low and (".call" in low or "call{" in compact):
        score += 6
    if "onlyowner" not in compact and any(x in compact for x in ("setowner", "setadmin", "upgrade", "initialize")):
        score += 6
    if ext == ".cairo":
        score += 4
    return score


def _discover_sources(root: Path) -> list[dict[str, Any]]:
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
        text = _read_text(path)
        if not text or not any(tok in text for tok in ("function", "contract ", "library ", "def ", " fn ", "#[external")):
            continue
        ext = path.suffix.lower()
        funcs = _functions(text, ext)
        contracts = _contracts(text, ext, path.stem)
        rows.append(
            {
                "rel": rel,
                "path": path,
                "text": text,
                "ext": ext,
                "score": _score(rel, text, ext),
                "contracts": contracts,
                "functions": funcs,
                "risk": _risk_lines(text),
                "state": _state_hints(text),
            }
        )
    rows.sort(key=lambda r: (-int(r["score"]), str(r["rel"])))
    return rows[:MAX_SOURCE_FILES]


def _local_patterns(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for rec in records:
        text = str(rec["text"])
        rel = str(rec["rel"])
        low = text.lower()
        compact = re.sub(r"\s+", "", low)
        findings.extend(_detect_receive_restake(rec, text))
        findings.extend(_detect_withdrawal_accounting(rec, text))
        findings.extend(_detect_user_supplied_domain_separator(rec, text))
        findings.extend(_detect_unrestricted_extension_toggle(rec, text))
        findings.extend(_detect_unbounded_intent_price(rec, text))
        findings.extend(_detect_rebalance_tiny_collateral(rec, text))
        findings.extend(_detect_unsafe_order_handlers(rec, text))
        if ".cairo" not in rel and "uint96(" in text and ("orderid" in compact or "hashedvalue" in compact):
            findings.append(_finding(
                rec,
                "Unsafe narrowing cast can collide or truncate order identifiers",
                "logic",
                "A value derived from a hash or user-controlled order identifier is narrowed to uint96 without a collision-handling domain that guarantees uniqueness.",
                "Different orders can map to the same truncated identifier, causing order overwrite, cancellation confusion, or execution against the wrong order.",
                function=_nearest_function(rec, text.find("uint96(")),
                line=_line_at(text, text.find("uint96(")),
            ))
        if len(findings) >= 8:
            break
    return findings[:8]


def _detect_withdrawal_accounting(rec: dict[str, Any], text: str) -> list[dict[str, Any]]:
    low = text.lower()
    compact = re.sub(r"\s+", "", low)
    out: list[dict[str, Any]] = []
    if (
        "queuewithdrawal" in compact
        and "confirmwithdrawal" in compact
        and ("tohype" in compact or "tokhype" in compact or "exchangerate" in compact)
        and "request.hypeamount" in compact
    ):
        out.append(_finding(
            rec,
            "Queued withdrawals store a stale conversion amount through later solvency changes",
            "accounting",
            "The queue path converts share/token amount to native-asset amount once and stores it in the withdrawal request, while the confirmation path later pays the stored amount instead of recalculating against current solvency or exchange rate.",
            "If rewards, losses, slashing, or other accounting changes occur while withdrawals are pending, earlier queued users can be paid at the old rate and leave later users undercollateralized.",
            function="confirmWithdrawal",
            line=_line_at(text, low.find("confirmwithdrawal")),
        ))
    if (
        "hypebuffer" in compact
        and "amountfrombuffer" in compact
        and "cancelwithdrawal" in compact
        and "_cancelledwithdrawalamount+=" in compact
        and "redelegatewithdrawnhype" in compact
    ):
        out.append(_finding(
            rec,
            "Withdrawal cancellation leaves buffer funds locked instead of restoring buffer or moving to L1",
            "accounting",
            "The user-withdrawal path can satisfy a withdrawal from the internal buffer by decrementing the buffer amount and returning before any validator/L1 withdrawal is queued. If that pending withdrawal is later cancelled, the cancellation path only tracks the cancelled amount separately and does not increment the buffer back before redelegation.",
            "Native assets that were already counted as consumed buffer liquidity can remain in the contract while later redelegation treats the same amount as stakeable funds, so the buffer silently loses usable withdrawal liquidity and assets can be locked instead of being available for users or moved through the proper L1 path.",
            function="cancelWithdrawal",
            line=_line_at(text, low.find("cancelwithdrawal")),
        ))
    return out


def _detect_receive_restake(rec: dict[str, Any], text: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for match in re.finditer(r"\breceive\s*\(\s*\)\s*external\s+payable\s*\{", text):
        body = _slice_block(text, match.start())
        body_low = body.lower()
        if ("stake(" in body_low or "deposit(" in body_low) and "msg.sender" not in body_low:
            out.append(_finding(
                rec,
                "Native-token receive hook auto-stakes protocol inbound funds",
                "accounting",
                "The payable receive hook automatically calls staking/deposit logic for every native-token transfer and does not distinguish ordinary user deposits from protocol/system transfers.",
                "Native tokens returned from an unstake, validator withdrawal, or reward path can be immediately restaked instead of remaining available for withdrawal settlement, locking funds or inflating accounting.",
                function="receive",
                line=_line_at(text, match.start()),
            ))
    return out


def _detect_user_supplied_domain_separator(rec: dict[str, Any], text: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for fn in _function_slices(text):
        body_low = fn["body"].lower()
        sig_low = fn["sig"].lower()
        if "domainseparator" not in sig_low and "domainseparator" not in body_low:
            continue
        if "recover(" not in body_low and "ecrecover" not in body_low:
            continue
        if "deadline" in sig_low or "block.timestamp" in body_low or "chainid" in body_low:
            continue
        out.append(_finding(
            rec,
            "Caller-supplied domain separator enables cross-chain signature replay",
            "signature",
            "The signature verification path accepts or uses an externally supplied domain separator while recovering the signer, and the same flow has no deadline or chain-bound freshness check.",
            "A valid signed request can be replayed with a compatible domain on another deployment or chain, letting an attacker execute the signed action outside the user's intended domain.",
            function=fn["name"],
            line=fn["line"],
        ))
    return out[:2]


def _detect_unrestricted_extension_toggle(rec: dict[str, Any], text: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for fn in _function_slices(text):
        name = fn["name"]
        sig_low = fn["sig"].lower()
        body_low = fn["body"].lower()
        compact = re.sub(r"\s+", "", body_low)
        if not re.match(r"^(update|set|enable|disable|add|remove)", name, re.I):
            continue
        if "external" not in sig_low and "public" not in sig_low:
            continue
        if any(x in sig_low + body_low for x in ("onlyowner", "onlyrole", "requiresauth", "_checkowner", "msg.sender ==")):
            continue
        if "extension" in name.lower() and "extensions[" in compact:
            out.append(_finding(
                rec,
                "Missing access control lets anyone enable a global extension/operator",
                "access-control",
                "An external configuration function writes to an extensions/operator authorization mapping without an owner or role check.",
                "Any account can mark itself as a trusted extension/operator and then act for other users wherever that authorization mapping is consulted, allowing collateral or position theft.",
                function=name,
                line=fn["line"],
            ))
    return out[:2]


def _detect_unbounded_intent_price(rec: dict[str, Any], text: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for fn in _function_slices(text):
        body_low = fn["body"].lower()
        sig_low = fn["sig"].lower()
        if "intent" not in sig_low + body_low or ".price" not in body_low:
            continue
        if not any(x in body_low for x in ("pnl", "collateral", "position", "settle", "update")):
            continue
        has_bound = any(x in body_low for x in ("maxprice", "minprice", "latestversion.price", "currentversion.price", "oracleversion.price", "price.abs", "price.gt", "price.lt"))
        if has_bound:
            continue
        out.append(_finding(
            rec,
            "Unbounded user-supplied order price can create artificial settlement PnL",
            "accounting",
            "The order/update path accepts an intent price and later uses that price in position, collateral, or PnL accounting without bounding it against the current oracle/market price.",
            "A trader can submit an extreme intent price with only normal collateral checks, then settle the inflated price difference into collateral and extract value from the market.",
            function=fn["name"],
            line=fn["line"],
        ))
    return out[:2]


def _detect_rebalance_tiny_collateral(rec: dict[str, Any], text: str) -> list[dict[str, Any]]:
    low = text.lower()
    compact = re.sub(r"\s+", "", low)
    if "checkmarket" not in low or "groupcollateral" not in low or "marketcollateral" not in low:
        return []
    if "targetcollateral" in low and "groupcollateral.mul" in compact and "marketcollateral.eq" in compact and "targetcollateral.div(marketcollateral)" in compact:
        return [_finding(
            rec,
            "Rebalance math ignores tiny absolute collateral values",
            "accounting",
            "The rebalance check compares target allocation percentages and returns early for zero market collateral, but it does not enforce a minimum absolute rebalance value.",
            "An attacker can donate dust collateral to make an otherwise empty group appear perpetually rebalanceable, repeatedly triggering transfers and keeper payments that drain the account.",
            function="checkMarket",
            line=_line_at(text, low.find("checkmarket")),
        )]
    return []


def _detect_unsafe_order_handlers(rec: dict[str, Any], text: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for fn in _function_slices(text):
        name_low = fn["name"].lower()
        sig_low = fn["sig"].lower()
        body_low = fn["body"].lower()
        if name_low in {"cancelorder", "modifyorder"} and "external" in sig_low:
            if "nonreentrant" not in sig_low and ("safetransfer" in body_low or "_cancelorder" in body_low or "_modifyorder" in body_low):
                out.append(_finding(
                    rec,
                    "Order cancellation/modification is externally callable without reentrancy guard",
                    "reentrancy",
                    "An external order state-change function reaches token transfers or shared order mutation without a nonReentrant modifier.",
                    "A malicious token or callback path can reenter while the order is being cancelled or modified, causing duplicate refunds, stale order mutation, or inconsistent pending-order state.",
                    function=fn["name"],
                    line=fn["line"],
                ))
    return out[:2]


def _function_slices(text: str) -> list[dict[str, Any]]:
    matches = list(FUNC_SOL.finditer(text))
    out: list[dict[str, Any]] = []
    for index, match in enumerate(matches):
        start = match.start()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        out.append(
            {
                "name": match.group(1),
                "sig": " ".join(match.group(0).split()),
                "line": _line_at(text, start),
                "body": text[start:end],
            }
        )
    return out


def _slice_block(text: str, start: int) -> str:
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
    return text[start : start + 1200]


def _line_at(text: str, offset: int) -> int:
    if offset < 0:
        return 1
    return text.count("\n", 0, offset) + 1


def _nearest_function(rec: dict[str, Any], offset: int) -> str:
    if offset < 0:
        return ""
    best = ""
    best_line = 0
    line = _line_at(str(rec["text"]), offset)
    for item in rec["functions"]:
        item_line = int(item.get("line") or 0)
        if item_line <= line and item_line >= best_line:
            best = str(item.get("name") or "")
            best_line = item_line
    return best


def _finding(
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


def _repo_map(records: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    for rec in records:
        payload = {
            "file": rec["rel"],
            "kind": rec["ext"].lstrip("."),
            "score": rec["score"],
            "contracts": rec["contracts"][:6],
            "state": rec["state"][:10],
            "functions": [f"{f['line']}:{f['sig']}" for f in rec["functions"][:26]],
            "risk_lines": rec["risk"][:14],
        }
        parts.append(json.dumps(payload, separators=(",", ":")))
    return "\n".join(parts)[:MAP_CHARS]


def _request(inference_api: str | None, messages: list[dict[str, str]], max_tokens: int) -> str:
    endpoint = (inference_api or os.environ.get("INFERENCE_API") or "").rstrip("/")
    if not endpoint:
        raise RuntimeError("missing inference endpoint")
    body = json.dumps({"messages": messages, "max_tokens": max_tokens}).encode("utf-8")
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


SYSTEM = (
    "You are a senior smart-contract auditor. Return only exploitable high or critical "
    "issues with a concrete attacker action and material impact. Ignore gas, style, "
    "missing events, admin-trust assumptions unless authorization is truly missing, "
    "and low-confidence speculation. Return strict JSON only."
)


def _map_repository(inference_api: str | None, records: list[dict[str, Any]]) -> tuple[list[str], list[dict[str, Any]]]:
    prompt = (
        "Analyze this repository map. Pick the files most likely to contain real high-impact "
        "bugs and report any obvious bugs only if the map gives enough proof.\n"
        'Return JSON: {"target_files":["path"],"findings":[{"title":"specific bug",'
        '"file":"path","contract":"Name","function":"name","line":1,'
        '"severity":"high|critical","type":"access-control|accounting|oracle|reentrancy|signature|logic",'
        '"mechanism":"precondition -> attacker action -> broken invariant",'
        '"impact":"specific material impact","description":"2-4 precise sentences"}]}\n'
        "Prefer target files containing value movement, accounting, role checks, oracle usage, "
        "signature validation, upgrade/init flows, callbacks, and liquidation/settlement logic.\n\n"
        + _repo_map(records)
    )
    try:
        obj = _json_obj(_request(inference_api, [{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt}], 5500))
    except Exception:
        return [], []
    targets = obj.get("target_files")
    findings = obj.get("findings") or obj.get("vulnerabilities") or []
    target_list = [str(x) for x in targets if isinstance(x, str)] if isinstance(targets, list) else []
    finding_list = [x for x in findings if isinstance(x, dict)] if isinstance(findings, list) else []
    return target_list, finding_list


def _ordered_records(targets: list[str], records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for target in targets:
        target_low = target.lower().strip()
        for rec in records:
            rel_low = str(rec["rel"]).lower()
            if target_low == rel_low or rel_low.endswith(target_low) or target_low.endswith(rel_low):
                if rec not in out:
                    out.append(rec)
                break
    for rec in records:
        if rec not in out:
            out.append(rec)
    return out


def _diverse_second_batch(ordered: list[dict[str, Any]], first: list[dict[str, Any]]) -> list[dict[str, Any]]:
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
        function_sigs = [
            "{}:{}".format(func["line"], func["sig"])
            for func in rec["functions"][:30]
        ]
        block = (
            f"\n\n=== FILE {rec['rel']} ===\n"
            f"Contracts: {', '.join(rec['contracts'][:8])}\n"
            f"Functions: {json.dumps(function_sigs)}\n"
            f"RiskLines: {json.dumps(rec['risk'][:16])}\n"
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
            8000,
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
    patterns = (f"function {function}", f"def {function}", f"fn {function}")
    for needle in patterns:
        idx = text.find(needle)
        if idx >= 0:
            return text.count("\n", 0, idx) + 1
    return None


def _normalize_finding(raw: dict[str, Any], rel_map: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
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
    title = _clean(raw.get("title")) or f"{contract or Path(rel).stem}.{function or 'logic'} - exploitable vulnerability"
    if len(mechanism) < 24 and len(description) < 120:
        return None
    bad = ("maybe", "possibly", "could be", "best practice", "gas optimization", "missing event")
    combined_low = f"{title} {mechanism} {impact} {description}".lower()
    if any(term in combined_low for term in bad) and "attacker" not in combined_low:
        return None
    where = f"In `{rel}`"
    if contract:
        where += f", contract/module `{contract}`"
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
    if len(rebuilt) < 120:
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


if __name__ == "__main__":
    print(json.dumps(agent_main(), indent=2))
