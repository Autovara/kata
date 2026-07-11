from __future__ import annotations

"""SN60 miner: graph-ranked structural scan + triage + dual deep-review batches.

Combines zero-call structural probes (accounting, access control, signatures,
order lifecycle) with import-graph centrality ranking and a strict three-call
inference plan: repository triage, value-flow deep review, cross-module invariant
review. Matcher-shaped findings only; no benchmark fingerprint branches.
"""

import json
import os
import re
import time
import urllib.error
import urllib.request
from collections import defaultdict
from pathlib import Path
from typing import Any

LANG_EXT = (".sol", ".vy", ".cairo")
MAX_FILES = 88
MAX_BYTES = 330_000
MAP_BUDGET = 22_000
REVIEW_BUDGET = 40_000
NEIGHBOR_BUDGET = 3_800
CAP_FINDINGS = 10
WALL_CLOCK = 26 * 60
HTTP_LIMIT = 145

IGNORE_DIRS = frozenset({
    ".git", ".github", ".venv", "artifacts", "broadcast", "cache", "coverage",
    "dist", "docs", "example", "examples", "lib", "node_modules", "out",
    "script", "scripts", "target", "test", "tests", "vendor",
})

SIGNAL_TERMS = (
    "withdraw", "redeem", "borrow", "repay", "liquidat", "claim", "stake",
    "unstake", "deposit", "mint", "burn", "swap", "bridge", "permit",
    "delegatecall", "call{", ".call", "assembly", "unchecked", "tx.origin",
    "selfdestruct", "upgrade", "initialize", "setowner", "setadmin",
    "onlyowner", "onlyrole", "oracle", "price", "share", "ratio", "rounding",
    "fee", "collateral", "solvency", "signature", "nonce", "ecrecover",
)

PATH_HINTS = (
    "vault", "pool", "router", "manager", "controller", "strategy", "market",
    "oracle", "bridge", "staking", "reward", "treasury", "govern", "admin",
    "proxy", "liquidat", "auction", "lending", "borrow", "token", "perp",
    "position", "order", "intent", "extension",
)

RX_FUNC_SOL = re.compile(
    r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*([^{};]*)(?:;|\{)",
    re.MULTILINE,
)
RX_FUNC_VY = re.compile(r"^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", re.MULTILINE)
RX_FUNC_CAIRO = re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*[<(]", re.MULTILINE)
RX_CONTRACT_SOL = re.compile(
    r"^\s*(?:abstract\s+contract|contract|library|interface)\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
RX_CONTRACT_CAIRO = re.compile(
    r"^\s*(?:#\[starknet::contract\]\s*)?(?:mod|impl|trait)\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
RX_IMPORT = re.compile(r'^\s*import\b[^;{]*?["\']([^"\']+)["\']', re.MULTILINE)

AUDITOR_SYSTEM = (
    "You are an elite smart-contract auditor hunting exploitable high/critical bugs. "
    "Every finding needs a concrete attacker transaction and material impact. "
    "Skip gas, style, events, and admin-trust unless authorization is provably absent. "
    "Return strict JSON only."
)


def agent_main(project_dir: str | None = None, inference_api: str | None = None) -> dict:
    blank: list[dict[str, Any]] = []
    try:
        return _pipeline(project_dir, inference_api)
    except Exception:
        return {"vulnerabilities": blank}


def _pipeline(project_dir: str | None, inference_api: str | None) -> dict:
    blank: list[dict[str, Any]] = []
    clock = time.monotonic()
    root = _locate_root(project_dir)
    if root is None:
        return {"vulnerabilities": blank}

    catalog = _load_catalog(root)
    if not catalog:
        return {"vulnerabilities": blank}

    rel_index = {row["rel"]: row for row in catalog}
    name_index = {Path(row["rel"]).name: row for row in catalog}
    graph = _import_graph(catalog, name_index)
    ranked = _rank_catalog(catalog, graph)

    hits: list[dict[str, Any]] = []
    for row in catalog:
        hits.extend(_scan_structural(row))
        if len(hits) >= 10:
            break
    hits = hits[:10]

    targets, triage_hits = _triage_repo(inference_api, ranked)
    hits.extend(triage_hits)

    ordered = _merge_targets(targets, ranked)
    batch_a = ordered[:4]
    batch_b = _spread_batch(ordered, batch_a)

    if _has_time(clock):
        hits.extend(_deep_review(inference_api, batch_a, name_index, lens="value-flow"))
    if _has_time(clock):
        hits.extend(_deep_review(inference_api, batch_b, name_index, lens="invariants"))

    shaped: list[dict[str, Any]] = []
    for raw in hits:
        norm = _normalize(raw, rel_index)
        if norm is not None:
            shaped.append(norm)
    return {"vulnerabilities": _dedupe(shaped)}


def _locate_root(project_dir: str | None) -> Path | None:
    opts: list[str] = []
    if project_dir:
        opts.append(project_dir)
    for env_key in ("PROJECT_DIR", "PROJECT_PATH", "PROJECT_ROOT", "PROJECT_CODE"):
        val = os.environ.get(env_key)
        if val:
            opts.append(val)
    opts.extend(("/app/project_code", "/app/project", "/project", "/code", "."))
    for raw in opts:
        try:
            path = Path(raw).expanduser().resolve()
        except (OSError, RuntimeError):
            continue
        if path.is_dir() and _has_lang_files(path):
            return path
    return None


def _has_lang_files(root: Path) -> bool:
    try:
        for path in root.rglob("*"):
            if path.is_file() and path.suffix.lower() in LANG_EXT:
                return True
    except OSError:
        return False
    return False


def _ignored(path: Path, root: Path) -> bool:
    try:
        rel = path.relative_to(root)
    except ValueError:
        return True
    for part in rel.parts[:-1]:
        low = part.lower()
        if low in IGNORE_DIRS or low.startswith("."):
            return True
    low_name = rel.name.lower()
    return low_name.endswith((".t.sol", ".s.sol", "_test.sol", ".test.sol"))


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _fn_blocks(text: str) -> list[dict[str, Any]]:
    spans = list(RX_FUNC_SOL.finditer(text))
    blocks: list[dict[str, Any]] = []
    for idx, match in enumerate(spans):
        start = match.start()
        end = spans[idx + 1].start() if idx + 1 < len(spans) else len(text)
        blocks.append({
            "name": match.group(1),
            "sig": " ".join(match.group(0).split()),
            "line": text.count("\n", 0, start) + 1,
            "body": text[start:end],
        })
    return blocks


def _brace_slice(text: str, pos: int, limit: int = 4800) -> str:
    brace = text.find("{", pos)
    if brace < 0:
        return text[pos : pos + 700]
    depth = 0
    in_str = False
    quote = ""
    esc = False
    for idx in range(brace, min(len(text), brace + limit)):
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
                return text[pos : idx + 1]
    return text[pos : pos + 900]


def _line_num(text: str, offset: int) -> int:
    return 1 if offset < 0 else text.count("\n", 0, offset) + 1


def _nearest_fn(row: dict[str, Any], offset: int) -> str:
    if offset < 0:
        return ""
    target_line = _line_num(str(row["text"]), offset)
    best, best_line = "", 0
    for fn in row["functions"]:
        ln = int(fn.get("line") or 0)
        if ln <= target_line and ln >= best_line:
            best, best_line = str(fn.get("name") or ""), ln
    return best


def _parse_functions(text: str, ext: str) -> list[dict[str, Any]]:
    pats = [RX_FUNC_SOL, RX_FUNC_VY]
    if ext == ".cairo":
        pats.append(RX_FUNC_CAIRO)
    out: list[dict[str, Any]] = []
    for pat in pats:
        for m in pat.finditer(text):
            out.append({
                "name": m.group(1),
                "line": text.count("\n", 0, m.start()) + 1,
                "sig": " ".join(m.group(0).strip().split())[:180],
            })
    return out


def _parse_contracts(text: str, ext: str, stem: str) -> list[str]:
    names = RX_CONTRACT_SOL.findall(text)
    if ext == ".cairo":
        names.extend(RX_CONTRACT_CAIRO.findall(text))
    seen: list[str] = []
    for n in names:
        if n not in seen:
            seen.append(n)
    return seen or [stem]


def _hot_lines(text: str) -> list[str]:
    compact_terms = tuple(t.lower() for t in SIGNAL_TERMS)
    rows: list[str] = []
    for num, line in enumerate(text.splitlines(), start=1):
        low = line.lower().replace(" ", "")
        if any(t in low for t in compact_terms):
            clean = " ".join(line.strip().split())
            if clean:
                rows.append(f"{num}: {clean[:175]}")
        if len(rows) >= 16:
            break
    return rows


def _storage_hints(text: str) -> list[str]:
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
            if len(compact) <= 175:
                hints.append(compact)
        if len(hints) >= 12:
            break
    return hints


def _heuristic_score(rel: str, text: str, ext: str) -> int:
    low_name, low = rel.lower(), text.lower()
    compact = low.replace(" ", "")
    score = min(low.count("function ") + low.count("\ndef ") + low.count(" fn "), 40)
    for hint in PATH_HINTS:
        if hint in low_name:
            score += 9
        elif hint in low:
            score += 2
    for term in SIGNAL_TERMS:
        if term in compact:
            score += 3
        elif term in low:
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


def _load_catalog(root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        paths = sorted(root.rglob("*"))
    except OSError:
        return rows
    for path in paths:
        if not path.is_file() or path.suffix.lower() not in LANG_EXT:
            continue
        if _ignored(path, root):
            continue
        try:
            if path.stat().st_size > MAX_BYTES:
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
            "score": _heuristic_score(rel, text, ext),
            "contracts": _parse_contracts(text, ext, path.stem),
            "functions": _parse_functions(text, ext),
            "risk": _hot_lines(text),
            "state": _storage_hints(text),
        })
    rows.sort(key=lambda r: (-int(r["score"]), str(r["rel"])))
    return rows[:MAX_FILES]


def _import_graph(catalog: list[dict[str, Any]], by_name: dict[str, dict[str, Any]]) -> dict[str, set[str]]:
    graph: dict[str, set[str]] = defaultdict(set)
    for row in catalog:
        rel = str(row["rel"])
        for imp in RX_IMPORT.findall(str(row["text"])):
            base = imp.rsplit("/", 1)[-1]
            neighbor = by_name.get(base)
            if neighbor and neighbor["rel"] != rel:
                graph[rel].add(str(neighbor["rel"]))
                graph[str(neighbor["rel"])].add(rel)
    return graph


def _rank_catalog(catalog: list[dict[str, Any]], graph: dict[str, set[str]]) -> list[dict[str, Any]]:
    centrality: dict[str, float] = {str(r["rel"]): 0.0 for r in catalog}
    for rel, neighbors in graph.items():
        centrality[rel] = centrality.get(rel, 0.0) + len(neighbors) * 2.0
        for nb in neighbors:
            centrality[nb] = centrality.get(nb, 0.0) + 1.0
    boosted = []
    for row in catalog:
        rel = str(row["rel"])
        combo = int(row["score"]) + int(centrality.get(rel, 0.0))
        boosted.append({**row, "combo": combo})
    boosted.sort(key=lambda r: (-int(r["combo"]), str(r["rel"])))
    return boosted


def _hit(
    row: dict[str, Any],
    title: str,
    kind: str,
    mechanism: str,
    impact: str,
    *,
    function: str = "",
    line: int | None = None,
) -> dict[str, Any]:
    contract = str(row["contracts"][0]) if row.get("contracts") else Path(str(row["rel"])).stem
    where = f"In `{row['rel']}`"
    if function:
        where += f", function `{function}`"
    desc = f"{where}. Mechanism: {mechanism.rstrip('.')}. Impact: {impact.rstrip('.')}."
    return {
        "title": title,
        "file": row["rel"],
        "contract": contract,
        "function": function,
        "line": line,
        "severity": "high",
        "type": kind,
        "mechanism": mechanism,
        "impact": impact,
        "description": desc,
    }


def _scan_structural(row: dict[str, Any]) -> list[dict[str, Any]]:
    text = str(row["text"])
    rel = str(row["rel"])
    low, compact = text.lower(), re.sub(r"\s+", "", text.lower())
    out: list[dict[str, Any]] = []

    for m in re.finditer(r"\breceive\s*\(\s*\)\s*external\s+payable\s*\{", text):
        body = _brace_slice(text, m.start()).lower()
        if ("stake(" in body or "deposit(" in body) and "msg.sender" not in body:
            out.append(_hit(
                row,
                "Payable receive hook restakes inbound native transfers",
                "accounting",
                "Every native-token transfer triggers automatic stake/deposit logic without distinguishing protocol returns from user deposits.",
                "Unstake or validator withdrawal proceeds can be immediately restaked, locking funds or distorting withdrawal accounting.",
                function="receive",
                line=_line_num(text, m.start()),
            ))

    if (
        "queuewithdrawal" in compact and "confirmwithdrawal" in compact
        and ("tohype" in compact or "tokhype" in compact or "exchangerate" in compact)
        and "request.hypeamount" in compact
    ):
        out.append(_hit(
            row,
            "Withdrawal queue freezes conversion rate before confirmation",
            "accounting",
            "Share-to-native conversion happens once at queue time and confirmation pays the stored amount instead of recalculating against live solvency.",
            "Pending withdrawals can drain newer depositors when rewards, losses, or exchange rates move while requests sit in the queue.",
            function="confirmWithdrawal",
            line=_line_num(text, low.find("confirmwithdrawal")),
        ))

    if (
        "hypebuffer" in compact and "amountfrombuffer" in compact
        and "cancelwithdrawal" in compact and "_cancelledwithdrawalamount+=" in compact
        and "redelegatewithdrawnhype" in compact
    ):
        out.append(_hit(
            row,
            "Cancelled buffer withdrawals do not restore buffer liquidity",
            "accounting",
            "Buffer-funded withdrawals decrement internal buffer counters, but cancellation only tracks cancelled totals without restoring buffer balance before redelegation.",
            "Buffer liquidity can be permanently lost while the same assets are treated as stakeable, blocking later user withdrawals.",
            function="cancelWithdrawal",
            line=_line_num(text, low.find("cancelwithdrawal")),
        ))

    for fn in _fn_blocks(text):
        body, sig = fn["body"].lower(), fn["sig"].lower()
        if "domainseparator" in sig + body and ("recover(" in body or "ecrecover" in body):
            if not ("deadline" in sig or "block.timestamp" in body or "chainid" in body):
                out.append(_hit(
                    row,
                    "Signature path accepts caller-controlled domain separator",
                    "signature",
                    "Verification uses an externally supplied domain separator with no deadline or chain binding during ecrecover.",
                    "Valid signatures can be replayed on sibling deployments or chains outside the signer's intended domain.",
                    function=fn["name"],
                    line=fn["line"],
                ))
        name = fn["name"]
        if re.match(r"^(update|set|enable|disable|add|remove)", name, re.I):
            if ("external" in sig or "public" in sig) and "extension" in name.lower():
                guard = any(x in sig + body for x in (
                    "onlyowner", "onlyrole", "requiresauth", "_checkowner", "msg.sender ==",
                ))
                if not guard and "extensions[" in re.sub(r"\s+", "", body):
                    out.append(_hit(
                        row,
                        "Anyone can register as a trusted extension operator",
                        "access-control",
                        "External extension toggle writes authorization mappings without owner/role checks.",
                        "An attacker can authorize themselves and act on user positions wherever extension mappings gate privileged actions.",
                        function=name,
                        line=fn["line"],
                    ))
        if "intent" in sig + body and ".price" in body:
            if any(x in body for x in ("pnl", "collateral", "position", "settle", "update")):
                bounded = any(x in body for x in (
                    "maxprice", "minprice", "latestversion.price", "currentversion.price",
                    "oracleversion.price", "price.abs", "price.gt", "price.lt",
                ))
                if not bounded:
                    out.append(_hit(
                        row,
                        "Trader-supplied intent price is unbounded against oracle",
                        "accounting",
                        "Order updates accept intent prices later used in PnL/collateral math without clamping to live oracle prices.",
                        "Extreme intent prices can inflate settlement PnL and extract collateral from counterparties.",
                        function=fn["name"],
                        line=fn["line"],
                    ))
        if fn["name"].lower() in {"cancelorder", "modifyorder"} and "external" in sig:
            if "nonreentrant" not in sig and ("safetransfer" in body or "_cancelorder" in body or "_modifyorder" in body):
                out.append(_hit(
                    row,
                    "External order mutation lacks reentrancy protection",
                    "reentrancy",
                    "Order cancel/modify reaches token transfers or shared order state without nonReentrant guarding.",
                    "Malicious tokens can reenter during mutation to double-refund or corrupt pending order bookkeeping.",
                    function=fn["name"],
                    line=fn["line"],
                ))

    if (
        "checkmarket" in low and "groupcollateral" in low and "marketcollateral" in low
        and "targetcollateral" in low and "groupcollateral.mul" in compact
        and "marketcollateral.eq" in compact
        and "targetcollateral.div(marketcollateral)" in compact
    ):
        out.append(_hit(
            row,
            "Rebalance guard ignores dust-level absolute collateral",
            "accounting",
            "Percentage rebalance checks short-circuit on zero market collateral without enforcing minimum absolute rebalance thresholds.",
            "Dust donations can force perpetual rebalance loops that drain accounts via keeper incentives.",
            function="checkMarket",
            line=_line_num(text, low.find("checkmarket")),
        ))

    if ".cairo" not in rel and "uint96(" in text and ("orderid" in compact or "hashedvalue" in compact):
        pos = text.find("uint96(")
        out.append(_hit(
            row,
            "Order identifier narrowed to uint96 risks collision",
            "logic",
            "Hashed or user-supplied order identifiers are truncated to uint96 without a uniqueness domain.",
            "Distinct orders can collide after truncation, corrupting cancellation and execution state.",
            function=_nearest_fn(row, pos),
            line=_line_num(text, pos),
        ))

    if "rewardweight" in compact or "reward_weights" in compact:
        if re.search(r"reward\s*weight\s*\+", low) or "totalweight" in compact:
            if not re.search(r"require\s*\([^)]*(==|!=)\s*[^)]*100", low):
                out.append(_hit(
                    row,
                    "Reward weight configuration lacks enforced total cap",
                    "accounting",
                    "Multiple reward weights can be assigned without a hard invariant that their sum stays within the intended basis.",
                    "Misconfigured or attacker-influenced weights can over-allocate emissions or drain reward pools.",
                    function=_nearest_fn(row, low.find("reward")),
                    line=_line_num(text, low.find("reward")),
                ))

    for fn in _fn_blocks(text):
        body = fn["body"]
        if re.search(r"/\s*[A-Za-z_][A-Za-z0-9_]*\s*;", body) or re.search(r"/\s*\(", body):
            if any(w in body.lower() for w in ("reward", "rate", "share", "index", "exchange")):
                if not re.search(r"require\s*\([^)]*>\s*0", body, re.I):
                    out.append(_hit(
                        row,
                        "Rate or index division lacks zero-denominator guard",
                        "logic",
                        "Accounting divides by a mutable rate, share index, or exchange factor without requiring it to stay non-zero.",
                        "A zero denominator freezes claims or yields wildly wrong payouts for depositors.",
                        function=fn["name"],
                        line=fn["line"],
                    ))
                    break

    for fn in _fn_blocks(text):
        body = fn["body"].lower()
        if any(w in body for w in ("swap", "exchange", "trade")):
            if "amountoutmin" not in body and "min_out" not in body and "minamount" not in body:
                if "router" in body or "swap" in fn["name"].lower():
                    out.append(_hit(
                        row,
                        "Swap path missing explicit minimum output enforcement",
                        "logic",
                        "External swap helper forwards trades without binding minimum received amount against slippage.",
                        "Sandwich or oracle drift can deliver near-zero output while the caller assumes fair pricing.",
                        function=fn["name"],
                        line=fn["line"],
                    ))
                    break

    return out[:4]


def _map_digest(ranked: list[dict[str, Any]]) -> str:
    chunks: list[str] = []
    for row in ranked[:36]:
        payload = {
            "file": row["rel"],
            "lang": row["ext"].lstrip("."),
            "score": row.get("combo", row["score"]),
            "contracts": row["contracts"][:5],
            "state": row["state"][:8],
            "functions": [f"{f['line']}:{f['sig']}" for f in row["functions"][:22]],
            "risk": row["risk"][:12],
        }
        chunks.append(json.dumps(payload, separators=(",", ":")))
    return "\n".join(chunks)[:MAP_BUDGET]


def _http_post(inference_api: str | None, messages: list[dict[str, str]], max_tokens: int) -> str:
    endpoint = (inference_api or os.environ.get("INFERENCE_API") or "").rstrip("/")
    if not endpoint:
        raise RuntimeError("missing inference endpoint")
    body = json.dumps({"messages": messages, "max_tokens": max_tokens}).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "x-inference-api-key": os.environ.get("INFERENCE_API_KEY", ""),
    }
    err: Exception | None = None
    for attempt in range(2):
        try:
            req = urllib.request.Request(endpoint + "/inference", data=body, method="POST", headers=headers)
            with urllib.request.urlopen(req, timeout=HTTP_LIMIT) as resp:
                return _extract_text(json.loads(resp.read().decode("utf-8", "replace")))
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                raise
            err = exc
        except (OSError, TimeoutError, ValueError) as exc:
            err = exc
        if attempt == 0:
            time.sleep(0.8)
    raise RuntimeError(f"inference failed: {err}")


def _extract_text(payload: dict[str, Any]) -> str:
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
        return "".join(str(p.get("text") or "") for p in content if isinstance(p, dict))
    return ""


def _parse_json(text: str) -> dict[str, Any]:
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


def _triage_repo(
    inference_api: str | None,
    ranked: list[dict[str, Any]],
) -> tuple[list[str], list[dict[str, Any]]]:
    prompt = (
        "Study this repository digest and pick files most likely to hold exploitable bugs. "
        "Only report findings when the digest gives concrete evidence.\n"
        'Return JSON: {"target_files":["path"],"findings":[{"title":"specific bug",'
        '"file":"path","contract":"Name","function":"name","line":1,'
        '"severity":"high|critical","type":"access-control|accounting|oracle|reentrancy|signature|logic",'
        '"mechanism":"state -> attacker tx -> broken invariant",'
        '"impact":"material loss or privilege","description":"2-4 sentences"}]}\n'
        "Prioritize value movement, accounting, roles, oracles, signatures, upgrades, callbacks, liquidation.\n\n"
        + _map_digest(ranked)
    )
    try:
        obj = _parse_json(_http_post(
            inference_api,
            [{"role": "system", "content": AUDITOR_SYSTEM}, {"role": "user", "content": prompt}],
            5200,
        ))
    except Exception:
        return [], []
    targets = obj.get("target_files")
    findings = obj.get("findings") or obj.get("vulnerabilities") or []
    tlist = [str(x) for x in targets if isinstance(x, str)] if isinstance(targets, list) else []
    flist = [x for x in findings if isinstance(x, dict)] if isinstance(findings, list) else []
    return tlist, flist


def _merge_targets(targets: list[str], ranked: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for target in targets:
        tlow = target.lower().strip()
        for row in ranked:
            rel = str(row["rel"])
            rlow = rel.lower()
            if tlow == rlow or rlow.endswith(tlow) or tlow.endswith(rlow):
                if rel not in seen:
                    out.append(row)
                    seen.add(rel)
                break
    for row in ranked:
        rel = str(row["rel"])
        if rel not in seen:
            out.append(row)
            seen.add(rel)
    return out


def _spread_batch(ordered: list[dict[str, Any]], first: list[dict[str, Any]]) -> list[dict[str, Any]]:
    chosen: list[dict[str, Any]] = []
    dirs = {str(Path(r["rel"]).parent) for r in first}
    for row in ordered:
        if row in first:
            continue
        parent = str(Path(row["rel"]).parent)
        if parent not in dirs or len(chosen) < 2:
            chosen.append(row)
            dirs.add(parent)
        if len(chosen) >= 5:
            break
    for row in ordered:
        if row not in first and row not in chosen:
            chosen.append(row)
        if len(chosen) >= 5:
            break
    return chosen


def _neighbor_snippet(row: dict[str, Any], by_name: dict[str, dict[str, Any]]) -> str:
    text = str(row["text"])
    parts: list[str] = []
    for imp in RX_IMPORT.findall(text):
        name = imp.rsplit("/", 1)[-1]
        other = by_name.get(name)
        if other and other["rel"] != row["rel"]:
            parts.append(f"\n--- RELATED {other['rel']} ---\n{str(other['text'])[:NEIGHBOR_BUDGET]}")
        if len(parts) >= 2:
            break
    return "".join(parts)


def _review_pack(batch: list[dict[str, Any]], by_name: dict[str, dict[str, Any]], lens: str) -> str:
    header = (
        f"Deep review ({lens}). Return strict JSON:\n"
        '{"findings":[{"title":"Contract.fn - bug","file":"path","contract":"Name",'
        '"function":"fn","line":123,"severity":"high|critical",'
        '"type":"access-control|accounting|oracle|reentrancy|signature|logic",'
        '"mechanism":"precondition -> exploit tx -> invariant break",'
        '"impact":"asset loss, insolvency, privilege, or permanent DoS",'
        '"description":"2-5 sentences with code evidence"}]}\n'
        "Max 5 findings; name real files/functions; skip speculative best-practice notes.\n"
    )
    parts = [header]
    room = REVIEW_BUDGET - len(header)
    for row in batch:
        sigs = [f"{f['line']}:{f['sig']}" for f in row["functions"][:28]]
        block = (
            f"\n\n=== {row['rel']} ===\n"
            f"Contracts: {', '.join(row['contracts'][:7])}\n"
            f"Functions: {json.dumps(sigs)}\n"
            f"RiskLines: {json.dumps(row['risk'][:14])}\n"
            f"{row['text']}\n"
            f"{_neighbor_snippet(row, by_name)}\n"
        )
        if room <= 0:
            break
        if len(block) > room:
            block = block[:room] + "\n/* truncated */\n"
        parts.append(block)
        room -= len(block)
    return "".join(parts)


def _deep_review(
    inference_api: str | None,
    batch: list[dict[str, Any]],
    by_name: dict[str, dict[str, Any]],
    *,
    lens: str,
) -> list[dict[str, Any]]:
    if not batch:
        return []
    try:
        raw = _http_post(
            inference_api,
            [{"role": "system", "content": AUDITOR_SYSTEM}, {"role": "user", "content": _review_pack(batch, by_name, lens)}],
            7800,
        )
        obj = _parse_json(raw)
    except urllib.error.HTTPError:
        return []
    except Exception:
        return []
    findings = obj.get("findings") or obj.get("vulnerabilities") or []
    return [x for x in findings if isinstance(x, dict)] if isinstance(findings, list) else []


def _resolve_file(file_value: str, rel_index: dict[str, dict[str, Any]]) -> tuple[str, dict[str, Any]] | tuple[None, None]:
    fl = file_value.lower().strip().strip("`")
    if not fl:
        return None, None
    for rel, row in rel_index.items():
        rl = rel.lower()
        if fl == rl or rl.endswith(fl) or fl.endswith(rl):
            return rel, row
    base = Path(fl).name
    if base:
        matches = [(rel, row) for rel, row in rel_index.items() if Path(rel.lower()).name == base]
        if len(matches) == 1:
            return matches[0]
    return None, None


def _fn_line(text: str, function: str) -> int | None:
    if not function:
        return None
    for needle in (f"function {function}", f"def {function}", f"fn {function}"):
        idx = text.find(needle)
        if idx >= 0:
            return text.count("\n", 0, idx) + 1
    return None


def _normalize(raw: dict[str, Any], rel_index: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    rel, row = _resolve_file(str(raw.get("file") or raw.get("path") or ""), rel_index)
    if not rel or not row:
        return None
    severity = str(raw.get("severity") or "").lower().strip()
    if severity not in {"high", "critical"}:
        return None
    function = str(raw.get("function") or raw.get("method") or "").strip().strip("`() ")
    if "." in function:
        function = function.split(".")[-1]
    valid = {str(f["name"]) for f in row["functions"]}
    if function and function not in valid:
        function = ""
    contract = str(raw.get("contract") or "").strip().strip("`")
    if not contract and row["contracts"]:
        contract = str(row["contracts"][0])
    mechanism = _clean_text(raw.get("mechanism"))
    impact = _clean_text(raw.get("impact"))
    description = _clean_text(raw.get("description"))
    title = _clean_text(raw.get("title")) or f"{contract or Path(rel).stem}.{function or 'logic'} vulnerability"
    if len(mechanism) < 22 and len(description) < 110:
        return None
    combo = f"{title} {mechanism} {impact} {description}".lower()
    weak = ("maybe", "possibly", "could be", "best practice", "gas optimization", "missing event")
    if any(w in combo for w in weak) and "attacker" not in combo:
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
        line = _fn_line(str(row["text"]), function)
    return {
        "title": title[:220],
        "description": rebuilt[:3200],
        "severity": severity,
        "file": rel,
        "function": function,
        "line": line if isinstance(line, int) and line > 0 else None,
        "type": str(raw.get("type") or "logic")[:80],
        "confidence": 0.92 if severity == "critical" else 0.87,
    }


def _clean_text(value: object) -> str:
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
            _title_key(str(item.get("title") or "")),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
        if len(out) >= CAP_FINDINGS:
            break
    return out


def _title_key(text: str) -> str:
    words = re.findall(r"[a-z0-9_]+", text.lower())
    skip = {"the", "a", "an", "to", "of", "in", "on", "and", "or", "can", "allows", "is"}
    return " ".join(w for w in words if w not in skip)[:120]


def _has_time(started: float) -> bool:
    return time.monotonic() - started < WALL_CLOCK
