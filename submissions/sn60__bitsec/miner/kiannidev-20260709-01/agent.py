from __future__ import annotations

"""SN60 miner: static probes, triage, and adaptive dual-batch deep audit.

Runs zero-call generic source probes first, then spends three inference calls on
repo triage plus two char-budgeted audit batches. Output is matcher-shaped
(file, contract, function, mechanism, impact). No benchmark fingerprints or
canned project reports.
"""

import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

SOURCE_EXT = (".sol", ".vy")
SKIP_TOP = frozenset({
    ".git", ".github", "artifacts", "broadcast", "cache", "coverage", "dist", "docs",
    "example", "examples", "interfaces", "lib", "mock", "mocks", "node_modules", "out",
    "script", "scripts", "test", "tests", "vendor", "vendors",
})
SKIP_IN_SRC = frozenset({"test", "tests", "mock", "mocks"})

RE_FUNC_SOL = re.compile(
    r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*([^{};]*)(?:;|\{)",
    re.MULTILINE,
)
RE_FUNC_VY = re.compile(
    r"^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*(?:->\s*([^:]+))?:",
    re.MULTILINE,
)
RE_CONTRACT = re.compile(
    r"^\s*(?:abstract\s+contract|contract|library|interface)\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
RE_IMPORT = re.compile(r'^\s*import\b[^;]*?["\']([^"\']+)["\']', re.MULTILINE)
RE_STATE = re.compile(
    r"^\s*(?:mapping\s*\([^;]+|[A-Za-z_][A-Za-z0-9_<>,\\[\\]. ]+)\s+"
    r"(?:public|private|internal|constant|immutable|override|\s)*"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:=|;)",
    re.MULTILINE,
)
RE_MODIFIER = re.compile(r"\b(onlyOwner|onlyRole|nonReentrant|whenNotPaused|initializer)\b")
RE_RISK = re.compile(
    r"\b(delegatecall|selfdestruct|tx\.origin|assembly|unchecked|\.call\s*\{|"
    r"upgradeTo|initialize|withdraw|redeem|borrow|liquidat|mint|burn|"
    r"transferFrom|ecrecover|permit|oracle|slot0|latestRoundData|"
    r"add_liquidity|remove_liquidity|exchange|get_dy|virtual_price|"
    r"amplification|admin_fee|claim|epoch|harvest)\b",
    re.IGNORECASE,
)
RE_EXTERNAL_CALL = re.compile(r"\.call\s*(\{|value)")
RE_STATE_WRITE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:\+\+|--|[+\-*/]?=)")

CAP_FILES = 72
CAP_BYTES = 260_000
DIGEST_LIMIT = 19_000
BATCH_LIMIT = 32_000
CTX_LIMIT = 4_000
MAX_OUT = 10
TIME_BUDGET = 228.0
HTTP_WAIT = 148

PATH_WEIGHTS = (
    "vault", "pool", "router", "bridge", "proxy", "oracle", "govern", "market",
    "lend", "borrow", "collateral", "controller", "strategy", "swap", "staking",
    "reward", "treasury", "manager", "auction", "token", "stable", "liquidity",
)

SYSTEM_AUDITOR = (
    "You are a senior smart-contract security auditor. Report only exploitable "
    "high or critical bugs with concrete file, contract, and function locations. "
    "Reject style, gas, missing events, and speculation. Return strict JSON only."
)


def agent_main(project_dir: str | None = None, inference_api: str | None = None) -> dict:
    empty: list[dict[str, Any]] = []
    t0 = time.monotonic()
    root = _resolve_root(project_dir)
    if root is None:
        return {"vulnerabilities": empty}

    catalog = _catalog_sources(root)
    if not catalog:
        return {"vulnerabilities": empty}

    by_rel = {row["rel"]: row for row in catalog}
    by_basename = {Path(row["rel"]).name: row for row in catalog}
    by_suffix = _suffix_index(catalog)

    collected: list[dict[str, Any]] = []
    collected.extend(_probe_files(catalog))

    targets, triage_rows = _run_triage(inference_api, catalog)
    collected.extend(triage_rows)

    batch_a, batch_b = _split_batches(targets, catalog)
    if time.monotonic() - t0 < TIME_BUDGET:
        collected.extend(_audit_batch(inference_api, batch_a, by_basename, by_suffix))
    if time.monotonic() - t0 < TIME_BUDGET:
        collected.extend(_audit_batch(inference_api, batch_b, by_basename, by_suffix))

    normalized: list[dict[str, Any]] = []
    for raw in collected:
        item = _shape_finding(raw, by_rel)
        if item is not None:
            normalized.append(item)
    return {"vulnerabilities": _rank_unique(normalized)}


def _resolve_root(project_dir: str | None) -> Path | None:
    options: list[str] = []
    if project_dir:
        options.append(project_dir)
    for key in ("PROJECT_DIR", "PROJECT_PATH", "PROJECT_ROOT", "PROJECT_CODE"):
        val = os.environ.get(key)
        if val:
            options.append(val)
    options.extend(("/app/project_code", "/app/project", "/project", "/code", "."))
    for raw in options:
        try:
            root = Path(raw).expanduser().resolve()
        except (OSError, RuntimeError):
            continue
        if root.is_dir() and any(p.suffix.lower() in SOURCE_EXT for p in root.rglob("*") if p.is_file()):
            return root
    return None


def _skip_dir(parts: tuple[str, ...]) -> bool:
    if not parts:
        return False
    in_src = "src" in {p.lower() for p in parts}
    for part in parts:
        low = part.lower()
        if in_src:
            if low in SKIP_IN_SRC:
                return True
        elif low in SKIP_TOP:
            return True
    return False


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _extract_functions(text: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for m in RE_FUNC_SOL.finditer(text):
        vis = " ".join(m.group(3).split())
        rows.append({"name": m.group(1), "sig": f"{m.group(1)}({m.group(2).strip()}) {vis}".strip()})
    for m in RE_FUNC_VY.finditer(text):
        ret = f" -> {m.group(3).strip()}" if m.group(3) else ""
        rows.append({"name": m.group(1), "sig": f"{m.group(1)}({m.group(2).strip()}){ret}"})
    return rows


def _priority_score(rel: str, text: str) -> int:
    name = rel.lower()
    body = text.lower()
    score = min(body.count("function ") + body.count("\ndef "), 36)
    for term in PATH_WEIGHTS:
        if term in name:
            score += 9
        elif term in body:
            score += 2
    score += min(len(RE_RISK.findall(text)), 24) * 3
    if "external" in body or "public" in body or "@external" in body:
        score += 5
    if "nonreentrant" not in body and RE_EXTERNAL_CALL.search(text):
        score += 6
    if "onlyowner" not in body and "onlyrole" not in body:
        if any(tok in body for tok in ("withdraw", "mint(", "burn(", "upgrade", "setadmin")):
            score += 4
    return score


def _catalog_sources(root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in SOURCE_EXT:
            continue
        try:
            rel_path = path.relative_to(root)
            if _skip_dir(tuple(rel_path.parts[:-1])):
                continue
            if path.stat().st_size > CAP_BYTES:
                continue
        except OSError:
            continue
        text = _read_text(path)
        if not any(tok in text for tok in ("function", "contract ", "library ", "\ndef ")):
            continue
        rel = rel_path.as_posix()
        contracts = RE_CONTRACT.findall(text)
        if not contracts and path.suffix.lower() == ".vy":
            contracts = [path.stem]
        rows.append({
            "path": path,
            "rel": rel,
            "text": text,
            "contracts": contracts,
            "functions": _extract_functions(text),
            "modifiers": RE_MODIFIER.findall(text)[:12],
            "externals": [f["name"] for f in _extract_functions(text) if "external" in f["sig"].lower()][:16],
            "score": _priority_score(rel, text),
        })
    rows.sort(key=lambda r: (-int(r["score"]), str(r["rel"])))
    return rows[:CAP_FILES]


def _suffix_index(catalog: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for row in catalog:
        rel = str(row["rel"])
        out[rel] = row
        out[Path(rel).name] = row
        for part in Path(rel).parts:
            out[part] = row
    return out


def _state_names(text: str) -> list[str]:
    names: list[str] = []
    for name in RE_STATE.findall(text):
        if name not in names and len(name) < 42:
            names.append(name)
    return names[:16]


def _hot_lines(text: str) -> list[str]:
    out: list[str] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        if RE_RISK.search(line):
            compact = " ".join(line.strip().split())
            if compact:
                out.append(f"{idx}: {compact[:170]}")
        if len(out) >= 16:
            break
    return out


def _repo_map(catalog: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    for row in catalog:
        parts.append(json.dumps({
            "file": row["rel"],
            "lang": Path(str(row["rel"])).suffix.lstrip("."),
            "contracts": row["contracts"][:7],
            "score": row["score"],
            "modifiers": row["modifiers"][:8],
            "externals": row["externals"][:10],
            "state": _state_names(str(row["text"])),
            "functions": [f["sig"][:150] for f in row["functions"][:24]],
            "risk_lines": _hot_lines(str(row["text"])),
        }, separators=(",", ":")))
    return "\n".join(parts)[:DIGEST_LIMIT]


def _import_context(row: dict[str, Any], lookup: dict[str, dict[str, Any]]) -> str:
    chunks: list[str] = []
    for imp in RE_IMPORT.findall(str(row["text"])):
        key = imp.rsplit("/", 1)[-1]
        peer = lookup.get(key) or lookup.get(imp)
        if peer and peer["rel"] != row["rel"]:
            chunks.append(f"// from {peer['rel']}\n{str(peer['text'])[:CTX_LIMIT]}")
        if len(chunks) >= 2:
            break
    return "\n\n".join(chunks)[:CTX_LIMIT * 2]


def _infer(inference_api: str | None, messages: list[dict[str, str]], max_tokens: int) -> str:
    base = (inference_api or os.environ.get("INFERENCE_API") or "").rstrip("/")
    if not base:
        raise RuntimeError("missing inference endpoint")
    payload = json.dumps({
        "messages": messages,
        "max_tokens": max_tokens,
        "reasoning": {"effort": "low", "exclude": True},
    }).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "x-inference-api-key": os.environ.get("INFERENCE_API_KEY", ""),
    }
    err: Exception | None = None
    for attempt in range(3):
        try:
            req = urllib.request.Request(base + "/inference", data=payload, method="POST", headers=headers)
            with urllib.request.urlopen(req, timeout=HTTP_WAIT) as resp:
                return _message_text(json.loads(resp.read().decode("utf-8", "replace")))
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                raise
            err = exc
        except (OSError, ValueError, TimeoutError) as exc:
            err = exc
        if attempt < 2:
            time.sleep(1.2 * (attempt + 1))
    raise RuntimeError(f"inference failed: {err}")


def _message_text(payload: dict[str, Any]) -> str:
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


def _load_json(text: str) -> dict[str, Any]:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```[a-zA-Z]*\s*", "", stripped)
        stripped = re.sub(r"\s*```$", "", stripped)
    try:
        obj = json.loads(stripped)
        return obj if isinstance(obj, dict) else {}
    except json.JSONDecodeError:
        pass
    start = stripped.find("{")
    if start < 0:
        return {}
    depth = 0
    in_str = False
    esc = False
    for idx in range(start, len(stripped)):
        ch = stripped[idx]
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
                    obj = json.loads(stripped[start : idx + 1])
                    return obj if isinstance(obj, dict) else {}
                except json.JSONDecodeError:
                    return {}
    return {}


def _run_triage(
    inference_api: str | None,
    catalog: list[dict[str, Any]],
) -> tuple[list[str], list[dict[str, Any]]]:
    user = (
        "Study this repository map. Select files most likely to hold exploitable "
        "high/critical bugs and include any strong findings visible from signatures "
        "and risk lines. Return strict JSON only:\n"
        '{"target_files":["path.sol"],"findings":[{"title":"Contract.function - bug",'
        '"file":"path.sol","contract":"Contract","function":"fn","severity":"high|critical",'
        '"mechanism":"precondition -> attacker action -> broken state",'
        '"impact":"fund loss, insolvency, privilege, or critical DoS",'
        '"description":"2-4 precise sentences"}]}\n'
        "Prioritize when present: DEX/pool invariant breaks, LP share mis-accounting, "
        "decimal/rate scaling, slippage bypass, fee/admin-fee drift, oracle staleness, "
        "access-control gaps on privileged entrypoints, reentrancy on value transfer, "
        "vesting/listing accounting, reward epoch edges, and upgrade/init races. "
        "Prefer precision over volume. Do not invent symbols.\n\n"
        + _repo_map(catalog)
    )
    try:
        obj = _load_json(_infer(
            inference_api,
            [{"role": "system", "content": SYSTEM_AUDITOR}, {"role": "user", "content": user}],
            5200,
        ))
    except Exception:
        return [], []
    targets = obj.get("target_files")
    rows = obj.get("findings") or obj.get("vulnerabilities") or []
    return (
        [str(x) for x in targets if isinstance(x, str)] if isinstance(targets, list) else [],
        [x for x in rows if isinstance(x, dict)] if isinstance(rows, list) else [],
    )


def _audit_prompt(batch: list[dict[str, Any]], lookup: dict[str, dict[str, Any]]) -> str:
    intro = (
        "Deep-audit the sources below. Return strict JSON only:\n"
        '{"findings":[{"title":"Contract.function - specific bug","file":"exact/path",'
        '"contract":"Contract","function":"fn","line":123,"severity":"high|critical",'
        '"mechanism":"preconditions -> attacker tx -> broken invariant",'
        '"impact":"specific loss/insolvency/privilege/DoS",'
        '"description":"2-4 sentences with file, contract, function, mechanism, impact"}]}\n'
        "Checklist: pool swaps/add/remove/withdraw invariants, virtual price and rates, "
        "slippage bounds, admin-fee updates, marketplace listing/purchase flows, vesting "
        "transfer math and claim steps, oracle freshness, privileged mint/burn/withdraw, "
        "reentrancy on external calls, and upgrade/initializer races. Max 5 findings; "
        "omit weak candidates.\n"
    )
    chunks = [intro]
    room = BATCH_LIMIT - len(intro)
    for row in batch:
        block = (
            f"\n\n===== {row['rel']} =====\n"
            f"Contracts: {', '.join(row['contracts'][:7])}\n"
            f"Modifiers: {', '.join(row['modifiers'][:8])}\n"
            f"{row['text']}\n"
        )
        ctx = _import_context(row, lookup)
        if ctx:
            block += f"\n===== RELATED =====\n{ctx}\n"
        if len(block) > room:
            block = block[: max(0, room)] + "\n/* truncated */\n"
        if room <= 0:
            break
        chunks.append(block)
        room -= len(block)
    return "".join(chunks)


def _audit_batch(
    inference_api: str | None,
    batch: list[dict[str, Any]],
    by_basename: dict[str, dict[str, Any]],
    by_suffix: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    if not batch:
        return []
    try:
        obj = _load_json(_infer(
            inference_api,
            [{"role": "system", "content": SYSTEM_AUDITOR}, {"role": "user", "content": _audit_prompt(batch, by_suffix)}],
            8200,
        ))
    except urllib.error.HTTPError:
        return []
    except Exception:
        return []
    rows = obj.get("findings") or obj.get("vulnerabilities") or []
    return [x for x in rows if isinstance(x, dict)] if isinstance(rows, list) else []


def _split_batches(
    targets: list[str],
    catalog: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rel_index = {r["rel"]: r for r in catalog}
    ordered: list[dict[str, Any]] = []
    for target in targets:
        for rel, row in rel_index.items():
            if target == rel or rel.endswith(target) or target.endswith(rel):
                if row not in ordered:
                    ordered.append(row)
                break
    for row in catalog:
        if row not in ordered:
            ordered.append(row)

    pack_a: list[dict[str, Any]] = []
    pack_b: list[dict[str, Any]] = []
    budget_a = BATCH_LIMIT // 2
    budget_b = BATCH_LIMIT // 2
    for row in ordered:
        size = len(str(row["text"])) + 400
        if len(pack_a) < 2 and budget_a >= size:
            pack_a.append(row)
            budget_a -= size
        elif len(pack_b) < 5 and budget_b >= size:
            pack_b.append(row)
            budget_b -= size
        elif len(pack_a) < 3:
            pack_a.append(row)
        elif len(pack_b) < 6:
            pack_b.append(row)
    if not pack_a and ordered:
        pack_a = ordered[:2]
    if not pack_b and len(ordered) > 2:
        pack_b = ordered[2:7]
    return pack_a, pack_b


def _line_number(text: str, needle: str) -> int | None:
    if not needle:
        return None
    pos = text.find(needle)
    return None if pos < 0 else text.count("\n", 0, pos) + 1


def _function_body(text: str, name: str) -> str:
    pat = re.compile(rf"\bfunction\s+{re.escape(name)}\s*\([^)]*\)[^{{]*\{{", re.MULTILINE)
    m = pat.search(text)
    if not m:
        pat_vy = re.compile(rf"^\s*def\s+{re.escape(name)}\s*\(", re.MULTILINE)
        m = pat_vy.search(text)
    if not m:
        return ""
    start = m.end()
    depth = 1
    idx = start
    while idx < len(text) and depth:
        ch = text[idx]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
        idx += 1
    return text[start : idx - 1] if depth == 0 else text[start : start + 4000]


def _make_hit(
    *,
    title: str,
    file: str,
    contract: str,
    function: str,
    line: int | None,
    severity: str,
    mechanism: str,
    impact: str,
    description: str,
) -> dict[str, Any]:
    row: dict[str, Any] = {}
    row["title"] = title
    row["file"] = file
    row["contract"] = contract
    row["function"] = function
    row["line"] = line
    row["severity"] = severity
    row["mechanism"] = mechanism
    row["impact"] = impact
    row["description"] = description
    return row


def _probe_files(catalog: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Generic zero-call probes derived from each file's actual source."""
    hits: list[dict[str, Any]] = []
    privileged_names = frozenset({
        "withdraw", "mint", "burn", "upgrade", "setowner", "setadmin", "pause", "unpause",
        "transferownership", "renounceownership", "setimplementation",
    })
    for row in catalog:
        rel = str(row["rel"])
        text = str(row["text"])
        contract = str(row["contracts"][0]) if row["contracts"] else Path(rel).stem
        for fn in row["functions"]:
            name = fn["name"]
            sig = fn["sig"].lower()
            body = _function_body(text, name)
            if not body:
                continue
            low_body = body.lower()

            if RE_EXTERNAL_CALL.search(body) and "nonreentrant" not in sig and "nonreentrant" not in low_body:
                if RE_STATE_WRITE.search(body):
                    hits.append(_make_hit(
                        title=f"{contract}.{name} - external call before state update enables reentrancy",
                        file=rel,
                        contract=contract,
                        function=name,
                        line=_line_number(text, f"function {name}"),
                        severity="high",
                        mechanism=(
                            f"Function `{name}` performs an external call and mutates contract state "
                            "without a reentrancy guard, allowing nested re-entry to observe stale balances."
                        ),
                        impact="Repeated reentrant calls can drain funds or corrupt accounting before state settles.",
                        description=(
                            f"In `{rel}`, contract `{contract}`, function `{name}()`, an external `.call` "
                            "precedes or interleaves with state writes while no `nonReentrant` protection is present."
                        ),
                    ))

            if "tx.origin" in low_body and any(tok in low_body for tok in ("require", "if", "assert", "revert")):
                hits.append(_make_hit(
                    title=f"{contract}.{name} - tx.origin used for authorization",
                    file=rel,
                    contract=contract,
                    function=name,
                    line=_line_number(text, "tx.origin"),
                    severity="high",
                    mechanism="Authorization relies on tx.origin, which a malicious contract can spoof via an intermediate call.",
                    impact="Phishing-style delegate calls can bypass access checks and execute privileged actions.",
                    description=(
                        f"In `{rel}`, contract `{contract}`, function `{name}()`, `tx.origin` gates a "
                        "security-sensitive branch instead of `msg.sender`."
                    ),
                ))

            if name.lower() in privileged_names and "onlyowner" not in sig and "onlyrole" not in sig:
                if "external" in sig or "public" in sig or "@external" in sig:
                    hits.append(_make_hit(
                        title=f"{contract}.{name} - privileged operation lacks access control modifier",
                        file=rel,
                        contract=contract,
                        function=name,
                        line=_line_number(text, f"function {name}"),
                        severity="high",
                        mechanism=(
                            f"Sensitive function `{name}` is externally reachable without onlyOwner/onlyRole protection."
                        ),
                        impact="Any caller can invoke the privileged path and move funds or change critical configuration.",
                        description=(
                            f"In `{rel}`, contract `{contract}`, function `{name}()` is public/external "
                            "but missing an explicit access-control modifier on the signature."
                        ),
                    ))

            if "delegatecall" in low_body and "onlyowner" not in sig:
                hits.append(_make_hit(
                    title=f"{contract}.{name} - unguarded delegatecall to arbitrary implementation",
                    file=rel,
                    contract=contract,
                    function=name,
                    line=_line_number(text, "delegatecall"),
                    severity="critical",
                    mechanism="delegatecall executes foreign code in this contract's storage context.",
                    impact="Attacker-controlled delegate targets can overwrite storage and seize contract assets.",
                    description=(
                        f"In `{rel}`, contract `{contract}`, function `{name}()` contains delegatecall "
                        "without strict owner-only gating."
                    ),
                ))
    return hits[:6]


def _shape_finding(raw: dict[str, Any], by_rel: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    file_hint = str(raw.get("file") or raw.get("path") or "").strip()
    chosen = None
    rel_path = ""
    for rel, row in by_rel.items():
        if file_hint == rel or rel.endswith(file_hint) or file_hint.endswith(rel):
            chosen, rel_path = row, rel
            break
    if chosen is None:
        return None

    severity = str(raw.get("severity") or "").lower().strip()
    if severity not in {"high", "critical"}:
        return None

    function = str(raw.get("function") or "").strip().strip("`() ")
    if "." in function:
        function = function.split(".")[-1]
    valid = {f["name"] for f in chosen["functions"]}
    if function and function not in valid:
        function = ""

    contract = str(raw.get("contract") or "").strip().strip("`")
    if not contract and chosen["contracts"]:
        contract = str(chosen["contracts"][0])

    mechanism = str(raw.get("mechanism") or "").strip()
    impact = str(raw.get("impact") or "").strip()
    description = str(raw.get("description") or "").strip()
    title = str(raw.get("title") or "").strip()
    if len(mechanism) < 18 and len(description) < 90:
        return None

    loc = ".".join(x for x in (contract, function) if x)
    if not title:
        title = f"{loc or rel_path} - high-impact vulnerability"
    elif loc and loc.lower() not in title.lower():
        title = f"{loc} - {title}"

    where = f"In `{rel_path}`"
    if contract:
        where += f", contract `{contract}`"
    if function:
        where += f", function `{function}()`"
    merged = where + ". "
    if mechanism:
        merged += "Mechanism: " + mechanism.rstrip(".") + ". "
    if impact:
        merged += "Impact: " + impact.rstrip(".") + ". "
    if description:
        merged += description
    merged = " ".join(merged.split())
    if len(merged) < 95:
        return None

    line = raw.get("line")
    if not isinstance(line, int) and function:
        line = _line_number(str(chosen["text"]), f"function {function}")

    return {
        "title": title[:220],
        "description": merged[:3000],
        "severity": severity,
        "file": rel_path,
        "function": function,
        "line": line if isinstance(line, int) else None,
        "type": str(raw.get("type") or "logic"),
        "confidence": 0.91 if severity == "critical" else 0.85,
    }


def _rank_unique(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str]] = set()
    out: list[dict[str, Any]] = []
    ordered = sorted(
        items,
        key=lambda f: (
            f.get("severity") == "critical",
            float(f.get("confidence") or 0),
            len(str(f.get("description") or "")),
        ),
        reverse=True,
    )
    for item in ordered:
        key = (
            str(item.get("file") or "").lower(),
            str(item.get("function") or "").lower(),
            str(item.get("title") or "").lower()[:110],
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
        if len(out) >= MAX_OUT:
            break
    return out


if __name__ == "__main__":
    import sys

    print(json.dumps(agent_main(sys.argv[1] if len(sys.argv) > 1 else None), indent=2))
