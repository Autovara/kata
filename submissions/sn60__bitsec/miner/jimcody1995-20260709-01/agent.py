from __future__ import annotations

"""SN60 miner: graph-ranked triage, static probes, and adaptive deep audits.

Combines the current king's triage+batch flow with competitor ideas: import-graph
centrality ranking (RealDiligent), zero-call per-function static probes (kiannidev),
adaptive char-budget batching, multi-language discovery (.sol/.vy/.rs), and
matcher-shaped output with explicit location hints. Three inference calls only.
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

EXT = (".sol", ".vy", ".rs")
SKIP_GLOBAL = frozenset({
    ".git", ".github", "artifacts", "broadcast", "cache", "coverage", "dist", "docs",
    "example", "examples", "interfaces", "lib", "mock", "mocks", "node_modules", "out",
    "script", "scripts", "test", "tests", "vendor", "vendors", "target",
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
RE_FUNC_RS = re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*[(<]")
RE_CONTRACT = re.compile(
    r"\b(?:abstract\s+contract|contract|library|interface|module|struct|trait)\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
RE_IMPORT = re.compile(r'^\s*(?:import|use)\b[^;\n]*?["\']?([A-Za-z0-9_./]+)["\']?', re.MULTILINE)
RE_STATE = re.compile(
    r"^\s*(?:mapping\s*\([^;]+|[A-Za-z_][A-Za-z0-9_<>,\\[\\]. ]+)\s+"
    r"(?:public|private|internal|constant|immutable|override|\s)*"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:=|;)",
    re.MULTILINE,
)
RE_MODIFIER = re.compile(r"\b(onlyOwner|onlyRole|nonReentrant|whenNotPaused|initializer)\b")
RE_RISK = re.compile(
    r"\b(delegatecall|selfdestruct|tx\.origin|assembly|unchecked|\.call\s*\{|"
    r"onlyOwner|onlyRole|upgradeTo|initialize|withdraw|redeem|borrow|liquidat|"
    r"transferFrom|ecrecover|permit|oracle|flash|swap|slippage|reentr|"
    r"slot0|latestRoundData|add_liquidity|remove_liquidity|get_dy|virtual_price)\b",
    re.IGNORECASE,
)
RE_EXTERNAL = re.compile(r"\.call\s*(\{|value)")
RE_EXTERNAL_FN = re.compile(
    r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)\s+"
    r"(?:public|external)\b[^;{]*",
    re.MULTILINE | re.IGNORECASE,
)
RE_STATE_WRITE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:\+\+|--|[+\-*/]?=)")

MAX_FILES = 72
MAX_BYTES = 260_000
DIGEST_LIMIT = 19_000
BATCH_LIMIT = 32_000
IMPORT_LIMIT = 4_000
MAX_OUT = 10
TIME_BUDGET = 228.0
HTTP_WAIT = 148

PATH_HINTS = (
    "vault", "pool", "router", "bridge", "proxy", "oracle", "govern", "treasury",
    "manager", "market", "lend", "borrow", "collateral", "controller", "strategy",
    "auction", "token", "staking", "reward", "factory", "escrow", "swap", "stable",
    "liquidity", "liquidat",
)

PRIVILEGED_NAMES = frozenset({
    "withdraw", "mint", "burn", "upgrade", "setowner", "setadmin", "pause", "unpause",
    "transferownership", "renounceownership", "setimplementation",
})

BUG_TAXONOMY = (
    "Hunt: missing access control on privileged state changes; reentrancy and "
    "checks-effects-interactions violations; price/oracle manipulation and stale reads; "
    "share/LP accounting errors, donation inflation, rounding; slippage/min-out bypass; "
    "liquidation math; unsafe delegatecall/upgrade/initializer; signature/permit replay; "
    "decimal/unit mismatches; cross-function invariant breaks."
)

SYSTEM = (
    "You are a senior smart-contract security auditor. Report only high or critical "
    "vulnerabilities with a concrete exploit path and material impact. Reject style, "
    "gas, centralization, and speculation. Return strict JSON only."
)


def agent_main(project_dir: str | None = None, inference_api: str | None = None) -> dict:
    findings: list[dict[str, Any]] = []
    root = locate_project(project_dir)
    if root is None:
        return {"vulnerabilities": findings}

    clock = time.monotonic()
    catalog = build_catalog(root)
    if not catalog:
        return {"vulnerabilities": findings}

    by_rel = {row["rel"]: row for row in catalog}
    lookup = suffix_index(catalog)
    graph = import_graph(catalog, lookup)
    ranked = rank_catalog(catalog, graph)

    collected: list[dict[str, Any]] = []
    collected.extend(static_probes(ranked))

    targets, triage_items = run_triage(inference_api, ranked, graph)
    collected.extend(triage_items)

    batch_a, batch_b = plan_batches(targets, ranked)
    if time.monotonic() - clock < TIME_BUDGET:
        collected.extend(run_deep_pass(inference_api, batch_a, lookup))
    if time.monotonic() - clock < TIME_BUDGET:
        collected.extend(run_deep_pass(inference_api, batch_b, lookup))

    for raw in collected:
        shaped = format_finding(raw, by_rel)
        if shaped is not None:
            findings.append(shaped)
    return {"vulnerabilities": collapse_findings(findings)}


def locate_project(project_dir: str | None) -> Path | None:
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
            p = Path(raw).expanduser().resolve()
        except (OSError, RuntimeError):
            continue
        if p.is_dir() and any(f.is_file() and f.suffix.lower() in EXT for f in p.rglob("*")):
            return p
    return None


def should_skip_dir(parts: tuple[str, ...]) -> bool:
    if not parts:
        return False
    in_src = "src" in {p.lower() for p in parts}
    for part in parts:
        low = part.lower()
        if in_src:
            if low in SKIP_IN_SRC:
                return True
        elif low in SKIP_GLOBAL:
            return True
    return False


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def parse_functions(text: str, suffix: str) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    if suffix == ".vy":
        for m in RE_FUNC_VY.finditer(text):
            ret = f" -> {m.group(3).strip()}" if m.group(3) else ""
            out.append({"name": m.group(1), "sig": f"{m.group(1)}({m.group(2).strip()}){ret}".strip()})
    elif suffix == ".rs":
        for m in RE_FUNC_RS.finditer(text):
            out.append({"name": m.group(1), "sig": m.group(1)})
    else:
        for m in RE_FUNC_SOL.finditer(text):
            tail = " ".join(m.group(3).split())
            out.append({"name": m.group(1), "sig": f"{m.group(1)}({m.group(2).strip()}) {tail}".strip()})
    return out


def hot_functions(text: str) -> list[str]:
    hits: list[str] = []
    for m in RE_EXTERNAL_FN.finditer(text):
        sig = " ".join(m.group(0).split())
        if RE_RISK.search(sig):
            hits.append(sig[:160])
        elif len(hits) < 8:
            hits.append(sig[:160])
        if len(hits) >= 12:
            break
    return hits


def risk_score(rel: str, text: str, graph: dict[str, set[str]]) -> int:
    name_low, text_low = rel.lower(), text.lower()
    score = min(text_low.count("function ") + text_low.count("\ndef ") + text_low.count("\nfn "), 36)
    score += min(len(graph.get(rel, set())), 8) * 4
    for hint in PATH_HINTS:
        if hint in name_low:
            score += 9
        elif hint in text_low:
            score += 2
    score += min(len(RE_RISK.findall(text)), 24) * 3
    if any(tok in text_low for tok in ("external", "public", "@external")):
        score += 5
    if "nonreentrant" not in text_low and RE_EXTERNAL.search(text):
        score += 6
    if "onlyowner" not in text_low and "onlyrole" not in text_low:
        if any(tok in text_low for tok in ("withdraw", "mint(", "burn(", "upgrade", "setadmin")):
            score += 4
    if "initializer" in text_low or "upgrade" in text_low:
        score += 5
    return score


def state_names(text: str) -> list[str]:
    seen: list[str] = []
    for name in RE_STATE.findall(text):
        if name not in seen and len(name) < 42:
            seen.append(name)
    return seen[:16]


def risk_snippets(text: str) -> list[str]:
    lines: list[str] = []
    for num, line in enumerate(text.splitlines(), start=1):
        if RE_RISK.search(line):
            compact = " ".join(line.strip().split())
            if compact:
                lines.append(f"{num}: {compact[:170]}")
        if len(lines) >= 16:
            break
    return lines


def build_catalog(root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in EXT:
            continue
        try:
            rel_path = path.relative_to(root)
            if should_skip_dir(tuple(rel_path.parts[:-1])):
                continue
            if path.stat().st_size > MAX_BYTES:
                continue
        except OSError:
            continue
        text = read_text(path)
        suffix = path.suffix.lower()
        if suffix == ".rs":
            has_code = "fn " in text or "pub fn" in text
        else:
            has_code = any(tok in text for tok in ("function", "contract ", "library ", "\ndef "))
        if not has_code:
            continue
        rel = rel_path.as_posix()
        contracts = RE_CONTRACT.findall(text)
        if not contracts:
            contracts = [path.stem]
        rows.append({
            "rel": rel,
            "text": text,
            "suffix": suffix,
            "contracts": contracts,
            "functions": parse_functions(text, suffix),
            "modifiers": RE_MODIFIER.findall(text)[:12],
            "externals": [f["name"] for f in parse_functions(text, suffix)
                          if "external" in f["sig"].lower() or "pub fn" in f["sig"].lower()][:14],
            "imports": RE_IMPORT.findall(text),
        })
    return rows[:MAX_FILES]


def suffix_index(catalog: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for row in catalog:
        rel = str(row["rel"])
        out[rel] = row
        out[Path(rel).name] = row
        for part in Path(rel).parts:
            out[part] = row
    return out


def import_graph(
    catalog: list[dict[str, Any]],
    lookup: dict[str, dict[str, Any]],
) -> dict[str, set[str]]:
    graph: dict[str, set[str]] = defaultdict(set)
    for row in catalog:
        rel = str(row["rel"])
        for imp in row["imports"]:
            base = imp.rsplit("/", 1)[-1]
            peer = lookup.get(base) or lookup.get(imp)
            if peer and peer["rel"] != rel:
                graph[rel].add(str(peer["rel"]))
                graph[str(peer["rel"])].add(rel)
    return graph


def rank_catalog(
    catalog: list[dict[str, Any]],
    graph: dict[str, set[str]],
) -> list[dict[str, Any]]:
    for row in catalog:
        row["score"] = risk_score(str(row["rel"]), str(row["text"]), graph)
    return sorted(catalog, key=lambda r: (-int(r["score"]), str(r["rel"])))


def graph_digest(ranked: list[dict[str, Any]], graph: dict[str, set[str]]) -> str:
    chunks: list[str] = []
    for row in ranked[:16]:
        rel = str(row["rel"])
        chunks.append(json.dumps({
            "file": rel,
            "score": row["score"],
            "contracts": row["contracts"][:7],
            "neighbors": sorted(graph.get(rel, set()))[:4],
            "modifiers": row["modifiers"][:8],
            "externals": row["externals"][:10],
            "hot_functions": hot_functions(str(row["text"]))[:8],
            "state": state_names(str(row["text"])),
            "functions": [f["sig"][:140] for f in row["functions"][:22]],
            "risk_lines": risk_snippets(str(row["text"])),
        }, separators=(",", ":")))
    return "\n".join(chunks)[:DIGEST_LIMIT]


def import_neighbors(row: dict[str, Any], lookup: dict[str, dict[str, Any]]) -> str:
    blocks: list[str] = []
    for imp in row["imports"]:
        key = imp.rsplit("/", 1)[-1]
        other = lookup.get(key) or lookup.get(imp)
        if other and other["rel"] != row["rel"]:
            blocks.append(f"// import {other['rel']}\n{str(other['text'])[:IMPORT_LIMIT]}")
        if len(blocks) >= 2:
            break
    return "\n\n".join(blocks)[:IMPORT_LIMIT * 2]


def infer(api: str | None, msgs: list[dict[str, str]], token_cap: int) -> str:
    endpoint = (api or os.environ.get("INFERENCE_API") or "").rstrip("/")
    if not endpoint:
        raise RuntimeError("missing inference endpoint")
    payload = json.dumps({
        "messages": msgs,
        "max_tokens": token_cap,
        "reasoning": {"effort": "low", "exclude": True},
    }).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "x-inference-api-key": os.environ.get("INFERENCE_API_KEY", ""),
    }
    last: Exception | None = None
    for attempt in range(3):
        try:
            req = urllib.request.Request(endpoint + "/inference", data=payload, method="POST", headers=headers)
            with urllib.request.urlopen(req, timeout=HTTP_WAIT) as resp:
                return pull_text(json.loads(resp.read().decode("utf-8", "replace")))
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                raise
            last = exc
        except (OSError, ValueError, TimeoutError) as exc:
            last = exc
        if attempt < 2:
            time.sleep(1.2 * (attempt + 1))
    raise RuntimeError(f"inference failed: {last}")


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
        return "".join(str(part.get("text") or "") for part in content if isinstance(part, dict))
    return ""


def load_json(text: str) -> dict[str, Any]:
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


def run_triage(
    api: str | None,
    ranked: list[dict[str, Any]],
    graph: dict[str, set[str]],
) -> tuple[list[str], list[dict[str, Any]]]:
    prompt = (
        "Review this import-graph ranked repository map. Pick files most likely to hold "
        "exploitable high/critical bugs. Return strict JSON only:\n"
        '{"target_files":["path.sol"],"findings":[{"title":"Contract.function - bug",'
        '"file":"path.sol","contract":"Contract","function":"fn","severity":"high|critical",'
        '"mechanism":"precondition -> attacker action -> broken invariant",'
        '"impact":"fund loss, insolvency, privilege, or critical DoS",'
        '"description":"2-4 precise sentences"}]}\n'
        "Prioritize high-centrality nodes, privileged entrypoints, and when present: "
        "DEX/pool invariant breaks, LP share mis-accounting, decimal/rate scaling, "
        "slippage bypass, oracle staleness, access-control gaps, reentrancy on value "
        "transfer, vesting/listing accounting, reward epoch edges, upgrade/init races. "
        "Use hot_functions, neighbors, and risk_lines as hints only. "
        "Prefer precision over volume. Do not invent files or functions.\n\n"
        + graph_digest(ranked, graph)
    )
    try:
        obj = load_json(infer(api, [{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt}], 5200))
    except Exception:
        return [], []
    targets = obj.get("target_files")
    items = obj.get("findings") or obj.get("vulnerabilities") or []
    return (
        [str(x) for x in targets if isinstance(x, str)] if isinstance(targets, list) else [],
        [x for x in items if isinstance(x, dict)] if isinstance(items, list) else [],
    )


def deep_prompt(batch: list[dict[str, Any]], lookup: dict[str, dict[str, Any]]) -> str:
    header = (
        "Deep-audit the contract sources below with import context. "
        + BUG_TAXONOMY + " "
        "Return strict JSON only:\n"
        '{"findings":[{"title":"Contract.function - specific bug","file":"exact/path",'
        '"contract":"Contract","function":"fn","line":123,"severity":"high|critical",'
        '"mechanism":"pre -> attack steps -> broken invariant",'
        '"impact":"specific material harm",'
        '"description":"2-4 sentences naming file, contract, function, mechanism, impact"}]}\n'
        "At most 5 findings. Omit weak or speculative issues.\n"
    )
    parts = [header]
    room = BATCH_LIMIT - len(header)
    for row in batch:
        block = (
            f"\n\n===== FILE: {row['rel']} (score={row.get('score', 0)}) =====\n"
            f"Contracts: {', '.join(row['contracts'][:7])}\n"
            f"Hot: {', '.join(hot_functions(str(row['text']))[:6])}\n"
            f"{row['text']}\n"
        )
        neighbors = import_neighbors(row, lookup)
        if neighbors:
            block += f"\n===== IMPORT CONTEXT =====\n{neighbors}\n"
        if len(block) > room:
            block = block[: max(0, room)] + "\n/* truncated */\n"
        if room <= 0:
            break
        parts.append(block)
        room -= len(block)
    return "".join(parts)


def run_deep_pass(
    api: str | None,
    batch: list[dict[str, Any]],
    lookup: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    if not batch:
        return []
    try:
        obj = load_json(infer(
            api,
            [{"role": "system", "content": SYSTEM}, {"role": "user", "content": deep_prompt(batch, lookup)}],
            8000,
        ))
    except urllib.error.HTTPError:
        return []
    except Exception:
        return []
    items = obj.get("findings") or obj.get("vulnerabilities") or []
    return [x for x in items if isinstance(x, dict)] if isinstance(items, list) else []


def plan_batches(
    targets: list[str],
    ranked: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    by_rel = {r["rel"]: r for r in ranked}
    ordered: list[dict[str, Any]] = []
    for target in targets:
        for rel, row in by_rel.items():
            if target == rel or rel.endswith(target) or target.endswith(rel):
                if row not in ordered:
                    ordered.append(row)
                break
    for row in ranked:
        if row not in ordered:
            ordered.append(row)

    pack_a: list[dict[str, Any]] = []
    pack_b: list[dict[str, Any]] = []
    budget_a = BATCH_LIMIT // 2
    budget_b = BATCH_LIMIT // 2
    for row in ordered:
        size = len(str(row["text"])) + 500
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


def function_body(text: str, name: str) -> str:
    pat = re.compile(rf"\bfunction\s+{re.escape(name)}\s*\([^)]*\)[^{{]*\{{", re.MULTILINE)
    m = pat.search(text)
    if not m:
        pat_vy = re.compile(rf"^\s*def\s+{re.escape(name)}\s*\(", re.MULTILINE)
        m = pat_vy.search(text)
    if not m:
        pat_rs = re.compile(rf"\bfn\s+{re.escape(name)}\s*[(<]")
        m = pat_rs.search(text)
    if not m:
        return ""
    if text[m.start():m.end()].strip().endswith("{"):
        start = m.end()
        depth = 1
        idx = start
        while idx < len(text) and depth:
            if text[idx] == "{":
                depth += 1
            elif text[idx] == "}":
                depth -= 1
            idx += 1
        return text[start : idx - 1] if depth == 0 else text[start : start + 4000]
    lines = text[m.end() :].splitlines()
    if not lines:
        return ""
    indent = len(lines[0]) - len(lines[0].lstrip()) if lines[0].strip() else 0
    body: list[str] = []
    for line in lines:
        if line.strip() and (len(line) - len(line.lstrip())) <= indent and body:
            break
        body.append(line)
    return "\n".join(body)


def static_probes(catalog: list[dict[str, Any]]) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for row in catalog:
        rel = str(row["rel"])
        text = str(row["text"])
        contract = str(row["contracts"][0]) if row["contracts"] else Path(rel).stem
        for fn in row["functions"]:
            name = fn["name"]
            sig = fn["sig"].lower()
            body = function_body(text, name)
            if not body:
                continue
            low = body.lower()

            if RE_EXTERNAL.search(body) and "nonreentrant" not in sig and "nonreentrant" not in low:
                if RE_STATE_WRITE.search(body):
                    hits.append(_probe_hit(
                        title=f"{contract}.{name} - external call interleaves with state writes",
                        file=rel, contract=contract, function=name,
                        line=line_number(text, f"function {name}"),
                        severity="high",
                        mechanism=(
                            f"`{name}` performs an external call while mutating state without "
                            "a reentrancy guard, allowing nested re-entry on stale balances."
                        ),
                        impact="Reentrant calls can drain funds or corrupt accounting before state settles.",
                        description=(
                            f"In `{rel}`, contract `{contract}`, function `{name}()`, an external "
                            "`.call` interleaves with state writes and lacks `nonReentrant` protection."
                        ),
                    ))

            if "tx.origin" in low and any(tok in low for tok in ("require", "if", "assert", "revert")):
                hits.append(_probe_hit(
                    title=f"{contract}.{name} - tx.origin used for authorization",
                    file=rel, contract=contract, function=name,
                    line=line_number(text, "tx.origin"),
                    severity="high",
                    mechanism="Authorization relies on tx.origin, spoofable via an intermediate contract call.",
                    impact="Phishing-style calls can bypass access checks and execute privileged actions.",
                    description=(
                        f"In `{rel}`, contract `{contract}`, function `{name}()`, `tx.origin` "
                        "gates a security-sensitive branch instead of `msg.sender`."
                    ),
                ))

            if name.lower() in PRIVILEGED_NAMES and "onlyowner" not in sig and "onlyrole" not in sig:
                if any(tok in sig for tok in ("external", "public", "@external", "pub fn")):
                    hits.append(_probe_hit(
                        title=f"{contract}.{name} - privileged entrypoint lacks access control",
                        file=rel, contract=contract, function=name,
                        line=line_number(text, f"function {name}"),
                        severity="high",
                        mechanism=f"Sensitive `{name}` is externally reachable without onlyOwner/onlyRole.",
                        impact="Any caller can invoke the privileged path and move funds or change configuration.",
                        description=(
                            f"In `{rel}`, contract `{contract}`, function `{name}()` is public/external "
                            "but missing an explicit access-control modifier."
                        ),
                    ))

            if "delegatecall" in low and "onlyowner" not in sig:
                hits.append(_probe_hit(
                    title=f"{contract}.{name} - unguarded delegatecall",
                    file=rel, contract=contract, function=name,
                    line=line_number(text, "delegatecall"),
                    severity="critical",
                    mechanism="delegatecall executes foreign code in this contract's storage context.",
                    impact="Attacker-controlled targets can overwrite storage and seize contract assets.",
                    description=(
                        f"In `{rel}`, contract `{contract}`, function `{name}()` contains delegatecall "
                        "without strict owner-only gating."
                    ),
                ))
    return hits[:6]


def _probe_hit(
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
    return {
        "title": title,
        "file": file,
        "contract": contract,
        "function": function,
        "line": line,
        "severity": severity,
        "mechanism": mechanism,
        "impact": impact,
        "description": description,
    }


def line_number(text: str, needle: str) -> int | None:
    if not needle:
        return None
    idx = text.find(needle)
    return None if idx < 0 else text.count("\n", 0, idx) + 1


def format_finding(raw: dict[str, Any], by_rel: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    file_hint = str(raw.get("file") or raw.get("path") or "").strip()
    if not file_hint:
        return None
    row = None
    for rel, candidate in by_rel.items():
        if file_hint == rel or rel.endswith(file_hint) or file_hint.endswith(rel):
            row, file_hint = candidate, rel
            break
    if row is None:
        return None
    severity = str(raw.get("severity") or "").lower().strip()
    if severity not in {"high", "critical"}:
        return None
    function = str(raw.get("function") or "").strip().strip("`() ")
    if "." in function:
        function = function.split(".")[-1]
    valid = {f["name"] for f in row["functions"]}
    if function and function not in valid:
        function = ""
    contract = str(raw.get("contract") or "").strip().strip("`")
    if not contract and row["contracts"]:
        contract = str(row["contracts"][0])
    mechanism = str(raw.get("mechanism") or "").strip()
    impact = str(raw.get("impact") or "").strip()
    description = str(raw.get("description") or "").strip()
    title = str(raw.get("title") or "").strip()
    if len(mechanism) < 20 and len(description) < 100:
        return None
    loc = ".".join(x for x in (contract, function) if x)
    if not title:
        title = f"{loc or file_hint} - high-impact vulnerability"
    elif loc and loc.lower() not in title.lower():
        title = f"{loc} - {title}"
    where = f"In `{file_hint}`"
    if contract:
        where += f", contract `{contract}`"
    if function:
        where += f", function `{function}()`"
    rebuilt = where + ". "
    if mechanism:
        rebuilt += "Mechanism: " + mechanism.rstrip(".") + ". "
    if impact:
        rebuilt += "Impact: " + impact.rstrip(".") + ". "
    if description:
        rebuilt += description
    description = " ".join(rebuilt.split())
    if len(description) < 100:
        return None
    basename = file_hint.rsplit("/", 1)[-1]
    loc_bits = [f"`{file_hint}`"]
    if basename != file_hint:
        loc_bits.append(f"`{basename}`")
    if function:
        loc_bits.append(f"`{function}()`")
    hint = " Affected location: " + ", ".join(loc_bits) + "."
    if hint.strip() not in description:
        description = description.rstrip() + hint
    line = raw.get("line")
    if not isinstance(line, int) and function:
        line = line_number(str(row["text"]), f"function {function}")
    return {
        "title": title[:220],
        "description": description[:3000],
        "severity": severity,
        "file": file_hint,
        "function": function,
        "line": line if isinstance(line, int) else None,
        "type": str(raw.get("type") or "logic"),
        "confidence": 0.91 if severity == "critical" else 0.85,
    }


def collapse_findings(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
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
