from __future__ import annotations

"""SN60 miner: import-graph expansion with graph-aware triage and deep audits.

Ranks Solidity/Vyper sources by risk heuristics and import-graph centrality,
runs one graph-compact triage call to pick priority targets, then audits triage
targets, graph neighbors, and top-ranked uncovered files. Includes zero-call static
probes. Self-contained stdlib; inference proxy only.
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

EXTS = (".sol", ".vy")
SKIP_TOP = frozenset({
    ".git", ".github", "artifacts", "broadcast", "cache", "coverage", "dist", "docs",
    "example", "examples", "interfaces", "lib", "mock", "mocks", "node_modules", "out",
    "script", "scripts", "test", "tests", "vendor", "vendors",
})
SKIP_IN_SRC = frozenset({"test", "tests", "mock", "mocks"})

RE_FUNC = re.compile(
    r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*([^{};]*)(?:;|\{)",
    re.MULTILINE,
)
RE_DEF = re.compile(r"^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", re.MULTILINE)
RE_CONTRACT = re.compile(
    r"^\s*(?:abstract\s+contract|contract|library|interface)\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
RE_IMPORT = re.compile(r'^\s*import\b[^;]*?["\']([^"\']+)["\']', re.MULTILINE)
RE_RISK = re.compile(
    r"\b(delegatecall|selfdestruct|tx\.origin|assembly|unchecked|\.call\s*\{|"
    r"onlyOwner|onlyRole|upgradeTo|initialize|withdraw|mint|burn|borrow|liquidat|"
    r"transferFrom|ecrecover|permit|slot0|latestRoundData)\b",
    re.IGNORECASE,
)
RE_EXTERNAL = re.compile(r"\.call\s*(\{|value)")

MAX_FILES = 75
MAX_BYTES = 270_000
PROMPT_BUDGET = 33_000
RELATED_BUDGET = 3_200
GRAPH_DIGEST_CHARS = 14_000
MAX_FINDINGS = 8
RUN_BUDGET = 228.0
HTTP_WAIT = 148

PATH_HINTS = (
    "vault", "pool", "router", "bridge", "proxy", "oracle", "govern", "market",
    "lend", "borrow", "collateral", "controller", "strategy", "swap", "staking",
    "treasury", "manager", "auction", "token", "reward", "liquidat", "claim",
)

AUDITOR = (
    "You are a senior smart-contract security auditor. Report only exploitable "
    "high or critical bugs with concrete file, contract, and function locations. "
    "Reject style, gas, missing events, and speculation. Return strict JSON only."
)


def agent_main(project_dir: str | None = None, inference_api: str | None = None) -> dict:
    findings: list[dict[str, Any]] = []
    started = time.monotonic()
    root = _resolve_root(project_dir)
    if root is None:
        return {"vulnerabilities": findings}

    catalog = _catalog(root)
    if not catalog:
        return {"vulnerabilities": findings}

    by_rel = {row["rel"]: row for row in catalog}
    by_name = {Path(row["rel"]).name: row for row in catalog}
    graph = _import_graph(catalog, by_name)
    ranked = _rank(catalog, graph)

    collected: list[dict[str, Any]] = []
    collected.extend(_static_probes(catalog))
    audited: set[str] = set()

    triage_targets, triage_hits = _graph_triage(inference_api, ranked, graph)
    collected.extend(triage_hits)

    def audit_rows(rows: list[dict[str, Any]]) -> None:
        if not rows or time.monotonic() - started >= RUN_BUDGET:
            return
        fresh = [row for row in rows if row["rel"] not in audited]
        if not fresh:
            return
        collected.extend(_deep_audit(inference_api, fresh[:3], by_name))
        audited.update(row["rel"] for row in fresh[:3])

    triage_rows = _resolve_target_rows(triage_targets, by_rel, ranked)
    audit_rows(triage_rows[:3])

    for row in triage_rows[:2]:
        audit_rows(_graph_neighbors(row["rel"], graph, by_rel))

    remaining = [row for row in ranked if row["rel"] not in audited]
    audit_rows(remaining[:4])

    normalized: list[dict[str, Any]] = []
    for raw in collected:
        shaped = _shape(raw, by_rel)
        if shaped is not None:
            normalized.append(shaped)
    return {"vulnerabilities": _dedupe(normalized)}


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
            path = Path(raw).expanduser().resolve()
        except (OSError, RuntimeError):
            continue
        if path.is_dir() and any(
            item.suffix.lower() in EXTS for item in path.rglob("*") if item.is_file()
        ):
            return path
    return None


def _skip(parts: tuple[str, ...]) -> bool:
    if not parts:
        return False
    in_src = "src" in {part.lower() for part in parts}
    for part in parts:
        low = part.lower()
        if in_src:
            if low in SKIP_IN_SRC:
                return True
        elif low in SKIP_TOP:
            return True
    return False


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _functions(text: str, suffix: str) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    if suffix in EXTS:
        for match in RE_FUNC.finditer(text):
            tail = " ".join(match.group(3).split())
            out.append({
                "name": match.group(1),
                "sig": f"{match.group(1)}({match.group(2).strip()}) {tail}".strip(),
            })
    if suffix == ".vy":
        for match in RE_DEF.finditer(text):
            out.append({"name": match.group(1), "sig": match.group(1)})
    return out


def _catalog(root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        suffix = path.suffix.lower()
        if suffix not in EXTS:
            continue
        try:
            rel_path = path.relative_to(root)
            if _skip(tuple(rel_path.parts[:-1])):
                continue
            if path.stat().st_size > MAX_BYTES:
                continue
        except OSError:
            continue
        text = _read(path)
        if "function" not in text and "\ndef " not in text and "contract " not in text:
            continue
        rel = rel_path.as_posix()
        contracts = RE_CONTRACT.findall(text)
        if not contracts and suffix == ".vy":
            contracts = [path.stem]
        rows.append({
            "rel": rel,
            "text": text,
            "suffix": suffix,
            "contracts": contracts,
            "functions": _functions(text, suffix),
            "imports": RE_IMPORT.findall(text),
        })
    return rows[:MAX_FILES]


def _import_graph(
    catalog: list[dict[str, Any]],
    by_name: dict[str, dict[str, Any]],
) -> dict[str, set[str]]:
    graph: dict[str, set[str]] = defaultdict(set)
    for row in catalog:
        rel = row["rel"]
        for imported in row["imports"]:
            base = imported.rsplit("/", 1)[-1]
            target = by_name.get(base)
            if target and target["rel"] != rel:
                graph[rel].add(target["rel"])
                graph[target["rel"]].add(rel)
    return graph


def _score_row(row: dict[str, Any], graph: dict[str, set[str]]) -> int:
    rel = row["rel"].lower()
    text = row["text"].lower()
    score = min(len(row["functions"]), 30)
    score += min(len(graph.get(row["rel"], set())), 8) * 4
    score += min(len(RE_RISK.findall(row["text"])), 16) * 2
    for hint in PATH_HINTS:
        if hint in rel:
            score += 8
        elif hint in text:
            score += 2
    if "external" in text or "public" in text:
        score += 4
    return score


def _rank(catalog: list[dict[str, Any]], graph: dict[str, set[str]]) -> list[dict[str, Any]]:
    for row in catalog:
        row["score"] = _score_row(row, graph)
    return sorted(catalog, key=lambda row: (-int(row["score"]), str(row["rel"])))


def _graph_neighbors(
    rel: str,
    graph: dict[str, set[str]],
    by_rel: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    return [by_rel[n] for n in sorted(graph.get(rel, set())) if n in by_rel]


def _graph_digest(
    ranked: list[dict[str, Any]],
    graph: dict[str, set[str]],
    *,
    limit: int = 14,
) -> str:
    lines: list[str] = []
    for row in ranked[:limit]:
        rel = row["rel"]
        neighbors = sorted(graph.get(rel, set()))[:4]
        lines.append(json.dumps({
            "file": rel,
            "score": row.get("score", 0),
            "contracts": row["contracts"][:5],
            "neighbors": neighbors,
            "functions": [fn["sig"][:100] for fn in row["functions"][:16]],
            "risk_hits": len(RE_RISK.findall(row["text"])),
        }, separators=(",", ":")))
    return "\n".join(lines)[:GRAPH_DIGEST_CHARS]


def _resolve_target_rows(
    targets: list[str],
    by_rel: dict[str, dict[str, Any]],
    ranked: list[dict[str, Any]],
) -> list[dict[str, Any]]:
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
    return ordered


def _graph_triage(
    inference_api: str | None,
    ranked: list[dict[str, Any]],
    graph: dict[str, set[str]],
) -> tuple[list[str], list[dict[str, Any]]]:
    prompt = (
        "Given this import-graph ranked repository map, pick files most likely to "
        "contain exploitable high or critical bugs. Return strict JSON only:\n"
        '{"target_files":["path/to/File.sol"],"findings":[{"title":"Contract.function - bug",'
        '"file":"path/to/File.sol","contract":"Contract","function":"functionName",'
        '"severity":"high|critical","mechanism":"precondition -> action -> effect",'
        '"impact":"material loss or privilege impact",'
        '"description":"2-4 precise sentences"}]}\n'
        "Prioritize high-centrality nodes, privileged entrypoints, external calls, and "
        "oracle/accounting logic. Do not invent files.\n\n"
        + _graph_digest(ranked, graph)
    )
    try:
        obj = _parse_json(_request(
            inference_api,
            [{"role": "system", "content": AUDITOR}, {"role": "user", "content": prompt}],
            4500,
        ))
    except Exception:
        return [], []
    targets = obj.get("target_files")
    findings = obj.get("findings") or obj.get("vulnerabilities") or []
    return (
        [str(item) for item in targets if isinstance(item, str)] if isinstance(targets, list) else [],
        [item for item in findings if isinstance(item, dict)] if isinstance(findings, list) else [],
    )


def _function_body(text: str, name: str) -> str:
    match = re.search(rf"\bfunction\s+{re.escape(name)}\s*\([^)]*\)[^{{;]*\{{", text)
    if not match:
        match = re.search(rf"^\s*def\s+{re.escape(name)}\s*\([^)]*\)[^:]*:", text, re.MULTILINE)
        if not match:
            return ""
        lines = text[match.end() :].splitlines()
        if not lines:
            return ""
        indent = len(lines[0]) - len(lines[0].lstrip())
        body: list[str] = []
        for line in lines:
            if line.strip() and (len(line) - len(line.lstrip())) <= indent and body:
                break
            body.append(line)
        return "\n".join(body)
    start = match.end()
    depth = 1
    index = start
    while index < len(text) and depth:
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
        index += 1
    return text[start : index - 1] if depth == 0 else ""


def _static_hit(
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


def _static_probes(catalog: list[dict[str, Any]]) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for row in catalog:
        rel = row["rel"]
        text = row["text"]
        contract = row["contracts"][0] if row["contracts"] else Path(rel).stem
        for fn in row["functions"]:
            name = fn["name"]
            sig = fn["sig"].lower()
            body = _function_body(text, name)
            if not body:
                continue
            low = body.lower()
            if RE_EXTERNAL.search(body) and "nonreentrant" not in sig and "nonreentrant" not in low:
                hits.append(_static_hit(
                    title=f"{contract}.{name} - unchecked external call surface",
                    file=rel,
                    contract=contract,
                    function=name,
                    line=_line(text, f"function {name}"),
                    severity="high",
                    mechanism=(
                        f"`{name}` performs an external call without an explicit reentrancy guard."
                    ),
                    impact="Nested re-entry can exploit stale balances before state updates finalize.",
                    description=(
                        f"In `{rel}`, contract `{contract}`, function `{name}()`, an external "
                        "`.call` is reachable without `nonReentrant` protection."
                    ),
                ))
                break
    return hits


def _related_block(row: dict[str, Any], by_name: dict[str, dict[str, Any]]) -> str:
    chunks: list[str] = []
    for imported in row["imports"]:
        base = imported.rsplit("/", 1)[-1]
        other = by_name.get(base)
        if other and other["rel"] != row["rel"]:
            chunks.append(f"// related {other['rel']}\n{other['text'][:RELATED_BUDGET]}")
        if len(chunks) >= 2:
            break
    return "\n\n".join(chunks)


def _audit_prompt(batch: list[dict[str, Any]], by_name: dict[str, dict[str, Any]]) -> str:
    header = (
        "Deep-audit the sources below. Return strict JSON only:\n"
        '{"findings":[{"title":"Contract.function - specific bug","file":"exact/path",'
        '"contract":"Contract","function":"functionName","line":123,"severity":"high|critical",'
        '"mechanism":"preconditions -> attacker action -> broken invariant",'
        '"impact":"specific loss/insolvency/privilege/DoS impact",'
        '"description":"2-4 sentences naming file, contract, function, mechanism, and impact"}]}\n'
        "At most 4 findings. Omit anything that is not clearly exploitable.\n"
    )
    parts = [header]
    remaining = PROMPT_BUDGET - len(header)
    for row in batch:
        block = (
            f"\n\n===== FILE: {row['rel']} =====\n"
            f"Score: {row.get('score', 0)}\n"
            f"Contracts: {', '.join(row['contracts'][:6])}\n"
            f"{row['text']}\n"
        )
        related = _related_block(row, by_name)
        if related:
            block += f"\n===== RELATED =====\n{related}\n"
        if len(block) > remaining:
            block = block[: max(0, remaining)] + "\n/* truncated */\n"
        if remaining <= 0:
            break
        parts.append(block)
        remaining -= len(block)
    return "".join(parts)


def _request(inference_api: str | None, messages: list[dict[str, str]], max_tokens: int) -> str:
    endpoint = (inference_api or os.environ.get("INFERENCE_API") or "").rstrip("/")
    if not endpoint:
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
    last: Exception | None = None
    for attempt in range(2):
        try:
            req = urllib.request.Request(
                endpoint + "/inference",
                data=payload,
                method="POST",
                headers=headers,
            )
            with urllib.request.urlopen(req, timeout=HTTP_WAIT) as resp:
                return _content(json.loads(resp.read().decode("utf-8", "replace")))
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                raise
            last = exc
        except (OSError, ValueError, TimeoutError) as exc:
            last = exc
        if attempt < 1:
            time.sleep(1.2)
    raise RuntimeError(f"inference failed: {last}")


def _content(payload: dict[str, Any]) -> str:
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


def _parse_json(text: str) -> dict[str, Any]:
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


def _deep_audit(
    inference_api: str | None,
    batch: list[dict[str, Any]],
    by_name: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    if not batch:
        return []
    try:
        obj = _parse_json(_request(
            inference_api,
            [{"role": "system", "content": AUDITOR}, {"role": "user", "content": _audit_prompt(batch, by_name)}],
            8500,
        ))
    except urllib.error.HTTPError:
        return []
    except Exception:
        return []
    findings = obj.get("findings") or obj.get("vulnerabilities") or []
    return [item for item in findings if isinstance(item, dict)] if isinstance(findings, list) else []


def _line(text: str, needle: str) -> int | None:
    if not needle:
        return None
    index = text.find(needle)
    return None if index < 0 else text.count("\n", 0, index) + 1


def _shape(raw: dict[str, Any], by_rel: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    file_hint = str(raw.get("file") or raw.get("path") or "").strip()
    chosen = None
    for rel, row in by_rel.items():
        if file_hint == rel or rel.endswith(file_hint) or file_hint.endswith(rel):
            chosen, file_hint = row, rel
            break
    if chosen is None:
        return None
    severity = str(raw.get("severity") or "").lower().strip()
    if severity not in {"high", "critical"}:
        return None
    function = str(raw.get("function") or "").strip().strip("`() ")
    if "." in function:
        function = function.split(".")[-1]
    valid = {fn["name"] for fn in chosen["functions"]}
    if function and function not in valid:
        function = ""
    contract = str(raw.get("contract") or "").strip().strip("`")
    if not contract and chosen["contracts"]:
        contract = str(chosen["contracts"][0])
    mechanism = str(raw.get("mechanism") or "").strip()
    impact = str(raw.get("impact") or "").strip()
    description = str(raw.get("description") or "").strip()
    title = str(raw.get("title") or "").strip()
    if len(mechanism) < 20 and len(description) < 100:
        return None
    loc = ".".join(part for part in (contract, function) if part)
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
    line = raw.get("line")
    if not isinstance(line, int) and function:
        line = _line(str(chosen["text"]), f"function {function}")
    return {
        "title": title[:220],
        "description": description[:3000],
        "severity": severity,
        "file": file_hint,
        "function": function,
        "line": line if isinstance(line, int) else None,
        "type": str(raw.get("type") or "logic"),
        "confidence": 0.92 if severity == "critical" else 0.86,
    }


def _dedupe(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str]] = set()
    output: list[dict[str, Any]] = []
    ordered = sorted(
        items,
        key=lambda finding: (
            finding.get("severity") == "critical",
            float(finding.get("confidence") or 0),
            len(str(finding.get("description") or "")),
        ),
        reverse=True,
    )
    for finding in ordered:
        key = (
            str(finding.get("file") or "").lower(),
            str(finding.get("function") or "").lower(),
            str(finding.get("title") or "").lower()[:100],
        )
        if key in seen:
            continue
        seen.add(key)
        output.append(finding)
        if len(output) >= MAX_FINDINGS:
            break
    return output


if __name__ == "__main__":
    import sys

    print(json.dumps(agent_main(sys.argv[1] if len(sys.argv) > 1 else None), indent=2))
