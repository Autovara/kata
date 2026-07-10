from __future__ import annotations

"""SN60 Bitsec miner: import-aware triage plus context-linked LLM audits.

Files are ranked by a risk heuristic boosted by import-graph centrality (files
many other files import score higher). One inference call lets the model pick
audit targets from a repository digest; the remaining two calls deep-audit
those targets plus their direct import neighbors and one directory-diverse
pick, with oversized files reduced to risk-relevant excerpts instead of raw
truncation. Two zero-cost static checks (unguarded reentrancy, tx.origin
authorization) contribute findings before any inference call is spent.
Self-contained stdlib; validator inference proxy only. No project-specific
fingerprints or canned findings.
"""

import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

CODE_EXTENSIONS = (".sol", ".vy", ".rs")
IGNORED_DIRECTORY_NAMES = {
    ".git", ".github", "node_modules", "lib", "libs", "vendor", "vendors",
    "test", "tests", "mock", "mocks", "script", "scripts", "docs", "artifacts",
    "cache", "out", "build", "dist", "coverage", "broadcast", "examples", "example",
    "interfaces", "generated",
}

MAX_SOURCE_BYTES = 240_000
MAX_FILES_CONSIDERED = 65
MAX_FINDINGS_RETURNED = 8
MAX_RUNTIME_SECONDS = 200
REQUEST_TIMEOUT_SECONDS = 140

DIGEST_CHAR_BUDGET = 20_000
TRIAGE_MAX_TOKENS = 4_500
AUDIT_MAX_TOKENS = 8_000
AUDIT_BATCH_CHAR_BUDGET = 42_000
PRIMARY_BATCH_TARGET_FILES = 2
SECONDARY_BATCH_MAX_FILES = 5
CONTEXT_CHAR_BUDGET = 3_500
INLINE_FULL_FILE_LIMIT = 11_000
COMPACT_EXCERPT_BUDGET = 9_000

FUNC_DECL_SOL_RE = re.compile(
    r"\bfunction\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*([^{};]*)(?:;|\{)",
    re.MULTILINE,
)
FUNC_DECL_VY_RE = re.compile(
    r"^\s*def\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*(?:->\s*([^:]+))?:",
    re.MULTILINE,
)
FUNC_DECL_RS_RE = re.compile(r"\bfn\s+([A-Za-z_]\w*)\s*[(<]")
CONTRACT_DECL_RE = re.compile(
    r"^\s*(?:abstract\s+contract|contract|library|interface)\s+([A-Za-z_]\w*)",
    re.MULTILINE,
)
RUST_TYPE_DECL_RE = re.compile(r"^\s*(?:pub\s+)?(?:struct|enum|trait|impl)\s+([A-Za-z_]\w*)", re.MULTILINE)
IMPORT_PATH_RE = re.compile(r'^\s*(?:import|use)\b[^;]*?["\']([^"\']+)["\']', re.MULTILINE)
STATE_VAR_RE = re.compile(
    r"^\s*(?:mapping\s*\([^;]+|[A-Za-z_][A-Za-z0-9_<>,\[\]. ]+)\s+"
    r"(?:public|private|internal|constant|immutable|override|\s)*"
    r"([A-Za-z_]\w*)\s*(?:=|;)",
    re.MULTILINE,
)
GUARD_MODIFIER_RE = re.compile(r"\b(nonReentrant|onlyOwner|onlyRole|whenNotPaused|initializer)\b")
STATE_WRITE_RE = re.compile(r"\b\w+(?:\[[^\]]*\])?\s*(?:\+=|-=|\*=|/=|=(?!=))")
EXTERNAL_CALL_RE = re.compile(r"\.call\s*\{|\.call\s*\(|\.send\(|\.transfer\(|raw_call\(")
SENSITIVE_BODY_RE = re.compile(
    r"call\s*\{|delegatecall|withdraw|redeem|liquidat|mint|burn|transfer|borrow|"
    r"oracle|unchecked|selfdestruct|permit|allowance|tx\.origin",
    re.IGNORECASE,
)

# Generic smart-contract risk vocabulary used for heuristic scoring. Not tied
# to any specific project or known finding.
RISK_SIGNALS: tuple[tuple[str, int], ...] = (
    (r"\.call\{", 12),
    (r"\.call\(", 7),
    (r"\.delegatecall\(", 14),
    (r"\.staticcall\(", 4),
    (r"\.send\(", 6),
    (r"\.transfer\(", 4),
    (r"selfdestruct", 10),
    (r"unchecked\s*\{", 9),
    (r"assembly\s*\{", 6),
    (r"ecrecover", 8),
    (r"permit\s*\(", 7),
    (r"tx\.origin", 8),
    (r"block\.timestamp", 3),
    (r"block\.number", 2),
    (r"nonReentrant", -3),
    (r"onlyOwner", -2),
    (r"onlyRole", -2),
    (r"whenNotPaused", -2),
    (r"initialize\s*\(", 6),
    (r"upgradeTo", 8),
    (r"setImplementation", 8),
    (r"withdraw", 5),
    (r"deposit", 3),
    (r"redeem", 5),
    (r"liquidat", 7),
    (r"borrow", 5),
    (r"repay", 4),
    (r"flashLoan", 8),
    (r"swap", 4),
    (r"oracle", 6),
    (r"getPrice", 6),
    (r"totalSupply", 3),
    (r"balanceOf", 2),
    (r"allowance", 4),
    (r"transferFrom", 4),
    (r"nonce", 4),
    (r"signature", 5),
    (r"slash", 6),
    (r"claim", 4),
    (r"vest", 4),
    (r"checked_add|checked_sub|checked_mul|checked_div", 6),
    (r"saturating_", 4),
    (r"wrapping_", 8),
    (r"as u128|as u64|as u32", 5),
)

PATH_HINT_TERMS = (
    "vault", "pool", "router", "bridge", "market", "staking", "escrow",
    "auction", "treasury", "governor", "oracle", "lend", "borrow", "swap",
    "reward", "vesting", "controller", "strategy", "manager",
)

SPECULATIVE_HEDGE_RE = re.compile(
    r"\b(if the admin|if an? external (?:dependency|contract)|if the token is malicious|"
    r"malicious erc20|non-?standard erc20|could potentially|might allow|may allow)\b",
    re.IGNORECASE,
)

AUDIT_SYSTEM_PROMPT = (
    "You are an experienced smart-contract security auditor reviewing unfamiliar source code "
    "for real high or critical severity bugs. Think through state transitions, access control, "
    "accounting, and arithmetic carefully before answering - many real bugs are subtle and easy "
    "to miss on a quick read. Report every vulnerability you can ground in the exact code shown, "
    "including ones that require tracing a multi-step call path. Do not invent bugs that depend "
    "on a malicious admin, a malicious token, or a compromised external contract - those need "
    "actual evidence in the code. Do not report style, gas, or purely informational issues. "
    "Respond with strict JSON only."
)


def _stderr(message: str) -> None:
    print(f"[sn60-fresh-agent] {message}", file=sys.stderr)


def _resolve_project_root(project_dir: str | None) -> Path | None:
    guesses = []
    if project_dir:
        guesses.append(project_dir)
    for env_name in ("PROJECT_DIR", "PROJECT_PATH", "PROJECT_ROOT", "PROJECT_CODE"):
        env_value = os.environ.get(env_name)
        if env_value:
            guesses.append(env_value)
    guesses.extend(["/app/project_code", "/app/project", "/project", "/code", "."])
    for guess in guesses:
        try:
            candidate = Path(guess).expanduser().resolve()
        except (OSError, RuntimeError):
            continue
        if candidate.is_dir() and _contains_source(candidate):
            return candidate
    return None


def _contains_source(root: Path) -> bool:
    try:
        return any(path.suffix.lower() in CODE_EXTENSIONS for path in root.rglob("*") if path.is_file())
    except OSError:
        return False


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _collect_source_files(root: Path) -> list[dict[str, Any]]:
    collected: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in CODE_EXTENSIONS:
            continue
        try:
            relative = path.relative_to(root)
        except ValueError:
            continue
        if any(part.lower() in IGNORED_DIRECTORY_NAMES for part in relative.parts[:-1]):
            continue
        try:
            if path.stat().st_size > MAX_SOURCE_BYTES:
                continue
        except OSError:
            continue
        text = _read_text(path)
        if not text.strip():
            continue
        collected.append(
            {
                "relative_path": relative.as_posix(),
                "suffix": path.suffix.lower(),
                "text": text,
            }
        )
    return collected[:MAX_FILES_CONSIDERED]


def _declared_names(text: str, suffix: str) -> list[str]:
    if suffix == ".rs":
        return RUST_TYPE_DECL_RE.findall(text)[:8]
    return CONTRACT_DECL_RE.findall(text)[:8]


def _extract_functions(text: str, suffix: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    if suffix == ".sol":
        for match in FUNC_DECL_SOL_RE.finditer(text):
            visibility = " ".join(match.group(3).split())
            rows.append({"name": match.group(1), "sig": f"{match.group(1)}({match.group(2).strip()}) {visibility}".strip()})
    elif suffix == ".vy":
        for match in FUNC_DECL_VY_RE.finditer(text):
            returns = f" -> {match.group(3).strip()}" if match.group(3) else ""
            rows.append({"name": match.group(1), "sig": f"{match.group(1)}({match.group(2).strip()}){returns}"})
    elif suffix == ".rs":
        for match in FUNC_DECL_RS_RE.finditer(text):
            rows.append({"name": match.group(1), "sig": match.group(1)})
    return rows


def _function_body(text: str, name: str) -> str:
    escaped = re.escape(name)
    match = re.search(rf"\bfunction\s+{escaped}\s*\([^)]*\)[^{{]*\{{", text, re.MULTILINE)
    if match is None:
        match = re.search(rf"\bfn\s+{escaped}\s*[(<][^{{]*\{{", text, re.MULTILINE)
    if match is not None:
        start = match.end()
        depth = 1
        index = start
        while index < len(text) and depth:
            char = text[index]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
            index += 1
        return text[start : index - 1] if depth == 0 else text[start : start + 4000]
    vyper_match = re.search(rf"^\s*def\s+{escaped}\s*\(", text, re.MULTILINE)
    if vyper_match is not None:
        tail = text[vyper_match.end() :]
        next_def = re.search(r"^\s*def\s+[A-Za-z_]\w*\s*\(", tail, re.MULTILINE)
        end = vyper_match.end() + (next_def.start() if next_def else min(len(tail), 4000))
        return text[vyper_match.end() : end]
    return ""


def _line_for(text: str, needle: str) -> int | None:
    if not needle:
        return None
    index = text.find(needle)
    return None if index < 0 else text.count("\n", 0, index) + 1


def _risk_score(relative_path: str, text: str) -> int:
    lowered_path = relative_path.lower()
    score = 0
    for pattern, weight in RISK_SIGNALS:
        hits = len(re.findall(pattern, text, re.IGNORECASE))
        if hits:
            score += min(hits, 6) * weight
    if any(term in lowered_path for term in PATH_HINT_TERMS):
        score += 10
    if any(term in lowered_path for term in ("mock", "helper", "faucet", "deployer")):
        score -= 20
    function_count = len(re.findall(r"\bfunction\s+\w+\s*\(", text)) + len(re.findall(r"^\s*(?:pub\s+)?fn\s+\w+", text, re.MULTILINE))
    score += min(function_count, 30)
    return score


def _build_import_graph(files: list[dict[str, Any]]) -> tuple[dict[str, set[str]], dict[str, int]]:
    by_name = {Path(entry["relative_path"]).name: entry for entry in files}
    outbound_graph: dict[str, set[str]] = {}
    inbound_counts: dict[str, int] = {}
    for entry in files:
        rel = entry["relative_path"]
        outbound: set[str] = set()
        for imported in IMPORT_PATH_RE.findall(entry["text"]):
            key = imported.rsplit("/", 1)[-1]
            peer = by_name.get(key)
            if peer and peer["relative_path"] != rel:
                outbound.add(peer["relative_path"])
                inbound_counts[peer["relative_path"]] = inbound_counts.get(peer["relative_path"], 0) + 1
        outbound_graph[rel] = outbound
    return outbound_graph, inbound_counts


def _rank_files(files: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, set[str]]]:
    graph, inbound_counts = _build_import_graph(files)
    for entry in files:
        rel = entry["relative_path"]
        entry["names"] = _declared_names(entry["text"], entry["suffix"])
        entry["functions"] = _extract_functions(entry["text"], entry["suffix"])
        entry["score"] = _risk_score(rel, entry["text"])
        entry["inbound"] = inbound_counts.get(rel, 0)
        entry["outbound"] = len(graph.get(rel, ()))
        entry["graph_score"] = entry["score"] + entry["inbound"] * 7 + entry["outbound"] * 2
    ranked = sorted(files, key=lambda entry: (-entry["graph_score"], -entry["score"], entry["relative_path"]))
    return ranked, graph


def _raw_finding(
    *,
    title: str,
    file: str,
    function: str,
    line: int | None,
    severity: str,
    description: str,
) -> dict[str, Any]:
    return {
        "title": title,
        "file": file,
        "function": function,
        "line": line,
        "severity": severity,
        "description": description,
    }


def _free_reentrancy_findings(ranked_files: list[dict[str, Any]]) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for entry in ranked_files:
        if entry["suffix"] != ".sol":
            continue
        text = entry["text"]
        contract = entry["names"][0] if entry["names"] else Path(entry["relative_path"]).stem
        for func in entry["functions"][:40]:
            name = func["name"]
            body = _function_body(text, name)
            if not body:
                continue
            if not EXTERNAL_CALL_RE.search(body) or not STATE_WRITE_RE.search(body):
                continue
            if GUARD_MODIFIER_RE.search(func.get("sig", "") + body):
                continue
            hits.append(
                _raw_finding(
                    title=f"{contract}.{name} - external call ahead of state update without a reentrancy guard",
                    file=entry["relative_path"],
                    function=name,
                    line=_line_for(text, f"function {name}"),
                    severity="high",
                    description=(
                        f"In `{entry['relative_path']}`, function `{name}()` performs an external call "
                        "and also writes contract state, with no reentrancy-guard modifier present on the "
                        "function. A reentrant call made during the external call can observe or corrupt "
                        "state before this function finishes updating it."
                    ),
                )
            )
            if len(hits) >= 3:
                return hits
    return hits


def _free_tx_origin_findings(ranked_files: list[dict[str, Any]]) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for entry in ranked_files:
        text = entry["text"]
        if "tx.origin" not in text:
            continue
        contract = entry["names"][0] if entry["names"] else Path(entry["relative_path"]).stem
        for func in entry["functions"][:40]:
            body = _function_body(text, func["name"])
            if "tx.origin" not in body:
                continue
            if not re.search(r"\b(require|if|assert|revert)\b", body):
                continue
            hits.append(
                _raw_finding(
                    title=f"{contract}.{func['name']} - tx.origin used for authorization",
                    file=entry["relative_path"],
                    function=func["name"],
                    line=_line_for(text, "tx.origin"),
                    severity="high",
                    description=(
                        f"In `{entry['relative_path']}`, function `{func['name']}()` checks `tx.origin` "
                        "in an authorization branch. A malicious contract can trick a user into calling "
                        "it, which in turn calls this function, and tx.origin still resolves to the "
                        "original user, bypassing the intended sender check."
                    ),
                )
            )
            if len(hits) >= 2:
                return hits
    return hits


def _hot_function_names(text: str) -> list[str]:
    hits: list[str] = []
    for func in _extract_functions(text, ".sol") + _extract_functions(text, ".vy"):
        body = _function_body(text, func["name"])
        if body and SENSITIVE_BODY_RE.search(body):
            hits.append(func["name"])
        if len(hits) >= 8:
            break
    return hits


def _state_var_names(text: str) -> list[str]:
    names: list[str] = []
    for name in STATE_VAR_RE.findall(text):
        if name not in names and len(name) < 42:
            names.append(name)
    return names[:14]


def _build_repo_digest(ranked_files: list[dict[str, Any]]) -> str:
    lines: list[str] = []
    used = 0
    for entry in ranked_files:
        row = json.dumps(
            {
                "file": entry["relative_path"],
                "lang": entry["suffix"].lstrip("."),
                "contracts": entry["names"][:6],
                "graph_score": entry["graph_score"],
                "inbound_imports": entry["inbound"],
                "outbound_imports": entry["outbound"],
                "hot_functions": _hot_function_names(entry["text"]),
                "state_vars": _state_var_names(entry["text"]),
                "functions": [func["sig"][:150] for func in entry["functions"][:24]],
            },
            separators=(",", ":"),
        )
        if used + len(row) > DIGEST_CHAR_BUDGET:
            break
        lines.append(row)
        used += len(row)
    return "\n".join(lines)


def _resolve_endpoint(inference_api: str | None) -> str:
    return (
        inference_api
        or os.environ.get("INFERENCE_API")
        or os.environ.get("KATA_SN60_INFERENCE_API")
        or "http://bitsec_proxy:8000"
    ).rstrip("/")


def _call_model(inference_api: str | None, prompt: str, max_tokens: int) -> str:
    endpoint = _resolve_endpoint(inference_api)
    body = json.dumps(
        {
            "messages": [
                {"role": "system", "content": AUDIT_SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "max_tokens": max_tokens,
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        endpoint + "/inference",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "x-inference-api-key": os.environ.get("INFERENCE_API_KEY", ""),
        },
    )
    last_error: Exception | None = None
    for attempt in range(2):
        try:
            with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
                parsed_response = json.loads(response.read().decode("utf-8", "replace"))
            return _extract_message_content(parsed_response)
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                raise
            last_error = exc
            _stderr(f"inference HTTP {exc.code} on attempt {attempt + 1}")
        except (OSError, ValueError, TimeoutError) as exc:
            last_error = exc
            _stderr(f"inference error on attempt {attempt + 1}: {exc}")
        if attempt == 0:
            time.sleep(1.5)
    raise RuntimeError(f"inference call failed: {last_error}")


def _extract_message_content(payload: dict[str, Any]) -> str:
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        return ""
    message = choices[0].get("message") if isinstance(choices[0], dict) else None
    if not isinstance(message, dict):
        return ""
    content = message.get("content")
    return content if isinstance(content, str) else ""


def _extract_json_object(text: str) -> dict[str, Any]:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```[a-zA-Z]*\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned)
    try:
        parsed = json.loads(cleaned)
        return parsed if isinstance(parsed, dict) else {}
    except json.JSONDecodeError:
        pass
    start = cleaned.find("{")
    if start < 0:
        return {}
    depth = 0
    in_string = False
    escape_next = False
    for index in range(start, len(cleaned)):
        char = cleaned[index]
        if in_string:
            if escape_next:
                escape_next = False
            elif char == "\\":
                escape_next = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                try:
                    parsed = json.loads(cleaned[start : index + 1])
                except json.JSONDecodeError:
                    return {}
                return parsed if isinstance(parsed, dict) else {}
    return {}


def _run_triage(inference_api: str | None, ranked_files: list[dict[str, Any]]) -> list[str]:
    prompt = (
        "Below is a compact map of this repository's source files. graph_score blends "
        "heuristic risk signals with import centrality, so files many other files import "
        "score higher. Choose the files most likely to hide a real, exploitable high or "
        "critical severity bug - favor highly-imported hub contracts and files whose "
        "hot_functions look sensitive (transfers, withdrawals, oracle reads, minting, "
        "upgrades, permission changes). Return strict JSON only:\n"
        '{"target_files":["path/one.sol","path/two.sol"]}\n\n'
        + _build_repo_digest(ranked_files)
    )
    try:
        raw_text = _call_model(inference_api, prompt, max_tokens=TRIAGE_MAX_TOKENS)
    except Exception as exc:
        _stderr(f"triage failed: {exc}")
        return []
    parsed = _extract_json_object(raw_text)
    targets = parsed.get("target_files")
    return [str(item) for item in targets if isinstance(item, str)] if isinstance(targets, list) else []


def _top_level_dir(relative_path: str) -> str:
    parts = relative_path.split("/")
    return parts[0] if len(parts) > 1 else ""


def _resolve_target_order(target_files: list[str], ranked_files: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_rel = {entry["relative_path"]: entry for entry in ranked_files}
    ordered: list[dict[str, Any]] = []
    for target in target_files:
        for rel, entry in by_rel.items():
            if target == rel or rel.endswith(target) or target.endswith(rel):
                if entry not in ordered:
                    ordered.append(entry)
                break
    for entry in ranked_files:
        if entry not in ordered:
            ordered.append(entry)
    return ordered


def _pick_diverse(ranked_files: list[dict[str, Any]], used: set[str]) -> dict[str, Any] | None:
    seen_dirs: set[str] = set()
    for entry in ranked_files:
        if entry["relative_path"] in used:
            continue
        top = _top_level_dir(entry["relative_path"])
        if top and top not in seen_dirs:
            seen_dirs.add(top)
            return entry
    for entry in ranked_files:
        if entry["relative_path"] not in used:
            return entry
    return None


def _build_audit_batches(
    target_files: list[str],
    ranked_files: list[dict[str, Any]],
    graph: dict[str, set[str]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    ordered = _resolve_target_order(target_files, ranked_files)
    by_rel = {entry["relative_path"]: entry for entry in ranked_files}

    primary: list[dict[str, Any]] = []
    used: set[str] = set()
    for entry in ordered[:PRIMARY_BATCH_TARGET_FILES]:
        primary.append(entry)
        used.add(entry["relative_path"])
        for dep_rel in list(graph.get(entry["relative_path"], ()))[:1]:
            dep = by_rel.get(dep_rel)
            if dep and dep_rel not in used:
                primary.append(dep)
                used.add(dep_rel)

    secondary: list[dict[str, Any]] = []
    budget = AUDIT_BATCH_CHAR_BUDGET // 2
    for entry in ordered[PRIMARY_BATCH_TARGET_FILES:]:
        rel = entry["relative_path"]
        if rel in used or len(secondary) >= SECONDARY_BATCH_MAX_FILES:
            continue
        size = min(len(entry["text"]), COMPACT_EXCERPT_BUDGET) + 400
        if budget < size:
            continue
        secondary.append(entry)
        used.add(rel)
        budget -= size

    diverse = _pick_diverse(ranked_files, used)
    if diverse is not None and len(secondary) <= SECONDARY_BATCH_MAX_FILES:
        secondary.append(diverse)
        used.add(diverse["relative_path"])

    if not primary and ordered:
        primary = ordered[:PRIMARY_BATCH_TARGET_FILES]
    if not secondary:
        primary_rels = {entry["relative_path"] for entry in primary}
        secondary = [entry for entry in ordered if entry["relative_path"] not in primary_rels][:SECONDARY_BATCH_MAX_FILES]
    return primary, secondary


def _compact_excerpt(text: str, budget: int = COMPACT_EXCERPT_BUDGET) -> str:
    if len(text) <= INLINE_FULL_FILE_LIMIT:
        return text
    chunks: list[str] = []
    used = 0
    for match in FUNC_DECL_SOL_RE.finditer(text):
        name = match.group(1)
        body = _function_body(text, name)
        if not body or not SENSITIVE_BODY_RE.search(body):
            continue
        block = f"// function {name}\n{body}\n"
        if used + len(block) > budget:
            break
        chunks.append(block)
        used += len(block)
    if used < budget // 3:
        return text[:budget]
    return "".join(chunks)


def _import_context(entry: dict[str, Any], by_name: dict[str, dict[str, Any]]) -> str:
    chunks: list[str] = []
    for imported in IMPORT_PATH_RE.findall(entry["text"]):
        key = imported.rsplit("/", 1)[-1]
        peer = by_name.get(key)
        if peer and peer["relative_path"] != entry["relative_path"]:
            chunks.append(f"// imported dependency: {peer['relative_path']}\n{_compact_excerpt(peer['text'], CONTEXT_CHAR_BUDGET)}")
        if len(chunks) >= 2:
            break
    return "\n\n".join(chunks)[: CONTEXT_CHAR_BUDGET * 2]


def _audit_prompt(batch: list[dict[str, Any]], by_name: dict[str, dict[str, Any]]) -> str:
    instructions = (
        "Review every source file below for real, exploitable high or critical severity "
        "vulnerabilities. Examine each file in turn: incorrect access control, unsafe external "
        "calls before state updates, unchecked or mismatched arithmetic, oracle or price misuse, "
        "signature or allowance/permission handling, and accounting errors that let value be "
        "stolen, duplicated, or permanently locked - including bugs that only appear when you "
        "trace how one function's output feeds another, or how a file interacts with the "
        "imported dependency shown alongside it. Report a finding whenever you can point to the "
        "specific lines that cause it, even if it takes careful reasoning to see - do not hold "
        "back a real, code-grounded bug just because it is subtle. Every finding must name the "
        "exact file, the function it lives in, and the lines responsible.\n\n"
        'Respond with strict JSON only: {"findings":[{"file":"path","function":"name",'
        '"line":123,"severity":"high|critical","title":"short bug summary",'
        '"description":"2-4 sentences: the flaw, how it is triggered, and the impact"}]}\n'
        "Return up to 6 findings, one per distinct bug.\n\n"
    )
    sections = [instructions]
    room = AUDIT_BATCH_CHAR_BUDGET - len(instructions)
    for entry in batch:
        header = f"===== FILE: {entry['relative_path']} =====\n"
        if entry["names"]:
            header += f"Declared: {', '.join(entry['names'])}\n"
        hot = _hot_function_names(entry["text"])
        if hot:
            header += f"Sensitive functions: {', '.join(hot)}\n"
        block = header + _compact_excerpt(entry["text"])
        context = _import_context(entry, by_name)
        if context:
            block += f"\n----- Imported dependency excerpt -----\n{context}\n"
        if len(block) > room:
            block = block[: max(0, room)] + "\n/* truncated */\n"
        if room <= 0:
            break
        sections.append(block)
        room -= len(block)
    return "\n\n".join(sections)


def _audit_batch(
    inference_api: str | None,
    batch: list[dict[str, Any]],
    by_name: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    if not batch:
        return []
    try:
        raw_text = _call_model(inference_api, _audit_prompt(batch, by_name), max_tokens=AUDIT_MAX_TOKENS)
    except Exception as exc:
        _stderr(f"audit batch failed: {exc}")
        return []
    parsed = _extract_json_object(raw_text)
    findings = parsed.get("findings")
    return [item for item in findings if isinstance(item, dict)] if isinstance(findings, list) else []


def _is_speculative(description: str, title: str) -> bool:
    combined = f"{title} {description}"
    if SPECULATIVE_HEDGE_RE.search(combined):
        return True
    hedge_words = ("if ", "could ", "may ", "might ", "potentially ")
    lowered = f" {combined.lower()} "
    return sum(lowered.count(word) for word in hedge_words) >= 4


def _match_file(raw_path: str, known_paths: list[str]) -> str | None:
    raw_path = raw_path.strip()
    if not raw_path:
        return None
    for known in known_paths:
        if raw_path == known or known.endswith(raw_path) or raw_path.endswith(known):
            return known
    return None


def _finalize_finding(raw: dict[str, Any], known_paths: list[str]) -> dict[str, Any] | None:
    file_value = _match_file(str(raw.get("file") or ""), known_paths)
    if file_value is None:
        return None
    severity = str(raw.get("severity") or "").strip().lower()
    if severity not in {"high", "critical"}:
        return None
    title = str(raw.get("title") or "").strip()
    description = str(raw.get("description") or "").strip()
    if len(description) < 40:
        return None
    if _is_speculative(description, title):
        return None
    function_name = str(raw.get("function") or "").strip()
    if not title:
        title = f"{file_value} - {function_name or 'high-impact vulnerability'}"
    line_value = raw.get("line")
    return {
        "title": title[:200],
        "description": description[:2500],
        "severity": severity,
        "file": file_value,
        "function": function_name,
        "line": line_value if isinstance(line_value, int) else None,
    }


def _dedupe(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen_keys: set[tuple[str, str]] = set()
    unique: list[dict[str, Any]] = []
    for finding in findings:
        file_key = str(finding.get("file", "")).lower()
        function_key = str(finding.get("function", "")).lower()
        key = (file_key, function_key) if function_key else (file_key, str(finding.get("title", "")).lower()[:100])
        if key in seen_keys:
            continue
        seen_keys.add(key)
        unique.append(finding)
        if len(unique) >= MAX_FINDINGS_RETURNED:
            break
    return unique


def _empty_report() -> dict[str, list[dict[str, Any]]]:
    return {"vulnerabilities": []}


def agent_main(project_dir: str | None = None, inference_api: str | None = None) -> dict:
    started_at = time.monotonic()
    root = _resolve_project_root(project_dir)
    if root is None:
        return _empty_report()

    files = _collect_source_files(root)
    if not files:
        return _empty_report()

    ranked_files, graph = _rank_files(files)
    by_name = {Path(entry["relative_path"]).name: entry for entry in ranked_files}
    known_paths = [entry["relative_path"] for entry in ranked_files]

    raw_findings: list[dict[str, Any]] = []
    raw_findings.extend(_free_reentrancy_findings(ranked_files))
    raw_findings.extend(_free_tx_origin_findings(ranked_files))

    target_files = _run_triage(inference_api, ranked_files)
    primary_batch, secondary_batch = _build_audit_batches(target_files, ranked_files, graph)

    if time.monotonic() - started_at < MAX_RUNTIME_SECONDS:
        raw_findings.extend(_audit_batch(inference_api, primary_batch, by_name))
    if time.monotonic() - started_at < MAX_RUNTIME_SECONDS:
        raw_findings.extend(_audit_batch(inference_api, secondary_batch, by_name))

    finalized: list[dict[str, Any]] = []
    for raw in raw_findings:
        finding = _finalize_finding(raw, known_paths)
        if finding is not None:
            finalized.append(finding)
    return {"vulnerabilities": _dedupe(finalized)}


if __name__ == "__main__":
    project_argument = sys.argv[1] if len(sys.argv) > 1 else None
    print(json.dumps(agent_main(project_argument), indent=2))
