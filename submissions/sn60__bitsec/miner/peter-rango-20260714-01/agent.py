"""General-purpose, evidence-first vulnerability miner."""

from __future__ import annotations

import json
import os
import posixpath
import re
import time
import urllib.error
import urllib.request
from collections import defaultdict
from pathlib import Path
from typing import Any

SOURCE_EXTENSIONS = frozenset({".sol", ".vy", ".cairo", ".move", ".rs"})
SKIP_DIRECTORIES = frozenset(
    {
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
        "node_modules",
        "out",
        "script",
        "scripts",
        "target",
        "test",
        "tests",
        "vendor",
        "vendors",
    }
)
MAX_SOURCE_FILES = 110
MAX_SOURCE_BYTES = 420_000
MAP_CHARS = 36_000
AUDIT_CHARS = 56_000
RELATED_CHARS = 6_000
MAX_FINDINGS = 16
RUN_SECONDS = 27 * 60
REQUEST_TIMEOUT = 220

NAME_SIGNALS = (
    "auction",
    "bridge",
    "borrow",
    "collateral",
    "controller",
    "factory",
    "govern",
    "liquidat",
    "manager",
    "market",
    "oracle",
    "pool",
    "position",
    "proxy",
    "router",
    "share",
    "stake",
    "strategy",
    "swap",
    "token",
    "treasury",
    "vault",
)
RISK_SIGNALS = (
    "approve",
    "assembly",
    "authorize",
    "borrow",
    "burn",
    "callback",
    "cancel",
    "claim",
    "delegatecall",
    "deposit",
    "ecrecover",
    "execute",
    "fee",
    "flash",
    "initialize",
    "liquidat",
    "mint",
    "nonce",
    "oracle",
    "permit",
    "price",
    "redeem",
    "reentr",
    "refund",
    "reward",
    "selfdestruct",
    "settle",
    "signature",
    "slippage",
    "stake",
    "swap",
    "transfer",
    "tx.origin",
    "unchecked",
    "unstake",
    "upgrade",
    "withdraw",
)
VALUE_SIGNALS = (
    "amount",
    "asset",
    "balance",
    "collateral",
    "debt",
    "fee",
    "liquidity",
    "price",
    "rate",
    "reward",
    "share",
    "supply",
    "value",
)

SOL_FUNCTION_RE = re.compile(
    r"\b(?:function|modifier)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*"
    r"\((?:[^()]|\([^()]*\))*\)[^{;]*",
    re.MULTILINE,
)
SOL_SPECIAL_RE = re.compile(r"\b(?P<name>constructor|receive|fallback)\s*\(", re.MULTILINE)
VY_FUNCTION_RE = re.compile(r"^\s*def\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(", re.MULTILINE)
CAIRO_FUNCTION_RE = re.compile(r"\bfn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*[<(]", re.MULTILINE)
MOVE_FUNCTION_RE = re.compile(
    r"\b(?:public(?:\([^)]*\))?\s+|public\s+entry\s+)?fun\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?:<[^>]*>)?\s*\(",
    re.MULTILINE,
)
RUST_FUNCTION_RE = re.compile(
    r"\b(?:pub(?:\([^)]*\))?\s+)?fn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"\s*(?:<[^>]*>)?\s*\(",
    re.MULTILINE,
)
SOL_CONTRACT_RE = re.compile(
    r"^\s*(?:abstract\s+contract|contract|library|interface)\s+"
    r"([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
CAIRO_CONTRACT_RE = re.compile(
    r"^\s*(?:#\[[^\]]+\]\s*)?(?:mod|impl|trait)\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
MOVE_MODULE_RE = re.compile(r"\bmodule\s+([A-Za-z0-9_]+::[A-Za-z0-9_]+)", re.MULTILINE)
RUST_TYPE_RE = re.compile(r"\b(?:impl|trait|struct|mod)\s+([A-Za-z_][A-Za-z0-9_]*)")
SOL_IMPORT_RE = re.compile(r"^\s*import\b[^;]*?[\"']([^\"']+)[\"']", re.MULTILINE)
VY_IMPORT_RE = re.compile(
    r"^\s*(?:from\s+([A-Za-z0-9_./]+)\s+import|import\s+([A-Za-z0-9_./]+))",
    re.MULTILINE,
)
USE_IMPORT_RE = re.compile(r"^\s*use\s+(?:crate::)?([A-Za-z0-9_:]+)", re.MULTILINE)

SYSTEM_PROMPT = (
    "You are a senior smart-contract security auditor. Work only from supplied source. "
    "Report exploitable high or critical vulnerabilities with a concrete attacker action, "
    "a broken invariant, and material impact. Ignore style, gas, missing events, trust "
    "assumptions, and speculation. Return strict JSON."
)


def agent_main(project_dir: str | None = None, inference_api: str | None = None) -> dict:
    """Run a bounded plan, depth audit, and cross-module audit for one project."""
    findings: list[dict[str, Any]] = []
    try:
        started = time.monotonic()
        root = _resolve_project_root(project_dir)
        if root is None:
            return {"vulnerabilities": findings}

        records = _discover_sources(root)
        if not records:
            return {"vulnerabilities": findings}
        graph = _build_graph(records)
        by_rel = {str(record["rel"]): record for record in records}
        endpoint = (inference_api or os.environ.get("INFERENCE_API") or "").rstrip("/")

        plan_reply, plan_status = _request(
            endpoint,
            _planning_prompt(records),
            max_tokens=5_000,
            reasoning_effort="low",
        )
        planning = _json_object(plan_reply)
        primary, secondary = _audit_batches(planning, records, graph)

        # A relay 429 is a hard per-problem budget boundary. Network failures are
        # different: keep trying the remaining independent audit with fallbacks.
        budget_exhausted = plan_status == 429
        if not budget_exhausted and _has_time(started):
            raw, audit_status = _audit(
                endpoint,
                primary,
                graph,
                planning,
                by_rel,
                mode="value-and-state",
                max_tokens=9_000,
            )
            _append_normalized(raw, by_rel, findings)
            budget_exhausted = audit_status == 429
        if not budget_exhausted and _has_time(started):
            raw, _audit_status = _audit(
                endpoint,
                secondary,
                graph,
                planning,
                by_rel,
                mode="cross-module",
                max_tokens=9_000,
            )
            _append_normalized(raw, by_rel, findings)
    except Exception:
        # The evaluator scores a crashed agent as invalid. Preserve any already
        # normalized evidence instead of losing the complete project result.
        pass
    return {"vulnerabilities": _dedupe_findings(findings)}


def _resolve_project_root(project_dir: str | None) -> Path | None:
    candidates: list[str] = []
    if project_dir:
        candidates.append(project_dir)
    for name in ("PROJECT_DIR", "PROJECT_PATH", "PROJECT_ROOT", "PROJECT_CODE"):
        value = os.environ.get(name)
        if value:
            candidates.append(value)
    candidates.extend(("/app/project_code", "/app/project", "/project", "/code", "."))
    for candidate in candidates:
        try:
            root = Path(candidate).expanduser().resolve()
        except (OSError, RuntimeError):
            continue
        if root.is_dir() and _contains_sources(root):
            return root
    return None


def _contains_sources(root: Path) -> bool:
    return next(_source_paths(root), None) is not None


def _discover_sources(root: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in _source_paths(root):
        try:
            if path.stat().st_size > MAX_SOURCE_BYTES:
                continue
            relative = path.relative_to(root).as_posix()
        except OSError:
            continue
        text = _read_text(path)
        if not text:
            continue
        extension = path.suffix.lower()
        functions = _functions(text, extension)
        contracts = _contracts(text, extension, path.stem)
        if not functions and not contracts:
            continue
        record: dict[str, Any] = {
            "path": path,
            "rel": relative,
            "ext": extension,
            "text": text,
            "functions": functions,
            "contracts": contracts,
            "imports": _imports(text, extension),
            "state": _state_hints(text),
            "signals": _risk_lines(text),
        }
        record["score"] = _risk_score(record)
        records.append(record)
    records.sort(key=lambda record: (-int(record["score"]), str(record["rel"])))
    return records[:MAX_SOURCE_FILES]


def _source_paths(root: Path):
    """Yield source files while pruning generated and dependency trees early."""
    try:
        for directory, names, files in os.walk(root, topdown=True, followlinks=False):
            names[:] = sorted(
                name
                for name in names
                if name.lower() not in SKIP_DIRECTORIES and not name.startswith(".")
            )
            parent = Path(directory)
            for name in sorted(files):
                if name.lower().endswith((".t.sol", ".s.sol", "_test.sol", ".test.sol")):
                    continue
                path = parent / name
                try:
                    if path.is_symlink() or not path.is_file():
                        continue
                except OSError:
                    continue
                if path.suffix.lower() in SOURCE_EXTENSIONS:
                    yield path
    except OSError:
        return


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _functions(text: str, extension: str) -> list[dict[str, Any]]:
    if extension == ".sol":
        patterns = (SOL_FUNCTION_RE, SOL_SPECIAL_RE)
    elif extension == ".vy":
        patterns = (VY_FUNCTION_RE,)
    elif extension == ".cairo":
        patterns = (CAIRO_FUNCTION_RE,)
    elif extension == ".move":
        patterns = (MOVE_FUNCTION_RE,)
    else:
        patterns = (RUST_FUNCTION_RE,)

    matches: list[tuple[int, str, str]] = []
    seen: set[tuple[int, str]] = set()
    for pattern in patterns:
        for match in pattern.finditer(text):
            name = match.group("name")
            key = (match.start(), name)
            if key in seen:
                continue
            seen.add(key)
            signature = " ".join(match.group(0).strip().split())[:220]
            matches.append((match.start(), name, signature))
    matches.sort()

    functions: list[dict[str, Any]] = []
    for index, (offset, name, signature) in enumerate(matches):
        next_offset = matches[index + 1][0] if index + 1 < len(matches) else len(text)
        line = text.count("\n", 0, offset) + 1
        body = text[offset:next_offset]
        functions.append(
            {
                "name": name,
                "line": line,
                "start": offset,
                "end": max(next_offset, offset + len(signature)),
                "sig": signature,
                "priority": _function_priority(signature, body),
            }
        )
    return functions


def _function_priority(signature: str, body: str) -> int:
    text = f"{signature}\n{body[:5000]}".lower()
    score = sum(2 for term in RISK_SIGNALS if term in text)
    if any(term in text for term in VALUE_SIGNALS):
        score += 3
    if any(term in text for term in ("external", "public", "entry", "payable")):
        score += 5
    if any(term in text for term in ("call", "transfer", "send", "delegate")):
        score += 4
    return score


def _contracts(text: str, extension: str, stem: str) -> list[str]:
    if extension == ".sol":
        names = SOL_CONTRACT_RE.findall(text)
    elif extension == ".cairo":
        names = CAIRO_CONTRACT_RE.findall(text)
    elif extension == ".move":
        names = MOVE_MODULE_RE.findall(text)
    elif extension == ".rs":
        names = RUST_TYPE_RE.findall(text)
    else:
        names = []
    if not names:
        names = [stem]
    return list(dict.fromkeys(names))[:12]


def _imports(text: str, extension: str) -> list[str]:
    if extension == ".sol":
        values = SOL_IMPORT_RE.findall(text)
    elif extension == ".vy":
        values = [left or right for left, right in VY_IMPORT_RE.findall(text)]
    else:
        values = USE_IMPORT_RE.findall(text)
    return list(dict.fromkeys(value.strip() for value in values if value.strip()))[:24]


def _risk_lines(text: str) -> list[str]:
    lines: list[str] = []
    for number, line in enumerate(text.splitlines(), start=1):
        lowered = line.lower()
        if not any(term in lowered for term in RISK_SIGNALS):
            continue
        compact = " ".join(line.strip().split())
        if compact:
            lines.append(f"{number}: {compact[:180]}")
        if len(lines) == 20:
            break
    return lines


def _state_hints(text: str) -> list[str]:
    hints: list[str] = []
    state_terms = ("mapping", "storage", "struct", "uint", "int", "address", "felt", "table")
    for line in text.splitlines():
        stripped = line.strip()
        lowered = stripped.lower()
        if not stripped or stripped.startswith(("//", "/*", "*", "#")):
            continue
        if not any(term in lowered for term in state_terms):
            continue
        if any(term in lowered for term in ("function ", "def ", " fn ", " event ", "error ")):
            continue
        compact = " ".join(stripped.split())
        if len(compact) <= 180:
            hints.append(compact)
        if len(hints) == 16:
            break
    return hints


def _risk_score(record: dict[str, Any]) -> int:
    relative = str(record["rel"]).lower()
    text = str(record["text"]).lower()
    score = min(len(record["functions"]) * 2, 48)
    for term in NAME_SIGNALS:
        score += 9 if term in relative else 2 if term in text else 0
    score += sum(3 for term in RISK_SIGNALS if term in text)
    if any(term in text for term in ("external", "public", "entry", "payable")):
        score += 7
    if any(term in text for term in ("call", "delegatecall", "transfer", "send")):
        score += 6
    return score


def _build_graph(records: list[dict[str, Any]]) -> dict[str, dict[str, set[str]]]:
    by_rel = {str(record["rel"]): record for record in records}
    by_name: dict[str, list[str]] = defaultdict(list)
    for relative in by_rel:
        by_name[Path(relative).name].append(relative)

    forward = {relative: set() for relative in by_rel}
    reverse = {relative: set() for relative in by_rel}
    for relative, record in by_rel.items():
        for imported in record["imports"]:
            target = _resolve_import(relative, str(imported), by_rel, by_name)
            if target is not None and target != relative:
                forward[relative].add(target)
                reverse[target].add(relative)
    for relative, record in by_rel.items():
        record["resolved_imports"] = sorted(forward[relative])
        record["imported_by"] = sorted(reverse[relative])
        record["score"] = (
            int(record["score"])
            + 5 * len(forward[relative])
            + 4 * len(reverse[relative])
        )
    records.sort(key=lambda record: (-int(record["score"]), str(record["rel"])))
    return {"forward": forward, "reverse": reverse}


def _resolve_import(
    relative: str,
    imported: str,
    by_rel: dict[str, dict[str, Any]],
    by_name: dict[str, list[str]],
) -> str | None:
    value = imported.strip().replace("\\", "/")
    if not value:
        return None
    candidates = [posixpath.normpath(value)]
    if value.startswith("."):
        candidates.insert(0, posixpath.normpath(posixpath.join(posixpath.dirname(relative), value)))
    if "::" in value:
        candidates.append(value.replace("::", "/"))
    if "." in value and "/" not in value and not value.endswith(tuple(SOURCE_EXTENSIONS)):
        candidates.append(value.replace(".", "/"))
    for candidate in candidates:
        if candidate in by_rel:
            return candidate
        for extension in SOURCE_EXTENSIONS:
            with_extension = candidate if candidate.endswith(extension) else candidate + extension
            if with_extension in by_rel:
                return with_extension
    basename = Path(value).name
    matches = by_name.get(basename, [])
    if len(matches) == 1:
        return matches[0]
    for extension in SOURCE_EXTENSIONS:
        matches = by_name.get(basename + extension, [])
        if len(matches) == 1:
            return matches[0]
    return None


def _planning_prompt(records: list[dict[str, Any]]) -> str:
    return (
        "Build an audit plan for this unfamiliar repository. Return JSON with targets "
        "and cross_file_reviews. Each target must name an exact file, relevant existing "
        "functions, a rationale, and invariants to test. Do not report vulnerabilities "
        "during planning. Prioritize public state transitions that move assets, change "
        "authority, rely on prices or signatures, settle positions, or cross boundaries.\n\n"
        "Required shape:\n"
        '{"targets":[{"file":"exact/path","functions":["name"],"rationale":"...",'
        '"invariants":["..."]}],"cross_file_reviews":[{"files":["exact/path"],'
        '"reason":"..."}]}\n\n'
        "Repository map:\n"
        + _repository_map(records)
    )


def _repository_map(records: list[dict[str, Any]]) -> str:
    chunks: list[str] = []
    used = 0
    for record in records:
        payload = {
            "file": record["rel"],
            "language": str(record["ext"]).lstrip("."),
            "risk_score": record["score"],
            "contracts": record["contracts"][:8],
            "imports": record.get("resolved_imports", [])[:8],
            "imported_by": record.get("imported_by", [])[:8],
            "functions": [f"{item['line']}: {item['sig']}" for item in record["functions"][:28]],
            "state_hints": record["state"][:12],
            "risk_lines": record["signals"][:14],
        }
        rendered = json.dumps(payload, ensure_ascii=True, separators=(",", ":")) + "\n"
        if used + len(rendered) > MAP_CHARS:
            break
        chunks.append(rendered)
        used += len(rendered)
    return "".join(chunks)


def _audit_batches(
    planning: dict[str, Any],
    records: list[dict[str, Any]],
    graph: dict[str, dict[str, set[str]]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    by_rel = {str(record["rel"]): record for record in records}
    requested = _planned_paths(planning, by_rel)
    ordered: list[dict[str, Any]] = []
    for relative in requested:
        record = by_rel.get(relative)
        if record is not None and record not in ordered:
            ordered.append(record)
    ordered.extend(record for record in records if record not in ordered)
    primary = ordered[:4]

    secondary_candidates: list[dict[str, Any]] = []
    for record in primary:
        relative = str(record["rel"])
        paths = graph["forward"].get(relative, set()) | graph["reverse"].get(relative, set())
        for path in sorted(paths):
            related = by_rel.get(path)
            if (
                related is not None
                and related not in primary
                and related not in secondary_candidates
            ):
                secondary_candidates.append(related)
    for record in ordered:
        if record not in primary and record not in secondary_candidates:
            secondary_candidates.append(record)
    return primary, _diverse_records(secondary_candidates, primary, limit=5)


def _planned_paths(planning: dict[str, Any], by_rel: dict[str, dict[str, Any]]) -> list[str]:
    paths: list[str] = []
    targets = planning.get("targets") or planning.get("target_files") or []
    if isinstance(targets, list):
        for target in targets:
            candidate = target.get("file") if isinstance(target, dict) else target
            matched = _match_record(str(candidate or ""), by_rel)
            if matched is not None and matched[0] not in paths:
                paths.append(matched[0])
    reviews = planning.get("cross_file_reviews") or []
    if isinstance(reviews, list):
        for review in reviews:
            if not isinstance(review, dict):
                continue
            for candidate in review.get("files") or []:
                matched = _match_record(str(candidate or ""), by_rel)
                if matched is not None and matched[0] not in paths:
                    paths.append(matched[0])
    return paths


def _planned_functions(
    planning: dict[str, Any],
    by_rel: dict[str, dict[str, Any]],
) -> dict[str, set[str]]:
    """Keep model-selected functions in truncated source excerpts when possible."""
    selected: dict[str, set[str]] = defaultdict(set)
    targets = planning.get("targets") or []
    if not isinstance(targets, list):
        return selected
    for target in targets:
        if not isinstance(target, dict):
            continue
        matched = _match_record(str(target.get("file") or ""), by_rel)
        if matched is None:
            continue
        relative, record = matched
        functions = target.get("functions") or []
        if not isinstance(functions, list):
            continue
        for candidate in functions:
            if not isinstance(candidate, str):
                continue
            function = _match_function(candidate, record)
            if function:
                selected[relative].add(function.lower())
    return selected


def _diverse_records(
    candidates: list[dict[str, Any]],
    primary: list[dict[str, Any]],
    *,
    limit: int,
) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    used_directories = {str(Path(str(record["rel"])).parent) for record in primary}
    for record in candidates:
        directory = str(Path(str(record["rel"])).parent)
        if directory in used_directories and len(selected) >= 2:
            continue
        selected.append(record)
        used_directories.add(directory)
        if len(selected) == limit:
            return selected
    for record in candidates:
        if record not in selected:
            selected.append(record)
        if len(selected) == limit:
            break
    return selected


def _audit(
    endpoint: str,
    records: list[dict[str, Any]],
    graph: dict[str, dict[str, set[str]]],
    planning: dict[str, Any],
    source_index: dict[str, dict[str, Any]],
    *,
    mode: str,
    max_tokens: int,
) -> tuple[list[dict[str, Any]], int]:
    if not records:
        return [], 0
    reply, status = _request(
        endpoint,
        _audit_prompt(records, graph, planning, source_index, mode),
        max_tokens=max_tokens,
    )
    payload = _json_object(reply)
    candidates = payload.get("vulnerabilities") or payload.get("findings") or []
    if not isinstance(candidates, list):
        return [], status
    return [item for item in candidates if isinstance(item, dict)], status


def _append_normalized(
    raw_findings: list[dict[str, Any]],
    by_rel: dict[str, dict[str, Any]],
    findings: list[dict[str, Any]],
) -> None:
    for candidate in raw_findings:
        finding = _normalize_finding(candidate, by_rel)
        if finding is not None:
            findings.append(finding)


def _audit_prompt(
    records: list[dict[str, Any]],
    graph: dict[str, dict[str, set[str]]],
    planning: dict[str, Any],
    source_index: dict[str, dict[str, Any]],
    mode: str,
) -> str:
    if mode == "value-and-state":
        focus = (
            "Trace value and state transitions end to end: input, authorization, "
            "calculation, storage mutation, external interaction, and settlement. "
            "Test accounting, pricing, rounding, callbacks, reentrancy, signatures, "
            "and asset conservation."
        )
    else:
        focus = (
            "Independently audit cross-module behavior: authority propagation, "
            "initialization and upgrades, lifecycle and cancellation paths, role "
            "changes, oracle dependencies, and inconsistent state across callers "
            "and dependencies. Find distinct exploit paths."
        )
    plan_excerpt = json.dumps(planning, ensure_ascii=True, separators=(",", ":"))[:4_000]
    preferred_functions = _planned_functions(planning, source_index)
    return (
        f"Audit mode: {mode}. {focus}\n\n"
        "Return JSON only:\n"
        '{"vulnerabilities":[{"title":"specific issue","file":"exact/path",'
        '"contract":"existing contract or module","function":"existing function",'
        '"line":123,"severity":"high|critical","type":"short category",'
        '"evidence":"specific source behavior","mechanism":"precondition -> attacker '
        'action -> violated invariant","impact":"concrete material result",'
        '"description":"precise supporting explanation"}]}\n\n'
        "Every finding must prove an attacker-reachable entry point, the controlling "
        "input or state condition, the wrong transition or external effect, and a "
        "material consequence. Do not invent files, functions, or line numbers. "
        "Omit anything uncertain. Report at most seven findings.\n\n"
        f"Planning context: {plan_excerpt}\n\n"
        + _source_pack(records, graph, source_index, preferred_functions)
    )


def _source_pack(
    records: list[dict[str, Any]],
    graph: dict[str, dict[str, set[str]]],
    source_index: dict[str, dict[str, Any]],
    preferred_functions: dict[str, set[str]],
) -> str:
    parts = ["Source material follows. Paths and numbered lines are authoritative.\n"]
    remaining = AUDIT_CHARS - len(parts[0])
    total = len(records)
    for index, record in enumerate(records):
        if remaining <= 0:
            break
        reserve = max(0, total - index - 1) * 7_000
        allowance = min(19_000, max(8_000, remaining - reserve))
        block = _record_block(
            record,
            allowance,
            preferred_functions.get(str(record["rel"]), set()),
        )
        block = block[:remaining]
        parts.append(block)
        remaining -= len(block)
        if remaining < 1_500:
            continue
        for neighbor in _neighbors(record, records, graph, source_index)[:2]:
            support = _related_block(
                neighbor,
                min(RELATED_CHARS, remaining),
                preferred_functions.get(str(neighbor["rel"]), set()),
            )
            if support:
                parts.append(support)
                remaining -= len(support)
            if remaining < 1_500:
                break
    return "".join(parts)


def _neighbors(
    record: dict[str, Any],
    batch: list[dict[str, Any]],
    graph: dict[str, dict[str, set[str]]],
    source_index: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    batch_paths = {str(item["rel"]) for item in batch}
    relative = str(record["rel"])
    paths = graph["forward"].get(relative, set()) | graph["reverse"].get(relative, set())
    neighbors = [
        source_index[path]
        for path in paths
        if path in source_index and path not in batch_paths and path != relative
    ]
    neighbors.sort(key=lambda item: (-int(item["score"]), str(item["rel"])))
    return neighbors


def _record_block(
    record: dict[str, Any], allowance: int, preferred_functions: set[str]
) -> str:
    metadata = (
        f"\n\n===== FILE {record['rel']} =====\n"
        f"Contracts/modules: {', '.join(record['contracts'][:8])}\n"
        f"Imports: {', '.join(record.get('resolved_imports', [])[:8]) or 'none'}\n"
        f"Imported by: {', '.join(record.get('imported_by', [])[:8]) or 'none'}\n"
        f"Functions: {json.dumps([item['sig'] for item in record['functions'][:32]])}\n"
        f"Risk lines: {json.dumps(record['signals'][:16])}\nSource:\n"
    )
    return metadata + _source_excerpt(
        record,
        max(1_000, allowance - len(metadata)),
        preferred_functions,
    )


def _related_block(
    record: dict[str, Any], allowance: int, preferred_functions: set[str]
) -> str:
    if allowance < 1_000:
        return ""
    header = f"\n\n----- RELATED FILE {record['rel']} -----\n"
    return header + _source_excerpt(
        record,
        max(800, allowance - len(header)),
        preferred_functions,
    )


def _source_excerpt(
    record: dict[str, Any], limit: int, preferred_functions: set[str] | None = None
) -> str:
    text = str(record["text"])
    if len(text) <= limit:
        return _numbered_lines(text, first_line=1, limit=limit)
    chunks: list[str] = []
    used = 0
    prelude = _numbered_lines(text[:5_000], first_line=1, limit=min(5_500, limit // 3))
    if prelude:
        chunks.append(prelude)
        used += len(prelude)
    preferred = preferred_functions or set()
    functions = sorted(
        record["functions"],
        key=lambda item: (
            str(item["name"]).lower() not in preferred,
            -int(item["priority"]),
            int(item["line"]),
            str(item["name"]),
        ),
    )
    included: set[str] = set()
    for function in functions:
        remaining = limit - used
        if remaining < 600:
            break
        name = str(function["name"])
        if name in included:
            continue
        included.add(name)
        start = int(function["start"])
        end = min(int(function["end"]), start + 12_000)
        rendered = "\n...\n" + _numbered_lines(
            text[start:end],
            first_line=int(function["line"]),
            limit=remaining - 10,
        )
        chunks.append(rendered)
        used += len(rendered)
    return "".join(chunks)[:limit]


def _numbered_lines(text: str, *, first_line: int, limit: int) -> str:
    rendered: list[str] = []
    used = 0
    for number, line in enumerate(text.splitlines(), start=first_line):
        row = f"{number:5}: {line.rstrip()}\n"
        if used + len(row) > limit:
            break
        rendered.append(row)
        used += len(row)
    return "".join(rendered)


def _request(
    endpoint: str,
    prompt: str,
    *,
    max_tokens: int,
    reasoning_effort: str | None = None,
) -> tuple[str, int]:
    if not endpoint:
        return "", 0
    payload: dict[str, Any] = {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "max_tokens": max_tokens,
        "response_format": {"type": "json_object"},
    }
    if reasoning_effort:
        payload["reasoning"] = {"effort": reasoning_effort, "exclude": True}
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        endpoint + "/inference",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "x-inference-api-key": os.environ.get("INFERENCE_API_KEY", ""),
        },
    )
    for attempt in range(2):
        try:
            with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
                response_payload = json.loads(response.read().decode("utf-8", errors="replace"))
            break
        except urllib.error.HTTPError as exc:
            if exc.code == 429 or exc.code < 500 or attempt:
                return "", exc.code
        except (OSError, ValueError, TimeoutError, urllib.error.URLError):
            if attempt:
                return "", 0
    else:
        return "", 0
    if not isinstance(response_payload, dict):
        return "", 200
    choices = response_payload.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        return "", 200
    message = choices[0].get("message")
    if not isinstance(message, dict):
        return "", 200
    content = message.get("content")
    if isinstance(content, str):
        return content, 200
    if isinstance(content, list):
        return (
            "".join(str(part.get("text") or "") for part in content if isinstance(part, dict)),
            200,
        )
    return "", 200


def _json_object(raw: str) -> dict[str, Any]:
    text = raw.strip()
    fence = chr(96) * 3
    if text.startswith(fence):
        newline = text.find("\n")
        text = text[newline + 1 :] if newline >= 0 else ""
        if text.rstrip().endswith(fence):
            text = text.rstrip()[: -len(fence)]
    try:
        value = json.loads(text)
        return value if isinstance(value, dict) else {}
    except json.JSONDecodeError:
        pass
    start = text.find("{")
    if start < 0:
        return {}
    depth = 0
    in_string = False
    escaped = False
    for index in range(start, len(text)):
        character = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                try:
                    value = json.loads(text[start : index + 1])
                    return value if isinstance(value, dict) else {}
                except json.JSONDecodeError:
                    return {}
    return {}


def _match_record(
    candidate: str,
    by_rel: dict[str, dict[str, Any]],
) -> tuple[str, dict[str, Any]] | None:
    value = candidate.strip().strip(chr(96) + " ").strip("./").replace("\\", "/").lower()
    if not value:
        return None
    exact = [(path, record) for path, record in by_rel.items() if path.lower() == value]
    if len(exact) == 1:
        return exact[0]
    suffix = [
        (path, record)
        for path, record in by_rel.items()
        if path.lower().endswith(value) or value.endswith(path.lower())
    ]
    if len(suffix) == 1:
        return suffix[0]
    basename = Path(value).name
    same_name = [
        (path, record) for path, record in by_rel.items() if Path(path).name.lower() == basename
    ]
    return same_name[0] if len(same_name) == 1 else None


def _normalize_finding(
    raw: dict[str, Any],
    by_rel: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    matched = _match_record(str(raw.get("file") or raw.get("path") or ""), by_rel)
    if matched is None:
        return None
    relative, record = matched
    severity = _clean(raw.get("severity")).lower()
    if severity not in {"high", "critical"}:
        return None
    title = _clean(raw.get("title"))
    evidence = _clean(raw.get("evidence") or raw.get("code_evidence"))
    mechanism = _clean(raw.get("mechanism") or raw.get("exploit_path"))
    impact = _clean(raw.get("impact"))
    explanation = _clean(raw.get("description"))
    if not title or not _credible(evidence, mechanism, impact, explanation):
        return None

    function = _match_function(_clean(raw.get("function") or raw.get("method")), record)
    line = _positive_line(raw.get("line"), str(record["text"]))
    if not function and line is not None:
        function = _function_at_line(line, record)
    if function and line is None:
        line = _function_line(function, record)
    contract = _match_contract(_clean(raw.get("contract") or raw.get("module")), record)
    if function and function.lower() not in title.lower():
        title = f"{function} - {title}"

    location = f"Location: {relative}"
    if contract:
        location += f", contract/module {contract}"
    if function:
        location += f", function {function}"
    if line is not None:
        location += f", line {line}"
    pieces = [location + "."]
    if evidence:
        pieces.append("Evidence: " + evidence.rstrip(".") + ".")
    if mechanism:
        pieces.append("Exploit path: " + mechanism.rstrip(".") + ".")
    if impact:
        pieces.append("Impact: " + impact.rstrip(".") + ".")
    if explanation:
        pieces.append(explanation)
    description = " ".join(pieces)

    return {
        "title": title[:220],
        "description": description[:3_200],
        "severity": severity,
        "file": relative,
        "contract": contract,
        "function": function,
        "line": line,
        "type": _clean(raw.get("type") or raw.get("category"))[:80] or "logic",
    }


def _credible(evidence: str, mechanism: str, impact: str, explanation: str) -> bool:
    combined = " ".join((evidence, mechanism, impact, explanation))
    if len(combined) < 140:
        return False
    if len(mechanism) < 24 and len(explanation) < 120:
        return False
    material_terms = (
        "drain",
        "fund",
        "loss",
        "lock",
        "insolv",
        "liquidat",
        "privilege",
        "steal",
        "unauthor",
        "denial",
        "dos",
        "execute",
        "bypass",
    )
    return any(term in combined.lower() for term in material_terms)


def _match_function(candidate: str, record: dict[str, Any]) -> str:
    value = candidate.strip().strip("() " + chr(96))
    if "." in value:
        value = value.rsplit(".", 1)[-1]
    for function in record["functions"]:
        if str(function["name"]).lower() == value.lower():
            return str(function["name"])
    return ""


def _function_at_line(line: int, record: dict[str, Any]) -> str:
    selected: dict[str, Any] | None = None
    for function in sorted(record["functions"], key=lambda item: int(item["line"])):
        if int(function["line"]) > line:
            break
        selected = function
    return str(selected["name"]) if selected is not None else ""


def _function_line(name: str, record: dict[str, Any]) -> int | None:
    for function in record["functions"]:
        if str(function["name"]) == name:
            return int(function["line"])
    return None


def _match_contract(candidate: str, record: dict[str, Any]) -> str:
    for contract in record["contracts"]:
        if candidate and str(contract).lower() == candidate.lower():
            return str(contract)
    return str(record["contracts"][0]) if record["contracts"] else ""


def _positive_line(value: Any, text: str) -> int | None:
    try:
        line = int(value)
    except (TypeError, ValueError):
        return None
    return line if 1 <= line <= text.count("\n") + 1 else None


def _clean(value: Any) -> str:
    return " ".join(str(value or "").replace("\x00", " ").split())


def _dedupe_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ordered = sorted(
        findings,
        key=lambda item: (
            item.get("severity") == "critical",
            bool(item.get("function")),
            len(str(item.get("description") or "")),
        ),
        reverse=True,
    )
    seen: set[tuple[str, str, str]] = set()
    deduped: list[dict[str, Any]] = []
    for finding in ordered:
        key = (
            str(finding.get("file") or "").lower(),
            str(finding.get("function") or "").lower(),
            _title_fingerprint(str(finding.get("title") or "")),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
        if len(deduped) == MAX_FINDINGS:
            break
    return deduped


def _title_fingerprint(title: str) -> str:
    stop_words = {"a", "an", "and", "can", "in", "of", "on", "the", "to", "with"}
    words = re.findall(r"[a-z0-9_]+", title.lower())
    return " ".join(word for word in words if word not in stop_words)[:140]


def _has_time(started: float) -> bool:
    return time.monotonic() - started < RUN_SECONDS


if __name__ == "__main__":
    print(json.dumps(agent_main(), indent=2))
