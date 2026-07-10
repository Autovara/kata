from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


SOURCE_EXTENSIONS = (".sol", ".vy", ".move", ".rs", ".cairo")
IGNORED_PARTS = {
    ".git",
    ".github",
    "artifacts",
    "broadcast",
    "cache",
    "coverage",
    "docs",
    "lib",
    "mock",
    "mocks",
    "node_modules",
    "out",
    "script",
    "scripts",
    "test",
    "tests",
    "vendor",
}

MAX_FILES = 64
MAX_FILE_BYTES = 220_000
MAX_BRIEF_CHARS = 18_000
MAX_SNIPPET_CHARS = 32_000
MAX_FINDINGS = 10
MAX_TRIAGE_TARGETS = 14
RELATED_CONTEXT_CHARS = 5_500
RUN_BUDGET_SECONDS = 235.0
REQUEST_TIMEOUT = 135

FUNCTION_RE = re.compile(
    r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*([^{};]*)(?:;|\{)",
    re.MULTILINE,
)
VYPER_FUNCTION_RE = re.compile(
    r"^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*(?:->\s*([^:]+))?:",
    re.MULTILINE,
)
CONTRACT_RE = re.compile(
    r"^\s*(?:abstract\s+contract|contract|library|interface)\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
IMPORT_RE = re.compile(r'^\s*import\b[^;]*?["\']([^"\']+)["\']', re.MULTILINE)
STATE_RE = re.compile(
    r"^\s*(?:mapping\s*\([^;]+|[A-Za-z_][A-Za-z0-9_<>,\[\]. ]+)\s+"
    r"(?:public|private|internal|constant|immutable|override|\s)*"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:=|;)",
    re.MULTILINE,
)

PATH_WEIGHT_TERMS = (
    "vault",
    "pool",
    "swap",
    "router",
    "manager",
    "controller",
    "strategy",
    "staking",
    "reward",
    "treasury",
    "bridge",
    "factory",
    "proxy",
    "govern",
    "oracle",
    "liquidat",
    "market",
    "token",
    "escrow",
    "auction",
    "vesting",
    "emission",
    "gauge",
    "fee",
    "position",
    "reserve",
    "order",
    "rental",
    "reservation",
    "refund",
    "lending",
    "perp",
    "dex",
    "math",
    "library",
    "contract",
    "contracts",
    "program",
    "programs",
    "cosmwasm",
    "anchor",
    "cairo",
    "starknet",
)

SOURCE_WEIGHT_TERMS = (
    "delegatecall",
    "selfdestruct",
    "tx.origin",
    ".call{",
    "assembly",
    "ecrecover",
    "permit",
    "signature",
    "nonce",
    "initialize",
    "upgradeTo",
    "setImplementation",
    "withdraw",
    "redeem",
    "deposit",
    "borrow",
    "repay",
    "liquidat",
    "collateral",
    "share",
    "totalAssets",
    "totalSupply",
    "oracle",
    "price",
    "latestRoundData",
    "swap",
    "flash",
    "claim",
    "reward",
    "epoch",
    "harvest",
    "unchecked",
    "safeTransfer",
    "transferFrom",
    "mint",
    "burn",
    "donate",
    "slippage",
    "rounding",
    "precision",
    "overflow",
    "underflow",
    "sqrt",
    "mulDiv",
    "fixed",
    "mantissa",
    "exponent",
    "public fun",
    "entry fun",
    "acquires",
    "pub fn",
    "entry_point",
    "cosmwasm_std",
    "depsmut",
    "messageinfo",
    "anchor_lang",
    "#[program]",
    "accountinfo",
    "remaining_accounts",
    "invoke_signed",
    "lamports",
    "signer",
    "owner",
    "admin",
    "role",
    "pause",
    "kill",
    "cancel",
    "refund",
    "has_one",
    "seeds",
    "bump",
    "get_caller_address",
    "contractstate",
    "storage",
    "felt252",
)

AUDIT_SYSTEM_PROMPT = (
    "You are auditing smart-contract code. Return JSON only. "
    "Report only high or critical exploitable vulnerabilities with concrete impact. "
    "Ignore style, gas, centralization, missing events, and speculative issues."
)


def agent_main(
    project_dir: str | None = None,
    inference_api: str | None = None,
) -> dict:
    root = _find_project_root(project_dir)
    if root is None:
        return _result([])

    files = _collect_sources(root)
    if not files:
        return _result([])

    started = time.monotonic()
    brief = _repository_brief(files)
    findings: list[dict[str, Any]] = []
    target_paths: list[str] = []
    endpoint = (inference_api or os.environ.get("INFERENCE_API") or "").rstrip("/")

    if endpoint:
        triage_response = _ask_inference(endpoint, _build_triage_prompt(brief), max_tokens=5000)
        findings.extend(_parse_findings(triage_response, files))
        target_paths = _parse_target_files(triage_response, files)

        for focus, selected in _audit_batches(files, target_paths):
            if time.monotonic() - started > RUN_BUDGET_SECONDS:
                break
            response = _ask_inference(
                endpoint,
                _build_prompt(focus, brief, selected, all_files=files),
                max_tokens=8000,
            )
            findings.extend(_parse_findings(response, files))
            if len(_dedupe_findings(findings)) >= MAX_FINDINGS:
                break

    if not findings:
        findings.extend(_pattern_findings(files))

    return _result(_dedupe_findings(findings)[:MAX_FINDINGS])


def _result(findings: list[dict[str, Any]]) -> dict:
    return {"vulnerabilities": findings}


def _find_project_root(project_dir: str | None) -> Path | None:
    candidates: list[str] = []
    if project_dir:
        candidates.append(project_dir)
    for name in ("PROJECT_DIR", "PROJECT_PATH", "PROJECT_ROOT", "PROJECT_CODE"):
        value = os.environ.get(name)
        if value:
            candidates.append(value)
    candidates.extend(("/app/project_code", "/app/project", "/project", "/code", "."))

    for raw in candidates:
        try:
            root = Path(raw).expanduser().resolve()
        except (OSError, RuntimeError):
            continue
        if not root.is_dir():
            continue
        try:
            if any(path.is_file() and path.suffix.lower() in SOURCE_EXTENSIONS for path in root.rglob("*")):
                return root
        except OSError:
            continue
    return None


def _collect_sources(root: Path) -> list[dict[str, Any]]:
    collected: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in SOURCE_EXTENSIONS:
            continue
        try:
            relative = path.relative_to(root).as_posix()
        except ValueError:
            continue
        parts = {part.lower() for part in Path(relative).parts}
        if parts & IGNORED_PARTS:
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if text.strip():
            collected.append(
                {
                    "path": relative,
                    "text": text,
                    "score": _risk_score(relative, text),
                }
            )
    collected.sort(key=lambda item: (-int(item["score"]), str(item["path"])))
    return collected[:MAX_FILES]


def _risk_score(relative: str, text: str) -> int:
    name = relative.lower()
    source = text.lower()
    score = min(
        source.count("function ")
        + source.count("\ndef ")
        + source.count(" fun ")
        + source.count("fn "),
        40,
    )
    for term in PATH_WEIGHT_TERMS:
        if term in name:
            score += 8
    for term in SOURCE_WEIGHT_TERMS:
        score += min(source.count(term.lower()), 8) * 4
    if "external" in source or "public" in source or "@external" in source:
        score += 5
    if any(word in source for word in ("onlyowner", "onlyrole", "auth", "governor")):
        score += 3
    if any(
        word in source
        for word in (
            "balance",
            "reserve",
            "supply",
            "price",
            "rate",
            "coin",
            "resource",
            "capability",
            "signer",
            "account",
            "storage",
            "caller",
        )
    ):
        score += 5
    return score


def _repository_brief(files: list[dict[str, Any]]) -> str:
    rows: list[str] = []
    for item in files[:32]:
        text = str(item["text"])
        path = str(item["path"])
        contracts = ", ".join(CONTRACT_RE.findall(text)[:6]) or "-"
        functions = []
        for match in FUNCTION_RE.finditer(text):
            functions.append(f"{match.group(1)}({match.group(2).strip()}) {match.group(3).strip()}")
            if len(functions) >= 12:
                break
        if not functions and str(item["path"]).endswith(".move"):
            for match in re.finditer(
                r"\b(?:public\s+)?(?:entry\s+)?fun\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)",
                text,
            ):
                functions.append(f"{match.group(1)}({match.group(2).strip()})")
                if len(functions) >= 12:
                    break
        if not functions and str(item["path"]).endswith((".rs", ".cairo")):
            for match in re.finditer(
                r"\b(?:pub\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:<[^>]+>)?\s*\(([^)]*)\)",
                text,
            ):
                functions.append(f"{match.group(1)}({match.group(2).strip()})")
                if len(functions) >= 12:
                    break
        if not functions:
            for match in VYPER_FUNCTION_RE.finditer(text):
                suffix = f" -> {match.group(3).strip()}" if match.group(3) else ""
                functions.append(f"{match.group(1)}({match.group(2).strip()}){suffix}")
                if len(functions) >= 12:
                    break
        risk_hits = [
            term
            for term in SOURCE_WEIGHT_TERMS
            if term.lower() in text.lower()
        ][:12]
        row = {
            "file": path,
            "language": Path(path).suffix.lstrip("."),
            "contracts": contracts,
            "state": _state_vars(text),
            "risk_terms": risk_hits,
            "risk_lines": _risk_lines(text),
            "functions": functions,
        }
        rows.append(json.dumps(row, ensure_ascii=False))
    brief = "\n".join(rows)
    return brief[:MAX_BRIEF_CHARS]


def _state_vars(text: str) -> list[str]:
    names: list[str] = []
    for name in STATE_RE.findall(text):
        if name not in names and len(name) < 48:
            names.append(name)
        if len(names) >= 14:
            break
    return names


def _risk_lines(text: str) -> list[str]:
    lines: list[str] = []
    lowered_terms = tuple(term.lower() for term in SOURCE_WEIGHT_TERMS)
    for number, line in enumerate(text.splitlines(), start=1):
        compact = " ".join(line.strip().split())
        if compact and any(term in compact.lower() for term in lowered_terms):
            lines.append(f"{number}: {compact[:160]}")
        if len(lines) >= 12:
            break
    return lines


def _build_prompt(
    focus: str,
    brief: str,
    files: list[dict[str, Any]],
    *,
    all_files: list[dict[str, Any]],
) -> str:
    snippets: list[str] = []
    remaining = MAX_SNIPPET_CHARS
    by_name = {Path(str(item["path"])).name: item for item in all_files}
    by_path = {str(item["path"]): item for item in all_files}
    for item in files:
        header = f"\n--- FILE: {item['path']} ---\n"
        related = _related_context(item, by_name=by_name, by_path=by_path)
        body_budget = remaining - len(header) - len(related)
        body = _numbered_source(str(item["text"]), body_budget)
        if len(body) < 120:
            continue
        chunk = header + body + related
        snippets.append(chunk)
        remaining -= len(chunk)
        if remaining <= 800:
            break

    return (
        "Audit focus: "
        + focus
        + "\n\nRepository map:\n"
        + brief
        + "\n\nSource snippets with line numbers:\n"
        + "".join(snippets)
        + "\n\nReturn exactly this JSON shape: "
        + '{"vulnerabilities":[{"title":"Contract.function - specific bug",'
        + '"description":"2-4 precise sentences with exploit steps and impact",'
        + '"severity":"high","type":"access-control|accounting|oracle|reentrancy|logic",'
        + '"file":"path/from/snippet.sol","function":"functionName","line":123,'
        + '"confidence":0.0}]}'
        + "\nEvery finding must identify the vulnerable path, function or entrypoint, "
        + "broken invariant, exploit steps, and concrete impact. Prioritize the SN60 "
        + "high-severity families that recur across competitive audits: asset/share "
        + "accounting, stale or manipulable oracle/slippage paths, lifecycle operations "
        + "such as cancel/burn/kill/delete, reward/epoch/index drift, unsafe refunds or "
        + "transfers, missing authorization, and denial-of-service that traps funds. "
        + "For Move code, check resource ownership, capability leakage, signer checks, "
        + "coin accounting, and cross-module invariant breaks. For Rust smart-contract "
        + "code, check CosmWasm message authorization and Solana/Anchor account, signer, "
        + "seed, CPI, and lamport accounting. For Cairo code, check caller authorization, "
        + "storage invariants, felt/u256 math, and cross-contract calls."
    )


def _build_triage_prompt(brief: str) -> str:
    return (
        "Use this repository map to choose the most security-critical files for a deep "
        "audit. Return JSON only with this shape: "
        '{"target_files":["exact/path"],"vulnerabilities":[{"title":"...",'
        '"description":"...", "severity":"high", "type":"logic", "file":"exact/path",'
        '"function":"optionalFunction", "confidence":0.0}]}'
        "\nPick files, not directories. Prefer files with external value movement, "
        "authorization, accounting, oracle, upgrade, signature, reward, liquidation, "
        "cross-contract, resource/capability, account-validation, or storage-invariant "
        "risk. Pay special attention to state lifecycle functions such as initialize, "
        "pause, unpause, cancel, burn, kill, withdraw, claim, redeem, settle, liquidate, "
        "distribute, refund, and transfer. Include an initial finding only when the map "
        "alone gives a concrete high-confidence issue; otherwise return an empty "
        "vulnerabilities list.\n\n"
        + brief
    )


def _audit_batches(
    files: list[dict[str, Any]],
    target_paths: list[str],
) -> list[tuple[str, list[dict[str, Any]]]]:
    ordered: list[dict[str, Any]] = []
    for target in target_paths[:MAX_TRIAGE_TARGETS]:
        matched = _find_file_record(target, files)
        if matched is not None and matched not in ordered:
            ordered.append(matched)
    for item in files:
        if item not in ordered:
            ordered.append(item)

    primary = ordered[:5]
    secondary = ordered[5:13] or ordered[:8]
    return [
        (
            "deep audit of triaged highest-risk files: exploitable entrypoints, "
            "state transitions, authority checks, and asset movement",
            primary,
        ),
        (
            "breadth audit of adjacent high-risk files: cross-file invariants, "
            "math/oracle/accounting edge cases, and privilege or capability misuse",
            secondary,
        ),
    ]


def _find_file_record(target: str, files: list[dict[str, Any]]) -> dict[str, Any] | None:
    normalized = target.strip().strip("./").replace("\\", "/")
    if not normalized:
        return None
    by_path = {str(item["path"]): item for item in files}
    if normalized in by_path:
        return by_path[normalized]
    by_name = {Path(path).name: item for path, item in by_path.items()}
    if Path(normalized).name in by_name:
        return by_name[Path(normalized).name]
    for path, item in by_path.items():
        if path.endswith(normalized) or normalized.endswith(path):
            return item
    return None


def _related_context(
    item: dict[str, Any],
    *,
    by_name: dict[str, dict[str, Any]],
    by_path: dict[str, dict[str, Any]],
) -> str:
    text = str(item["text"])
    current = str(item["path"])
    parts: list[str] = []
    for imported in IMPORT_RE.findall(text):
        normalized = imported.strip().replace("\\", "/")
        base = Path(normalized).name
        related = by_path.get(normalized) or by_name.get(base)
        if related is None or str(related["path"]) == current:
            continue
        snippet = str(related["text"])[: RELATED_CONTEXT_CHARS // 2]
        parts.append(f"\n--- RELATED IMPORT: {related['path']} ---\n{snippet}\n")
        if len(parts) >= 2:
            break
    joined = "".join(parts)
    return joined[:RELATED_CONTEXT_CHARS]


def _numbered_source(text: str, budget: int) -> str:
    out: list[str] = []
    used = 0
    for number, line in enumerate(text.splitlines(), start=1):
        rendered = f"{number}: {line.rstrip()}\n"
        used += len(rendered)
        if used > budget:
            break
        out.append(rendered)
    return "".join(out)


def _ask_inference(endpoint: str, prompt: str, *, max_tokens: int) -> str:
    body = json.dumps(
        {
            "messages": [
                {"role": "system", "content": AUDIT_SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "max_tokens": max_tokens,
            "response_format": {"type": "json_object"},
            "reasoning": {"effort": "low", "exclude": True},
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
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
            payload = json.loads(response.read().decode("utf-8", errors="ignore"))
    except (OSError, urllib.error.URLError, TimeoutError, ValueError):
        return ""
    try:
        return str(payload["choices"][0]["message"]["content"])
    except (KeyError, IndexError, TypeError):
        return ""


def _parse_findings(raw: str, files: list[dict[str, Any]]) -> list[dict[str, Any]]:
    payload = _json_payload(raw)
    if payload is None:
        return []
    if isinstance(payload, dict):
        items = payload.get("vulnerabilities", [])
    elif isinstance(payload, list):
        items = payload
    else:
        return []

    valid_paths = {str(item["path"]) for item in files}
    by_name = {Path(path).name: path for path in valid_paths}
    parsed: list[dict[str, Any]] = []
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        severity = str(item.get("severity", "high")).lower()
        if severity not in {"high", "critical"}:
            continue
        title = _clean_text(item.get("title"), 140)
        description = _clean_text(item.get("description"), 1800)
        file_name = _match_file(str(item.get("file", "")), valid_paths, by_name)
        if not title or not description or not file_name:
            continue
        if len(description) < 45:
            continue
        line = _as_positive_int(item.get("line"))
        finding = _make_finding(title, description, severity, file_name, line)
        function = _clean_text(item.get("function") or item.get("entrypoint"), 80)
        if function:
            finding["function"] = function
        vuln_type = _clean_text(
            item.get("type") or item.get("vulnerability_type") or item.get("category"),
            80,
        )
        if vuln_type:
            finding["type"] = vuln_type
        confidence = _as_float(item.get("confidence"))
        if confidence is not None:
            finding["confidence"] = max(0.0, min(1.0, confidence))
        parsed.append(finding)
    return parsed


def _parse_target_files(raw: str, files: list[dict[str, Any]]) -> list[str]:
    payload = _json_payload(raw)
    if not isinstance(payload, dict):
        return []
    candidates = (
        payload.get("target_files")
        or payload.get("targets")
        or payload.get("files")
        or []
    )
    if not isinstance(candidates, list):
        return []
    matched: list[str] = []
    for candidate in candidates:
        record = _find_file_record(str(candidate), files)
        if record is None:
            continue
        path = str(record["path"])
        if path not in matched:
            matched.append(path)
    return matched


def _json_payload(raw: str) -> Any:
    text = raw.strip()
    if not text:
        return None
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    start_positions = [pos for pos in (text.find("{"), text.find("[")) if pos >= 0]
    if not start_positions:
        return None
    start = min(start_positions)
    end = max(text.rfind("}"), text.rfind("]"))
    if end < start:
        return None
    try:
        return json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        return None


def _match_file(candidate: str, valid_paths: set[str], by_name: dict[str, str]) -> str | None:
    value = candidate.strip().strip("./")
    if value in valid_paths:
        return value
    normalized = value.replace("\\", "/")
    if normalized in valid_paths:
        return normalized
    if Path(normalized).name in by_name:
        return by_name[Path(normalized).name]
    for path in valid_paths:
        if path.endswith(normalized) or normalized.endswith(path):
            return path
    return None


def _clean_text(value: Any, limit: int) -> str:
    text = " ".join(str(value or "").split())
    return text[:limit].strip()


def _as_positive_int(value: Any) -> int | None:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _as_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _dedupe_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int | None]] = set()
    for finding in findings:
        title = str(finding.get("title", "")).lower()
        file_name = str(finding.get("file", ""))
        line = finding.get("line") if isinstance(finding.get("line"), int) else None
        key = (title, file_name, line)
        if key in seen:
            continue
        seen.add(key)
        out.append(finding)
    return out


def _make_finding(
    title: str,
    description: str,
    severity: str,
    file_name: str,
    line: int | None = None,
) -> dict[str, Any]:
    finding = dict(
        title=title,
        description=description,
        severity=severity,
        file=file_name,
    )
    if line is not None:
        finding["line"] = line
    return finding


def _pattern_findings(files: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for item in files[:24]:
        path = str(item["path"])
        text = str(item["text"])
        lowered = text.lower()
        if "tx.origin" in lowered:
            line = _line_of(text, "tx.origin")
            findings.append(
                _make_finding(
                    "tx.origin authorization can be bypassed by a phishing caller",
                    (
                        "This contract reads tx.origin in authorization logic. An attacker can "
                        "route a privileged user through a malicious contract so the origin check "
                        "passes while the attacker-controlled contract performs the sensitive call."
                    ),
                    "high",
                    path,
                    line,
                )
            )
        if "delegatecall" in lowered and _has_public_surface(text):
            line = _line_of(text, "delegatecall")
            findings.append(
                _make_finding(
                    "Externally reachable delegatecall can execute untrusted code in local storage",
                    (
                        "An externally reachable path performs delegatecall. If the target or calldata "
                        "can be influenced, the callee executes in this contract storage context and can "
                        "overwrite authority, balances, implementation slots, or other critical state."
                    ),
                    "critical",
                    path,
                    line,
                )
            )
        if "selfdestruct" in lowered and _has_public_surface(text):
            line = _line_of(text, "selfdestruct")
            findings.append(
                _make_finding(
                    "Externally reachable selfdestruct can permanently disable the contract",
                    (
                        "The source contains selfdestruct on a contract with public or external entry "
                        "points. If that call path lacks strict authorization, an attacker can destroy "
                        "the contract and permanently break user funds or protocol operations."
                    ),
                    "critical",
                    path,
                    line,
                )
            )
    return _dedupe_findings(findings)


def _line_of(text: str, needle: str) -> int | None:
    index = text.lower().find(needle.lower())
    if index < 0:
        return None
    return text.count("\n", 0, index) + 1


def _has_public_surface(text: str) -> bool:
    lowered = text.lower()
    return " external" in lowered or " public" in lowered or "@external" in lowered
