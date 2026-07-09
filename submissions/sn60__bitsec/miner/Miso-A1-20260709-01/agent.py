from __future__ import annotations

import json
import os
import re
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
MAX_BRIEF_CHARS = 14_000
MAX_SNIPPET_CHARS = 28_000
MAX_FINDINGS = 10
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
    "has_one",
    "seeds",
    "bump",
    "get_caller_address",
    "contractstate",
    "storage",
    "felt252",
)

AUDIT_SYSTEM_PROMPT = (
    "You are auditing Solidity and Vyper contracts. Return JSON only. "
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

    brief = _repository_brief(files)
    findings: list[dict[str, Any]] = []
    endpoint = (inference_api or os.environ.get("INFERENCE_API") or "").rstrip("/")

    if endpoint:
        passes = [
            (
                "access control, initialization, unsafe external calls, delegated execution",
                files[:10],
            ),
            (
                "asset accounting, share math, swaps, liquidations, fees, oracle use",
                files[4:16] or files[:10],
            ),
            (
                (
                    "cross-contract invariants, signatures, rewards, withdrawal and claim "
                    "paths, Move resource/accounting capabilities, Rust/CosmWasm/Solana "
                    "account validation, Cairo/Starknet storage and caller checks"
                ),
                files[10:24] or files[:12],
            ),
        ]
        for focus, selected in passes:
            response = _ask_inference(endpoint, _build_prompt(focus, brief, selected))
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
            "file": item["path"],
            "contracts": contracts,
            "risk_terms": risk_hits,
            "functions": functions,
        }
        rows.append(json.dumps(row, ensure_ascii=False))
    brief = "\n".join(rows)
    return brief[:MAX_BRIEF_CHARS]


def _build_prompt(focus: str, brief: str, files: list[dict[str, Any]]) -> str:
    snippets: list[str] = []
    remaining = MAX_SNIPPET_CHARS
    for item in files:
        header = f"\n--- FILE: {item['path']} ---\n"
        body = _numbered_source(str(item["text"]), remaining - len(header))
        if len(body) < 120:
            continue
        chunk = header + body
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
        + '{"vulnerabilities":[{"title":"...","description":"...","severity":"high",'
        + '"file":"path/from/snippet.sol","line":123}]}'
        + "\nEvery finding must identify the vulnerable path, exploit steps, and impact. "
        + "For Move code, check resource ownership, capability leakage, signer checks, "
        + "coin accounting, and cross-module invariant breaks. For Rust smart-contract "
        + "code, check CosmWasm message authorization and Solana/Anchor account, signer, "
        + "seed, CPI, and lamport accounting. For Cairo code, check caller authorization, "
        + "storage invariants, felt/u256 math, and cross-contract calls."
    )


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


def _ask_inference(endpoint: str, prompt: str) -> str:
    body = json.dumps(
        {
            "messages": [
                {"role": "system", "content": AUDIT_SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "max_tokens": 4500,
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
        description = _clean_text(item.get("description"), 1200)
        file_name = _match_file(str(item.get("file", "")), valid_paths, by_name)
        if not title or not description or not file_name:
            continue
        if len(description) < 45:
            continue
        line = _as_positive_int(item.get("line"))
        parsed.append(_make_finding(title, description, severity, file_name, line))
    return parsed


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
