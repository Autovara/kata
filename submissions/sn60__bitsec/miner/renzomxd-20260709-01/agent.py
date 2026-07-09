from __future__ import annotations

"""Repository triage plus focused deep audits for SN60."""

import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


SOURCE_SUFFIXES = (".sol", ".vy", ".rs")
SKIP_DIRS = {
    ".git",
    ".github",
    "artifacts",
    "broadcast",
    "build",
    "cache",
    "coverage",
    "dist",
    "docs",
    "example",
    "examples",
    "generated",
    "interfaces",
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
    "vendors",
}

SOL_FUNC_RE = re.compile(
    r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*"
    r"([^{};]*)(?:;|\{)",
    re.MULTILINE,
)
VY_FUNC_RE = re.compile(
    r"^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*(?:->\s*([^:]+))?:",
    re.MULTILINE,
)
RS_FUNC_RE = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*"
    r"\(([^)]*)\)\s*(?:->\s*([^{]+))?\s*\{",
    re.MULTILINE,
)
CONTRACT_RE = re.compile(
    r"^\s*(?:abstract\s+contract|contract|library|interface)\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
RS_CONTAINER_RE = re.compile(
    r"^\s*(?:pub\s+)?(?:struct|enum|trait|impl)\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
IMPORT_RE = re.compile(r'^\s*import\b[^;]*?["\']([^"\']+)["\']', re.MULTILINE)
STATE_RE = re.compile(
    r"^\s*(?:mapping\s*\([^;]+|[A-Za-z_][A-Za-z0-9_<>,\[\]. ]+)\s+"
    r"(?:public|private|internal|constant|immutable|override|\s)*"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:=|;)",
    re.MULTILINE,
)

MAX_FILES = 80
MAX_FILE_BYTES = 260_000
MAX_FINDINGS = 8
MAX_DIGEST_CHARS = 18_000
MAX_BATCH_CHARS = 31_000
MAX_RELATED_CHARS = 4_000
MAX_RUNTIME_SECONDS = 230
REQUEST_TIMEOUT_SECONDS = 150
MAX_TRIAGE_CANDIDATES = 40
MAX_AUDIT_CANDIDATES = 10

RISK_TERMS = (
    "delegatecall",
    ".call{",
    ".call(",
    ".transfer(",
    ".send(",
    "selfdestruct",
    "tx.origin",
    "assembly",
    "ecrecover",
    "permit",
    "permitwrap",
    "signature",
    "nonce",
    "execute",
    "delegat",
    "validator",
    "epoch",
    "slash",
    "queue",
    "confirm",
    "gas",
    "sqrt",
    "ln(",
    "log(",
    "initialize",
    "upgradeTo",
    "upgradeToAndCall",
    "setImplementation",
    "setOracle",
    "setPrice",
    "setRate",
    "onlyOwner",
    "onlyRole",
    "accessControl",
    "_mint",
    "_burn",
    "mint(",
    "burn(",
    "withdraw",
    "deposit",
    "redeem",
    "borrow",
    "repay",
    "liquidat",
    "flash",
    "swap",
    "claim",
    "harvest",
    "reward",
    "oracle",
    "price",
    "balanceOf",
    "totalSupply",
    "totalAssets",
    "allowance",
    "approve",
    "transferFrom",
    "unchecked",
    "for (",
    "while (",
)

NAME_TERMS = (
    "vault",
    "pool",
    "router",
    "market",
    "oracle",
    "price",
    "token",
    "staking",
    "validator",
    "delegat",
    "consensus",
    "float",
    "math",
    "reward",
    "escrow",
    "auction",
    "proxy",
    "bridge",
    "factory",
    "govern",
    "lending",
    "borrow",
    "strategy",
    "manager",
    "treasury",
)

ACCOUNTING_TERMS = (
    "amount",
    "balance",
    "claim",
    "collateral",
    "debt",
    "discount",
    "floor",
    "index",
    "liquidat",
    "loss",
    "math",
    "nonce",
    "epoch",
    "validator",
    "delegat",
    "slash",
    "queue",
    "confirm",
    "position",
    "price",
    "profit",
    "rate",
    "refund",
    "reward",
    "round",
    "share",
    "slippage",
    "step",
    "supply",
    "swap",
    "sqrt",
    "log",
    "total",
    "vesting",
)

UTILITY_NAME_TERMS = (
    "faucet",
    "interface",
    "deployer",
    "executor",
    "mock",
    "helper",
)

REJECT_PHRASES = (
    "if access control is insufficient",
    "if any bypass of",
    "if compiler settings change",
    "if the admin slot is corrupted",
    "if the admin executor address is attacker-controlled",
    "if an external dependency is malicious or compromised",
    "if an upstream dependency fails to enforce authorization",
    "if the token is malicious",
    "if tokens do not behave as expected",
    "malicious or non-compliant erc20",
    "non-standard erc20 token",
    "commented out require statements",
    "without strict access control",
    "without explicit reentrancy protection",
    "can revert unexpectedly causing dos",
)

IDENTIFIER_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]{3,}\b")
GENERIC_IDENTIFIER_TERMS = {
    "address",
    "amount",
    "attacker",
    "balance",
    "because",
    "bypass",
    "caller",
    "contract",
    "critical",
    "external",
    "function",
    "impact",
    "incorrect",
    "leading",
    "loss",
    "marketplace",
    "material",
    "mechanism",
    "position",
    "protocol",
    "reentrancy",
    "seller",
    "state",
    "token",
    "tokens",
    "transfer",
    "unauthorized",
    "user",
    "users",
    "vesting",
    "without",
}

AUDITOR_SYSTEM = (
    "You are a senior smart-contract security auditor. Return only real high or "
    "critical vulnerabilities with a concrete exploit path and material impact. "
    "Reject style issues, gas issues, missing events, vague centralization notes, "
    "and low-confidence speculation. Return the final JSON immediately."
)


def _log(message: str) -> None:
    print(f"[sn60-agent] {message}", file=sys.stderr)


def _env_first(*names: str) -> str | None:
    for name in names:
        value = os.environ.get(name, "").strip()
        if value:
            return value
    return None


def _project_root(project_dir: str | None) -> Path | None:
    candidates = []
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
            for path in root.rglob("*"):
                if path.is_file() and path.suffix.lower() in SOURCE_SUFFIXES:
                    return root
        except OSError:
            continue
    return None


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _line_for(text: str, needle: str) -> int | None:
    if not needle:
        return None
    idx = text.find(needle)
    if idx < 0:
        return None
    return text.count("\n", 0, idx) + 1


def _functions(text: str, suffix: str) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for match in SOL_FUNC_RE.finditer(text):
        name = match.group(1)
        tail = " ".join(match.group(3).split())
        out.append({"name": name, "sig": f"{name}({match.group(2).strip()}) {tail}".strip()})
    for match in VY_FUNC_RE.finditer(text):
        name = match.group(1)
        returns = f" -> {match.group(3).strip()}" if match.group(3) else ""
        out.append({"name": name, "sig": f"{name}({match.group(2).strip()}){returns}".strip()})
    if suffix == ".rs":
        for match in RS_FUNC_RE.finditer(text):
            name = match.group(1)
            returns = f" -> {match.group(3).strip()}" if match.group(3) else ""
            out.append({"name": name, "sig": f"{name}({match.group(2).strip()}){returns}".strip()})
    return out


def _state_vars(text: str) -> list[str]:
    names: list[str] = []
    for name in STATE_RE.findall(text):
        if name not in names and len(name) < 48:
            names.append(name)
    return names[:16]


def _risk_lines(text: str) -> list[str]:
    lines: list[str] = []
    lowered = [term.lower() for term in RISK_TERMS]
    for idx, line in enumerate(text.splitlines(), start=1):
        compact = " ".join(line.strip().split())
        if not compact:
            continue
        low = compact.lower()
        if any(term in low for term in lowered):
            lines.append(f"{idx}: {compact[:180]}")
        if len(lines) >= 18:
            break
    return lines


def _accounting_lines(text: str) -> list[str]:
    lines: list[str] = []
    lowered = [term.lower() for term in ACCOUNTING_TERMS]
    for idx, line in enumerate(text.splitlines(), start=1):
        compact = " ".join(line.strip().split())
        if not compact:
            continue
        low = compact.lower()
        if any(term in low for term in lowered) and any(op in compact for op in ("+", "-", "*", "/", "%", ">", "<", "=")):
            lines.append(f"{idx}: {compact[:180]}")
        if len(lines) >= 18:
            break
    return lines


def _has_implementation_body(text: str) -> bool:
    return bool(
        re.search(r"\bfunction\b[\s\S]{0,200}\{", text)
        or re.search(r"^\s*def\b[\s\S]{0,200}:", text, re.MULTILINE)
        or re.search(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\b[\s\S]{0,200}\{", text, re.MULTILINE)
    )


def _score(rel: str, text: str) -> int:
    low_name = rel.lower()
    low_text = text.lower()
    score = min(low_text.count("function ") + low_text.count("\ndef ") + low_text.count("\nfn "), 35)
    for term in NAME_TERMS:
        if term in low_name:
            score += 8
    if any(token in low_name for token in ("router", "registry", "delegation", "consensus", "float")):
        score += 10
    for term in ACCOUNTING_TERMS:
        hits = low_text.count(term.lower())
        score += min(hits, 10) * 5
    for term in RISK_TERMS:
        hits = low_text.count(term.lower())
        score += min(hits, 6) * 4
    if any(term in low_name for term in UTILITY_NAME_TERMS):
        score -= 18
    if low_name.split("/")[-1].startswith("i") and "interface " in low_text and "contract " not in low_text and "library " not in low_text:
        score -= 40
    if "external" in low_text or "public" in low_text or "@external" in low_text:
        score += 6
    if any(token in low_text for token in ("permit(", "permitwrap", "allowance", "transferfrom")):
        score += 12
    if sum(token in low_text for token in ("queue", "confirm", "withdraw", "reward", "slash")) >= 2:
        score += 10
    if any(token in low_text for token in ("pure returns", "view returns")) and any(
        token in low_text for token in ("sqrt(", " ln(", " log(", "exponent", "mantissa", "packedfloat")
    ):
        score += 8
    if "onlyowner" not in low_text and "onlyrole" not in low_text:
        if any(token in low_text for token in ("mint(", "burn(", "upgrade", "setoracle", "setprice")):
            score += 8
    if any(token in low_text for token in ("nonreentrant", "reentrancyguard")):
        score += 2
    if any(token in low_text for token in ("for (", "while (", "delete ", "pop(")):
        score += 4
    if any(token in low_text for token in ("checked_sub", "checked_add", "saturating_", "wrapping_", "div_down", "mul_down")):
        score += 10
    return score


def _discover(root: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        try:
            rel_path = path.relative_to(root)
            if any(part.lower() in SKIP_DIRS for part in rel_path.parts[:-1]):
                continue
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        text = _read(path)
        if (
            "function" not in text
            and "contract " not in text
            and "library " not in text
            and "\ndef " not in text
            and not text.lstrip().startswith("def ")
        ):
            continue
        if not _has_implementation_body(text):
            continue
        rel = rel_path.as_posix()
        suffix = path.suffix.lower()
        funcs = _functions(text, suffix)
        contracts = CONTRACT_RE.findall(text)
        if not contracts and path.suffix.lower() == ".vy":
            contracts = [path.stem]
        if not contracts and suffix == ".rs":
            contracts = RS_CONTAINER_RE.findall(text) or [path.stem]
        records.append(
            {
                "path": path,
                "rel": rel,
                "suffix": suffix,
                "text": text,
                "contracts": contracts[:8],
                "functions": funcs,
                "score": _score(rel, text),
            }
        )
    records.sort(key=lambda record: (-int(record["score"]), str(record["rel"])))
    return records[:MAX_FILES]


def _repo_digest(records: list[dict[str, Any]]) -> str:
    chunks = []
    for record in records:
        chunks.append(
            json.dumps(
                {
                    "file": record["rel"],
                    "language": Path(str(record["rel"])).suffix.lstrip("."),
                    "contracts": record["contracts"],
                    "score": record["score"],
                    "state": _state_vars(str(record["text"])),
                    "functions": [item["sig"][:180] for item in record["functions"][:28]],
                    "accounting_lines": _accounting_lines(str(record["text"])),
                    "risk_lines": _risk_lines(str(record["text"])),
                },
                separators=(",", ":"),
            )
        )
    return "\n".join(chunks)[:MAX_DIGEST_CHARS]


def _related_context(record: dict[str, Any], by_name: dict[str, dict[str, Any]]) -> str:
    pieces: list[str] = []
    for imported in IMPORT_RE.findall(str(record["text"])):
        base = imported.rsplit("/", 1)[-1]
        other = by_name.get(base)
        if other and other["rel"] != record["rel"]:
            pieces.append(f"// import {other['rel']}\n{str(other['text'])[:MAX_RELATED_CHARS]}")
        if len(pieces) >= 2:
            break
    return "\n\n".join(pieces)[: MAX_RELATED_CHARS * 2]


def _find_function_match(text: str, function: str, suffix: str) -> re.Match[str] | None:
    if suffix == ".rs":
        return re.search(
            rf"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+{re.escape(function)}\b",
            text,
            re.MULTILINE,
        )
    if suffix == ".vy":
        return re.search(rf"^\s*def\s+{re.escape(function)}\b", text, re.MULTILINE)
    return re.search(rf"\bfunction\s+{re.escape(function)}\b", text)


def _extract_function_snippet(record: dict[str, Any], function: str) -> tuple[str, int | None]:
    text = str(record["text"])
    suffix = str(record.get("suffix") or "")
    match = _find_function_match(text, function, suffix)
    if match is None:
        return text[:5000], None
    start = match.start()
    line = text.count("\n", 0, start) + 1

    if suffix == ".vy":
        next_match = re.search(r"^\s*def\s+[A-Za-z_][A-Za-z0-9_]*\b", text[match.end() :], re.MULTILINE)
        end = match.end() + next_match.start() if next_match else min(len(text), match.end() + 5000)
        return text[start:end], line

    brace_start = text.find("{", match.end())
    if brace_start < 0:
        return text[start : min(len(text), start + 5000)], line

    depth = 0
    end = min(len(text), brace_start + 6000)
    for index in range(brace_start, min(len(text), brace_start + 20000)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                end = index + 1
                break
    return text[start:end], line


def _candidate_highlights(snippet: str) -> list[str]:
    lines: list[str] = []
    lowered_terms = [term.lower() for term in ACCOUNTING_TERMS + RISK_TERMS]
    for idx, line in enumerate(snippet.splitlines(), start=1):
        compact = " ".join(line.strip().split())
        if not compact:
            continue
        low = compact.lower()
        if any(term in low for term in lowered_terms) and any(op in compact for op in ("+", "-", "*", "/", "%", ">", "<", "=")):
            lines.append(f"{idx}: {compact[:180]}")
        elif any(term in low for term in ("claim", "redeem", "release", "settle", "queue", "withdraw", "liquidat")):
            lines.append(f"{idx}: {compact[:180]}")
        if len(lines) >= 10:
            break
    return lines


def _candidate_score(record: dict[str, Any], function: str, snippet: str) -> int:
    score = min(int(record["score"]), 160)
    low_name = function.lower()
    low_snippet = snippet.lower()
    for term in ACCOUNTING_TERMS:
        if term in low_name:
            score += 10
        hits = low_snippet.count(term.lower())
        score += min(hits, 12) * 3
    if any(
        token in low_name
        for token in (
            "claim",
            "update",
            "modify",
            "liquidat",
            "transfer",
            "swap",
            "purchase",
            "list",
            "withdraw",
            "redeem",
            "execute",
            "harvest",
            "undeploy",
            "confirm",
            "queue",
            "slash",
            "reward",
            "sqrt",
            "ln",
            "log",
            "eq",
        )
    ):
        score += 14
    if low_name == "execute" or low_name.startswith("execute"):
        score += 55
    if "permit" in low_name or ("permit" in low_snippet and "transferfrom" in low_snippet):
        score += 50
    if ("external payable" in low_snippet or "public payable" in low_snippet) and ("execute" in low_name or "dispatch" in low_name):
        score += 20
    if low_name.startswith(("set", "get")):
        score -= 18
    if any(token in low_snippet for token in ("checked_sub", "checked_add", "saturating_", "wrapping_", "div_down", "mul_down")):
        score += 12
    if any(token in low_snippet for token in ("permit", "allowance", "transferfrom", "nonce", "delegate", "validator", "reward", "slash", "epoch")):
        score += 10
    if any(token in low_snippet for token in ("sqrt(", " ln(", " log(", "packedfloat", "mantissa", "exponent")):
        score += 12
    score += min(len(_candidate_highlights(snippet)), 8) * 4
    return score


def _function_candidates(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for record in records:
        for func in record["functions"]:
            name = str(func["name"])
            snippet, line = _extract_function_snippet(record, name)
            candidates.append(
                {
                    "file": record["rel"],
                    "suffix": record["suffix"],
                    "contract": record["contracts"][0] if record["contracts"] else Path(str(record["rel"])).stem,
                    "function": name,
                    "line": line,
                    "snippet": snippet[:9000],
                    "score": _candidate_score(record, name, snippet),
                    "highlights": _candidate_highlights(snippet),
                }
            )
    candidates.sort(
        key=lambda item: (
            int(item["score"]),
            len(str(item["snippet"])),
            str(item["file"]),
        ),
        reverse=True,
    )

    per_file: dict[str, list[dict[str, Any]]] = {}
    file_order: list[str] = []
    for candidate in candidates:
        file_key = str(candidate["file"])
        bucket = per_file.setdefault(file_key, [])
        if not bucket:
            file_order.append(file_key)
        bucket.append(candidate)

    diverse: list[dict[str, Any]] = []
    for index in range(4):
        for file_key in file_order:
            bucket = per_file[file_key]
            if index < len(bucket):
                diverse.append(bucket[index])

    seen_ids = {(item["file"], item["function"], item["line"]) for item in diverse}
    for candidate in candidates:
        key = (candidate["file"], candidate["function"], candidate["line"])
        if key in seen_ids:
            continue
        diverse.append(candidate)
    return diverse


def _candidate_digest(candidates: list[dict[str, Any]]) -> str:
    rows = []
    for index, candidate in enumerate(candidates[:MAX_TRIAGE_CANDIDATES], start=1):
        rows.append(
            json.dumps(
                {
                    "id": index,
                    "file": candidate["file"],
                    "contract": candidate["contract"],
                    "function": candidate["function"],
                    "line": candidate["line"],
                    "score": candidate["score"],
                    "highlights": candidate["highlights"][:8],
                },
                separators=(",", ":"),
            )
        )
    return "\n".join(rows)


def _triage_candidates(inference_api: str | None, candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    prompt = (
        "Review these function-level audit candidates. Select the functions most likely to contain real "
        "high or critical bugs in accounting, authorization, asset movement, settlement ordering, "
        "signature or allowance handling, liquidation or redemption logic, or arithmetic invariants. "
        "Reject generic access-control notes, delegatecall theories, or malicious-token assumptions. "
        'Return strict JSON only: {"candidate_ids":[1,2,3]}\n\n'
        + _candidate_digest(candidates)
    )
    try:
        parsed = _json_obj(
            _request(
                inference_api,
                [{"role": "system", "content": AUDITOR_SYSTEM}, {"role": "user", "content": prompt}],
                2200,
            )
        )
    except Exception as exc:
        _log(f"candidate triage failed: {exc}")
        return candidates[:MAX_AUDIT_CANDIDATES]
    chosen_ids = parsed.get("candidate_ids")
    if not isinstance(chosen_ids, list):
        return candidates[:MAX_AUDIT_CANDIDATES]
    selected: list[dict[str, Any]] = []
    for item in chosen_ids:
        if isinstance(item, int) and 1 <= item <= min(len(candidates), MAX_TRIAGE_CANDIDATES):
            candidate = candidates[item - 1]
            if candidate not in selected:
                selected.append(candidate)
        if len(selected) >= MAX_AUDIT_CANDIDATES:
            break
    return selected or candidates[:MAX_AUDIT_CANDIDATES]


def _audit_candidate(inference_api: str | None, candidate: dict[str, Any]) -> dict[str, Any] | None:
    prompt = (
        "Audit this single function. Find at most one real high or critical vulnerability. Prefer concrete "
        "state-transition, accounting, settlement, authorization, signature, arithmetic, "
        "liquidation, redemption, or asset-flow bugs. Reject generic reentrancy, generic auth, "
        "admin compromise, malicious token, or external-contract "
        "assumptions. The answer must cite exact variables from the code snippet. Return strict JSON only:\n"
        '{"finding":null}\n'
        "or\n"
        '{"finding":{"title":"...","file":"...","contract":"...","function":"...","line":123,'
        '"severity":"high|critical","mechanism":"...","impact":"...","description":"..."}}\n\n'
        f"FILE: {candidate['file']}\n"
        f"CONTRACT_OR_MODULE: {candidate['contract']}\n"
        f"FUNCTION: {candidate['function']}\n"
        f"LINE: {candidate['line']}\n"
        + candidate["snippet"]
    )
    try:
        parsed = _json_obj(
            _request(
                inference_api,
                [{"role": "system", "content": AUDITOR_SYSTEM}, {"role": "user", "content": prompt}],
                2600,
            )
        )
    except Exception as exc:
        _log(f"candidate audit failed for {candidate['file']}::{candidate['function']}: {exc}")
        return None
    finding = parsed.get("finding")
    return finding if isinstance(finding, dict) else None


def _verify_candidate(inference_api: str | None, candidate: dict[str, Any], finding: dict[str, Any]) -> dict[str, Any] | None:
    prompt = (
        "You are a strict exploitability reviewer. Accept only if the proposed bug is directly supported by "
        "this function snippet and does not depend on unstated assumptions about malicious admins, malicious "
        "tokens, compromised external contracts, or omitted code. Prefer concrete accounting or state-transition "
        "bugs. Return strict JSON only:\n"
        '{"verdict":"reject","reason":"..."}\n'
        "or\n"
        '{"verdict":"accept","title":"...","file":"...","contract":"...","function":"...","line":123,'
        '"severity":"high|critical","mechanism":"...","impact":"...","description":"..."}\n\n'
        f"CANDIDATE FILE: {candidate['file']}\n"
        f"CANDIDATE FUNCTION: {candidate['function']}\n"
        "PROPOSED FINDING:\n"
        + json.dumps(finding, separators=(",", ":"))
        + "\n\nFUNCTION SNIPPET:\n"
        + candidate["snippet"]
    )
    try:
        parsed = _json_obj(
            _request(
                inference_api,
                [{"role": "system", "content": AUDITOR_SYSTEM}, {"role": "user", "content": prompt}],
                1800,
            )
        )
    except Exception as exc:
        _log(f"candidate verification failed for {candidate['file']}::{candidate['function']}: {exc}")
        return None
    if parsed.get("verdict") != "accept":
        return None
    return parsed


def _request(inference_api: str | None, messages: list[dict[str, str]], max_tokens: int) -> str:
    endpoint = (
        inference_api
        or os.environ.get("INFERENCE_API")
        or os.environ.get("KATA_SN60_INFERENCE_API")
        or "http://bitsec_proxy:8000"
    ).rstrip("/")
    payload: dict[str, Any] = {
        "messages": messages,
        "max_tokens": max_tokens,
        "response_format": {"type": "json_object"},
        "reasoning": {"effort": "low", "exclude": True},
    }
    model = _env_first(
        "BITSEC_OPENAI_MODEL",
        "INFERENCE_MODEL",
        "KATA_SN60_INFERENCE_MODEL",
        "OPENAI_MODEL",
    )
    if model:
        payload["model"] = model
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        endpoint + "/inference",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "x-inference-api-key": os.environ.get("INFERENCE_API_KEY", ""),
            "x-agent-id": os.environ.get("AGENT_ID", "local-miner"),
            "x-job-run-id": os.environ.get("JOB_RUN_ID", "local-run"),
            "x-request-phase": "execution",
        },
    )
    last_error: Exception | None = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
                payload = json.loads(response.read().decode("utf-8", "replace"))
            return _content(payload)
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = exc.read().decode("utf-8", "replace")[:400]
            except Exception:
                detail = ""
            _log(
                f"inference HTTP {exc.code} attempt {attempt + 1}/3 endpoint={endpoint}/inference"
                + (f" detail={detail}" if detail else "")
            )
            if exc.code == 429:
                raise
            last_error = exc
        except (OSError, ValueError, TimeoutError) as exc:
            _log(f"inference error attempt {attempt + 1}/3 endpoint={endpoint}/inference error={exc}")
            last_error = exc
        if attempt < 2:
            time.sleep(1.5 * (attempt + 1))
    raise RuntimeError(f"inference failed: {last_error}")


def _content(payload: dict[str, Any]) -> str:
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        return ""
    choice = choices[0]
    if not isinstance(choice, dict):
        return ""
    message = choice.get("message")
    if not isinstance(message, dict):
        return ""
    content = message.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, dict):
                text = item.get("text")
                if isinstance(text, str):
                    parts.append(text)
        return "".join(parts)
    return ""


def _json_obj(text: str) -> dict[str, Any]:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```[a-zA-Z]*\s*", "", stripped)
        stripped = re.sub(r"\s*```$", "", stripped)
    try:
        parsed = json.loads(stripped)
        return parsed if isinstance(parsed, dict) else {}
    except json.JSONDecodeError:
        pass
    start = stripped.find("{")
    if start < 0:
        return {}
    depth = 0
    in_string = False
    escaped = False
    for index in range(start, len(stripped)):
        char = stripped[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
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
                    parsed = json.loads(stripped[start : index + 1])
                except json.JSONDecodeError:
                    return {}
                return parsed if isinstance(parsed, dict) else {}
    return {}


def _triage(inference_api: str | None, records: list[dict[str, Any]]) -> tuple[list[str], list[dict[str, Any]]]:
    prompt = (
        "Review this compact smart-contract repository map. Pick the files most likely to contain "
        "real high or critical exploitable bugs. Prioritize accounting, state transitions, asset "
        "movement, signature or allowance flows, liquidation or redemption paths, and arithmetic "
        "invariants. Deprioritize generic admin, delegatecall, faucet, interface, utility, or "
        "'if compromised' style hypotheses. Return strict JSON only:\n"
        '{"target_files":["path.sol"],"findings":[]}\n'
        + _repo_digest(records)
    )
    try:
        parsed = _json_obj(
            _request(
                inference_api,
                [{"role": "system", "content": AUDITOR_SYSTEM}, {"role": "user", "content": prompt}],
                5000,
            )
        )
    except Exception as exc:
        _log(f"triage failed: {exc}")
        return [], []
    targets = parsed.get("target_files")
    findings = parsed.get("findings") or parsed.get("vulnerabilities") or []
    return (
        [item for item in targets if isinstance(item, str)] if isinstance(targets, list) else [],
        [item for item in findings if isinstance(item, dict)] if isinstance(findings, list) else [],
    )


def _batch_prompt(batch: list[dict[str, Any]], by_name: dict[str, dict[str, Any]]) -> str:
    header = (
        "Deep-audit the Solidity or Vyper source below. Find only high or critical vulnerabilities "
        "with a concrete exploit path. Prefer accounting, state transitions, asset settlement, "
        "allowance or permit misuse, liquidation, arithmetic domain handling, and rounding bugs. "
        "Reject generic reentrancy, delegatecall, "
        "admin compromise, malicious-token, or missing-access-control theories unless the code itself "
        "shows a direct exploit path in this function. Every finding must cite exact variable names "
        "from the function body. Return strict JSON only:\n"
        '{"findings":[{"title":"Contract.function - specific bug","file":"exact/path.sol",'
        '"contract":"Contract","function":"functionName","line":123,"severity":"high|critical",'
        '"mechanism":"preconditions -> attacker transactions -> broken invariant",'
        '"impact":"specific loss, insolvency, privilege escalation, or durable DoS",'
        '"description":"2-4 precise sentences naming the exact file, contract, function, exploit path, and impact"}]}\n'
        "Audit for state-transition correctness, token/share/accounting math, "
        "liquidation or redemption correctness, signature or allowance flows, "
        "math-library domain correctness, and operations that can permanently lock user or protocol funds. At most 4 findings. "
        "If an issue is not clearly exploitable and material, omit it.\n"
    )
    parts = [header]
    remaining = MAX_BATCH_CHARS - len(header)
    for record in batch:
        related = _related_context(record, by_name)
        block = (
            f"\n\n===== FILE: {record['rel']} =====\n"
            f"Contracts: {', '.join(record['contracts'])}\n"
            f"{record['text']}\n"
        )
        if related:
            block += f"\n===== DIRECT IMPORT CONTEXT FOR {record['rel']} =====\n{related}\n"
        if len(block) > remaining:
            block = block[: max(0, remaining)] + "\n/* truncated */\n"
        if remaining <= 0:
            break
        parts.append(block)
        remaining -= len(block)
    return "".join(parts)


def _deep_audit(
    inference_api: str | None,
    batch: list[dict[str, Any]],
    by_name: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    if not batch:
        return []
    try:
        parsed = _json_obj(
            _request(
                inference_api,
                [{"role": "system", "content": AUDITOR_SYSTEM}, {"role": "user", "content": _batch_prompt(batch, by_name)}],
                8000,
            )
        )
    except urllib.error.HTTPError as exc:
        _log(f"deep audit HTTP error: {exc}")
        return []
    except Exception as exc:
        _log(f"deep audit failed: {exc}")
        return []
    findings = parsed.get("findings") or parsed.get("vulnerabilities") or []
    return [item for item in findings if isinstance(item, dict)] if isinstance(findings, list) else []


def _choose_batches(targets: list[str], records: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rel_map = {str(record["rel"]): record for record in records}
    ordered: list[dict[str, Any]] = []
    for target in targets:
        for rel, record in rel_map.items():
            if target == rel or rel.endswith(target) or target.endswith(rel):
                if record not in ordered:
                    ordered.append(record)
                break
    for record in records:
        if record not in ordered:
            ordered.append(record)
    return ordered[:2], ordered[2:4]


def _too_speculative(text: str) -> bool:
    low = " " + " ".join(text.lower().split()) + " "
    if any(phrase in low for phrase in REJECT_PHRASES):
        return True
    hedge_count = sum(low.count(token) for token in (" if ", " could ", " may ", " might ", " potentially "))
    return hedge_count >= 4


def _evidence_tokens(record: dict[str, Any], function: str) -> set[str]:
    text = str(record["text"])
    window = text
    if function:
        match = re.search(rf"\bfunction\s+{re.escape(function)}\b", text)
        if not match:
            match = re.search(rf"^\s*def\s+{re.escape(function)}\b", text, re.MULTILINE)
        if match:
            start = max(0, match.start() - 800)
            end = min(len(text), match.start() + 6000)
            window = text[start:end]
    tokens = set()
    for token in IDENTIFIER_RE.findall(window):
        low = token.lower()
        if low in GENERIC_IDENTIFIER_TERMS:
            continue
        if low == function.lower():
            continue
        tokens.add(token)
    tokens.update(name for name in _state_vars(text) if len(name) >= 4)
    return tokens


def _normalize(raw: dict[str, Any], rel_map: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    file_value = str(raw.get("file") or raw.get("path") or "").strip()
    if not file_value:
        return None
    chosen = None
    for rel, record in rel_map.items():
        if file_value == rel or rel.endswith(file_value) or file_value.endswith(rel):
            chosen = record
            file_value = rel
            break
    if chosen is None:
        return None

    severity = str(raw.get("severity") or "").lower().strip()
    if severity not in {"high", "critical"}:
        return None

    function = str(raw.get("function") or "").strip().strip("`() ")
    if "." in function:
        function = function.split(".")[-1]
    valid_functions = {item["name"] for item in chosen["functions"]}
    if function and function not in valid_functions:
        function = ""

    contract = str(raw.get("contract") or "").strip().strip("`")
    if not contract and chosen["contracts"]:
        contract = str(chosen["contracts"][0])

    mechanism = str(raw.get("mechanism") or "").strip()
    impact = str(raw.get("impact") or "").strip()
    description = str(raw.get("description") or "").strip()
    title = str(raw.get("title") or "").strip()
    if len(mechanism) < 25 and len(description) < 120:
        return None
    combined = " ".join(part for part in (title, mechanism, impact, description) if part)
    if _too_speculative(combined):
        return None

    chosen_text_low = str(chosen["text"]).lower()
    combined_low = combined.lower()
    if "underflow" in combined_low and "unchecked" not in chosen_text_low:
        return None
    if "commented out require" in combined_low and "commented out require" not in chosen_text_low:
        return None
    if "reentranc" in combined_low and "nonreentrant" in chosen_text_low:
        return None
    if "authorization bypass" in combined_low and any(
        token in combined_low
        for token in (
            "external contract",
            "upstream contract",
            "without proper authorization",
        )
    ):
        return None
    evidence_tokens = _evidence_tokens(chosen, function)
    mentioned = {token for token in evidence_tokens if token.lower() in combined_low}
    if len(mentioned) < 2:
        low_function = function.lower()
        if not (
            function
            and low_function in combined_low
            and len(mentioned) >= 1
        ):
            return None

    location = ".".join(part for part in (contract, function) if part)
    if not title:
        title = f"{location or contract or file_value} - high-impact vulnerability"
    elif location and location.lower() not in title.lower():
        title = f"{location} - {title}"

    rebuilt = f"In `{file_value}`"
    if contract:
        rebuilt += f", contract `{contract}`"
    if function:
        rebuilt += f", function `{function}()`"
    rebuilt += ". "
    if mechanism:
        rebuilt += "Mechanism: " + mechanism.rstrip(".") + ". "
    if impact:
        rebuilt += "Impact: " + impact.rstrip(".") + ". "
    if description:
        rebuilt += description
    rebuilt = " ".join(rebuilt.split())
    if len(rebuilt) < 100:
        return None

    line = raw.get("line")
    if not isinstance(line, int):
        needle = f"function {function}" if function else title.split(" - ", 1)[0]
        line = _line_for(str(chosen["text"]), needle)

    return {
        "title": title[:220],
        "description": rebuilt[:3000],
        "severity": severity,
        "file": file_value,
        "function": function,
        "line": line if isinstance(line, int) else None,
        "type": str(raw.get("type") or "logic"),
        "confidence": 0.92 if severity == "critical" else 0.84,
    }


def _dedupe(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str]] = set()
    output: list[dict[str, Any]] = []
    ordered = sorted(
        findings,
        key=lambda item: (
            str(item.get("severity")) == "critical",
            float(item.get("confidence") or 0),
            len(str(item.get("description") or "")),
        ),
        reverse=True,
    )
    for item in ordered:
        key = (
            str(item.get("file") or "").lower(),
            str(item.get("function") or "").lower(),
            str(item.get("title") or "").lower()[:120],
        )
        if key in seen:
            continue
        seen.add(key)
        output.append(item)
        if len(output) >= MAX_FINDINGS:
            break
    return output


def _empty_report() -> dict[str, list[dict[str, Any]]]:
    return {"vulnerabilities": []}


def agent_main(
    project_dir: str | None = None,
    inference_api: str | None = None,
) -> dict:
    start = time.monotonic()
    root = _project_root(project_dir)
    if root is None:
        return _empty_report()

    records = _discover(root)
    if not records:
        return _empty_report()

    rel_map = {str(record["rel"]): record for record in records}
    by_name = {Path(str(record["rel"])).name: record for record in records}

    raw_findings: list[dict[str, Any]] = []
    target_files, triage_findings = _triage(inference_api, records)
    raw_findings.extend(triage_findings)

    primary_batch, secondary_batch = _choose_batches(target_files, records)
    for batch in (primary_batch, secondary_batch):
        if time.monotonic() - start >= MAX_RUNTIME_SECONDS:
            break
        raw_findings.extend(_deep_audit(inference_api, batch, by_name))

    candidates = _function_candidates(records)
    if not candidates:
        normalized = [_normalize(raw, rel_map) for raw in raw_findings]
        return {"vulnerabilities": _dedupe([item for item in normalized if item is not None])}

    selected = _triage_candidates(inference_api, candidates)
    for candidate in selected:
        if time.monotonic() - start >= MAX_RUNTIME_SECONDS:
            break
        proposed = _audit_candidate(inference_api, candidate)
        if not isinstance(proposed, dict):
            continue
        accepted = _verify_candidate(inference_api, candidate, proposed)
        if isinstance(accepted, dict):
            raw_findings.append(accepted)

    normalized: list[dict[str, Any]] = []
    for raw in raw_findings:
        item = _normalize(raw, rel_map)
        if item is not None:
            normalized.append(item)
    return {"vulnerabilities": _dedupe(normalized)}


if __name__ == "__main__":
    import sys

    project = sys.argv[1] if len(sys.argv) > 1 else None
    print(json.dumps(agent_main(project), indent=2))
