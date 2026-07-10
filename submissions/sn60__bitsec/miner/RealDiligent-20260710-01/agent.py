from __future__ import annotations

"""SN60 miner: heuristic file ranking with three full deep-audit inference passes.

Ranks Solidity/Vyper/Rust sources with static risk heuristics, then spends every
inference call on deep audits of the highest-priority files (no separate triage
call). Self-contained stdlib; uses the validator inference proxy only.
"""

import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

SOURCE_SUFFIXES = (".sol", ".vy", ".rs")
EXCLUDED_TOP = frozenset({
    ".git", ".github", "artifacts", "broadcast", "cache", "coverage", "dist", "docs",
    "example", "examples", "interfaces", "lib", "mock", "mocks", "node_modules", "out",
    "script", "scripts", "test", "tests", "vendor", "vendors",
})
EXCLUDED_IN_SRC = frozenset({"test", "tests", "mock", "mocks"})

FUNC_SOL = re.compile(
    r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*([^{};]*)(?:;|\{)",
    re.MULTILINE,
)
FUNC_VY = re.compile(r"^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", re.MULTILINE)
FUNC_RS = re.compile(r"^\s*(?:pub\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", re.MULTILINE)
CONTRACT = re.compile(
    r"^\s*(?:abstract\s+contract|contract|library|interface)\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
IMPORT = re.compile(r'^\s*import\b[^;]*?["\']([^"\']+)["\']', re.MULTILINE)
RISK_TOKEN = re.compile(
    r"\b(delegatecall|selfdestruct|tx\.origin|assembly|unchecked|\.call\s*\{|"
    r"onlyOwner|onlyRole|upgradeTo|initialize|withdraw|redeem|borrow|liquidat|"
    r"transferFrom|ecrecover|permit|unsafe|unchecked)\b",
    re.IGNORECASE,
)

MAX_SCAN_FILES = 80
MAX_FILE_BYTES = 280_000
CONTEXT_SLICE = 34_000
RELATED_SLICE = 2_800
MAX_OUTPUT = 7
WALL_CLOCK_BUDGET = 210.0
HTTP_TIMEOUT = 140

PRIORITY_TERMS = (
    "vault", "pool", "router", "bridge", "proxy", "upgrade", "oracle", "govern",
    "treasury", "manager", "market", "lend", "borrow", "collateral", "controller",
    "strategy", "auction", "token", "admin", "owner", "swap", "staking", "reward",
    "liquidat", "mint", "burn", "pause", "claim",
)

AUDITOR_PROMPT = (
    "You are a senior smart-contract security auditor. Return only real high or "
    "critical vulnerabilities with a concrete exploit path and material impact. "
    "Reject style, gas, missing events, and speculation. Return strict JSON only."
)


def agent_main(project_dir: str | None = None, inference_api: str | None = None) -> dict:
    findings: list[dict[str, Any]] = []
    root = _resolve_project_root(project_dir)
    if root is None:
        return {"vulnerabilities": findings}

    started = time.monotonic()
    catalog = _scan_sources(root)
    if not catalog:
        return {"vulnerabilities": findings}

    rel_index = {entry["rel"]: entry for entry in catalog}
    basename_index = {Path(entry["rel"]).name: entry for entry in catalog}

    ranked = sorted(catalog, key=lambda row: (-int(row["priority"]), str(row["rel"])))
    audit_groups = [
        ranked[:1],
        ranked[1:3],
        ranked[3:6],
    ]

    collected: list[dict[str, Any]] = []
    for group in audit_groups:
        if time.monotonic() - started >= WALL_CLOCK_BUDGET:
            break
        collected.extend(_audit_group(inference_api, group, basename_index))

    for item in collected:
        normalized = _normalize_finding(item, rel_index)
        if normalized is not None:
            findings.append(normalized)
    return {"vulnerabilities": _unique_findings(findings)}


def _resolve_project_root(project_dir: str | None) -> Path | None:
    candidates: list[str] = []
    if project_dir:
        candidates.append(project_dir)
    for env_name in ("PROJECT_DIR", "PROJECT_PATH", "PROJECT_ROOT", "PROJECT_CODE"):
        env_value = os.environ.get(env_name)
        if env_value:
            candidates.append(env_value)
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
            if path.is_file() and path.suffix.lower() in SOURCE_SUFFIXES:
                return True
    except OSError:
        return False
    return False


def _path_excluded(parts: tuple[str, ...]) -> bool:
    if not parts:
        return False
    in_src = "src" in {part.lower() for part in parts}
    for part in parts:
        lowered = part.lower()
        if in_src:
            if lowered in EXCLUDED_IN_SRC:
                return True
        elif lowered in EXCLUDED_TOP:
            return True
    return False


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _extract_functions(text: str, suffix: str) -> list[dict[str, str]]:
    output: list[dict[str, str]] = []
    if suffix in {".sol", ".vy"}:
        for match in FUNC_SOL.finditer(text):
            tail = " ".join(match.group(3).split())
            output.append({
                "name": match.group(1),
                "sig": f"{match.group(1)}({match.group(2).strip()}) {tail}".strip(),
            })
    if suffix == ".vy":
        for match in FUNC_VY.finditer(text):
            output.append({"name": match.group(1), "sig": match.group(1)})
    if suffix == ".rs":
        for match in FUNC_RS.finditer(text):
            output.append({"name": match.group(1), "sig": match.group(1)})
    return output


def _priority_score(rel: str, text: str) -> int:
    rel_lower = rel.lower()
    text_lower = text.lower()
    fn_count = (
        text_lower.count("function ")
        + text_lower.count("\ndef ")
        + text_lower.count("\nfn ")
    )
    score = min(fn_count, 36)
    for term in PRIORITY_TERMS:
        if term in rel_lower:
            score += 9
        elif term in text_lower:
            score += 2
    score += min(len(RISK_TOKEN.findall(text)), 18) * 2
    if "external" in text_lower or "public" in text_lower or "@external" in text_lower:
        score += 5
    if ".call" in text_lower and "nonreentrant" not in text_lower:
        score += 4
    return score


def _risk_snippets(text: str) -> list[str]:
    lines: list[str] = []
    for index, line in enumerate(text.splitlines(), start=1):
        if RISK_TOKEN.search(line):
            compact = " ".join(line.strip().split())
            if compact:
                lines.append(f"{index}: {compact[:150]}")
        if len(lines) >= 12:
            break
    return lines


def _scan_sources(root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        suffix = path.suffix.lower()
        if suffix not in SOURCE_SUFFIXES:
            continue
        try:
            rel_path = path.relative_to(root)
            if _path_excluded(tuple(rel_path.parts[:-1])):
                continue
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        text = _read_text(path)
        source_tokens = ("function", "contract ", "library ", "\ndef ", "fn ")
        if not any(token in text for token in source_tokens):
            continue
        rel = rel_path.as_posix()
        contracts = CONTRACT.findall(text)
        if not contracts and suffix == ".vy":
            contracts = [path.stem]
        rows.append({
            "path": path,
            "rel": rel,
            "text": text,
            "suffix": suffix,
            "contracts": contracts,
            "functions": _extract_functions(text, suffix),
            "priority": _priority_score(rel, text),
            "risk_snippets": _risk_snippets(text),
        })
    rows.sort(key=lambda row: (-int(row["priority"]), str(row["rel"])))
    return rows[:MAX_SCAN_FILES]


def _import_context(record: dict[str, Any], basename_index: dict[str, dict[str, Any]]) -> str:
    chunks: list[str] = []
    for imported in IMPORT.findall(str(record["text"])):
        base = imported.rsplit("/", 1)[-1]
        other = basename_index.get(base)
        if other and other["rel"] != record["rel"]:
            chunks.append(
                f"// import {other['rel']}\n{str(other['text'])[:RELATED_SLICE]}"
            )
        if len(chunks) >= 2:
            break
    return "\n\n".join(chunks)


def _audit_prompt(batch: list[dict[str, Any]], basename_index: dict[str, dict[str, Any]]) -> str:
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
    remaining = CONTEXT_SLICE - len(header)
    for record in batch:
        block = (
            f"\n\n===== FILE: {record['rel']} =====\n"
            f"Priority: {record['priority']}\n"
            f"Contracts: {', '.join(record['contracts'][:6])}\n"
            f"Risk snippets: {record['risk_snippets']}\n"
            f"{record['text']}\n"
        )
        related = _import_context(record, basename_index)
        if related:
            block += f"\n===== IMPORT CONTEXT =====\n{related}\n"
        if len(block) > remaining:
            block = block[: max(0, remaining)] + "\n/* truncated */\n"
        if remaining <= 0:
            break
        parts.append(block)
        remaining -= len(block)
    return "".join(parts)


def _call_inference(
    inference_api: str | None,
    messages: list[dict[str, str]],
    max_tokens: int,
) -> str:
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
    last_error: Exception | None = None
    for attempt in range(2):
        try:
            request = urllib.request.Request(
                endpoint + "/inference",
                data=payload,
                method="POST",
                headers=headers,
            )
            with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:
                return _message_text(json.loads(response.read().decode("utf-8", "replace")))
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                raise
            last_error = exc
        except (OSError, ValueError, TimeoutError) as exc:
            last_error = exc
        if attempt < 1:
            time.sleep(1.2)
    raise RuntimeError(f"inference failed: {last_error}")


def _message_text(payload: dict[str, Any]) -> str:
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        return ""
    message = choices[0].get("message") if isinstance(choices[0], dict) else None
    if not isinstance(message, dict):
        return ""
    content = message.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(str(part.get("text") or "") for part in content if isinstance(part, dict))
    return ""


def _parse_json_object(text: str) -> dict[str, Any]:
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
                    return parsed if isinstance(parsed, dict) else {}
                except json.JSONDecodeError:
                    return {}
    return {}


def _audit_group(
    inference_api: str | None,
    batch: list[dict[str, Any]],
    basename_index: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    if not batch:
        return []
    try:
        parsed = _parse_json_object(_call_inference(
            inference_api,
            [
                {"role": "system", "content": AUDITOR_PROMPT},
                {"role": "user", "content": _audit_prompt(batch, basename_index)},
            ],
            9000,
        ))
    except urllib.error.HTTPError:
        return []
    except Exception:
        return []
    findings = parsed.get("findings") or parsed.get("vulnerabilities") or []
    if not isinstance(findings, list):
        return []
    return [item for item in findings if isinstance(item, dict)]


def _line_number(text: str, needle: str) -> int | None:
    if not needle:
        return None
    index = text.find(needle)
    return None if index < 0 else text.count("\n", 0, index) + 1


def _normalize_finding(
    raw: dict[str, Any],
    rel_index: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    file_hint = str(raw.get("file") or raw.get("path") or "").strip()
    matched = None
    for rel, record in rel_index.items():
        if file_hint == rel or rel.endswith(file_hint) or file_hint.endswith(rel):
            matched, file_hint = record, rel
            break
    if matched is None:
        return None
    severity = str(raw.get("severity") or "").lower().strip()
    if severity not in {"high", "critical"}:
        return None
    function = str(raw.get("function") or "").strip().strip("`() ")
    if "." in function:
        function = function.split(".")[-1]
    valid_functions = {fn["name"] for fn in matched["functions"]}
    if function and function not in valid_functions:
        function = ""
    contract = str(raw.get("contract") or "").strip().strip("`")
    if not contract and matched["contracts"]:
        contract = str(matched["contracts"][0])
    mechanism = str(raw.get("mechanism") or "").strip()
    impact = str(raw.get("impact") or "").strip()
    description = str(raw.get("description") or "").strip()
    title = str(raw.get("title") or "").strip()
    if len(mechanism) < 20 and len(description) < 100:
        return None
    location = ".".join(part for part in (contract, function) if part)
    if not title:
        title = f"{location or file_hint} - high-impact vulnerability"
    elif location and location.lower() not in title.lower():
        title = f"{location} - {title}"
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
        line = _line_number(str(matched["text"]), f"function {function}")
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


def _unique_findings(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
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
        if len(output) >= MAX_OUTPUT:
            break
    return output


if __name__ == "__main__":
    import sys

    print(json.dumps(agent_main(sys.argv[1] if len(sys.argv) > 1 else None), indent=2))
