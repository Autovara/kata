from __future__ import annotations

"""SN60 miner: breadth-first smart-contract vulnerability auditor.

General-purpose analysis for unseen Solidity/Vyper codebases. The agent ranks
source files with reusable static heuristics, then spends its three inference
calls on wide deep-audit batches so more distinct files are examined than a
single narrow pass would reach. Findings are shaped into matcher-friendly
records (file, contract, function, mechanism, impact) and filtered to real
high/critical issues only.

No project-specific fingerprints and no canned findings: the same code runs on
every codebase. Self-contained stdlib; the validator inference proxy is the only
network dependency.
"""

import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

SRC_EXTS = (".sol", ".vy")

# Directories that hold tests, mocks, dependencies, or build output rather than
# the audited production sources.
NON_SOURCE_DIRS = frozenset({
    ".git", ".github", "artifacts", "broadcast", "cache", "coverage", "dist",
    "docs", "example", "examples", "interfaces", "lib", "mock", "mocks",
    "node_modules", "out", "script", "scripts", "test", "testing", "tests",
    "vendor", "vendors", "fixtures",
})
NON_SOURCE_UNDER_SRC = frozenset({"test", "tests", "mock", "mocks", "fixtures"})

RE_CONTRACT = re.compile(
    r"^\s*(?:abstract\s+contract|contract|library|interface)\s+([A-Za-z_]\w*)",
    re.MULTILINE,
)
RE_FUNC_SOL = re.compile(
    r"\bfunction\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*([^{};]*)(?:;|\{)",
    re.MULTILINE,
)
RE_FUNC_VY = re.compile(r"^\s*def\s+([A-Za-z_]\w*)\s*\(", re.MULTILINE)
RE_IMPORT = re.compile(r'^\s*import\b[^;]*?["\']([^"\']+)["\']', re.MULTILINE)
RE_STATE = re.compile(
    r"^\s*(?:mapping\s*\([^;]+|[A-Za-z_][\w<>,\[\]. ]+)\s+"
    r"(?:public|private|internal|constant|immutable|override|\s)*"
    r"([A-Za-z_]\w*)\s*(?:=|;)",
    re.MULTILINE,
)
RE_RISK = re.compile(
    r"\b(delegatecall|selfdestruct|tx\.origin|assembly|unchecked|\.call\s*\{|"
    r"onlyOwner|onlyRole|_mint|_burn|initialize|initializer|upgradeTo|"
    r"withdraw|redeem|borrow|repay|liquidat|transferFrom|safeTransfer|"
    r"ecrecover|permit|approve|swap|flash|deposit|claim|rescue|sweep)\b",
    re.IGNORECASE,
)

# Static budgets. The relay funds up to 3 calls, 150k input tokens, and 24k
# output tokens per problem, so input context is cheap relative to output. We
# feed generous source context and keep the requested output modest per call.
MAX_FILES_TRACKED = 90
MAX_FILE_BYTES = 300_000
AUDIT_CHARS = 44_000
RELATED_CHARS = 3_800
BATCH_SIZE = 5
MAX_BATCHES = 3
MAX_REPORT = 20
PER_CALL_FINDINGS = 8
RUN_DEADLINE = 235.0
HTTP_TIMEOUT = 140

RISK_NAME_HINTS = (
    "vault", "pool", "router", "bridge", "proxy", "upgrade", "oracle", "govern",
    "treasury", "manager", "market", "lend", "borrow", "collateral", "controller",
    "strategy", "auction", "token", "admin", "owner", "swap", "stake", "staking",
    "reward", "escrow", "distributor", "farm", "gauge", "minter",
)

SYSTEM_PROMPT = (
    "You are a meticulous smart-contract security auditor. Report only concrete "
    "high or critical severity vulnerabilities that have a realistic exploit path "
    "and material impact (loss of funds, insolvency, theft, permanent freeze, or "
    "unauthorized privilege). Ignore style, gas, missing events, and speculation. "
    "Be thorough: surface every distinct exploitable issue you can justify. "
    "Respond with strict JSON only, no prose."
)

AUDIT_CHECKLIST = (
    "Systematically check each source for: missing or wrong access control on "
    "state-changing or fund-moving functions; unsafe external calls and "
    "reentrancy; arithmetic, rounding, or accounting errors that break invariants; "
    "price/oracle manipulation and unbacked minting; unprotected initialization or "
    "upgrade paths; signature/nonce replay; and any path that lets an attacker "
    "drain, mint, freeze, or seize value."
)


def agent_main(project_dir: str | None = None, inference_api: str | None = None) -> dict:
    started = time.monotonic()
    findings: list[dict[str, Any]] = []
    root = locate_codebase(project_dir)
    if root is None:
        return {"vulnerabilities": findings}

    sources = collect_sources(root)
    if not sources:
        return {"vulnerabilities": findings}

    by_rel = {rec["rel"]: rec for rec in sources}
    by_name = {Path(rec["rel"]).name: rec for rec in sources}

    raw: list[dict[str, Any]] = []
    budget_exhausted = False
    for batch in partition_batches(sources):
        if budget_exhausted or time.monotonic() - started > RUN_DEADLINE:
            break
        batch_raw, budget_exhausted = audit_batch(inference_api, batch, by_name)
        raw.extend(batch_raw)

    for item in raw:
        shaped = shape_finding(item, by_rel)
        if shaped is not None:
            findings.append(shaped)
    return {"vulnerabilities": finalize(findings)}


# --------------------------------------------------------------------------- #
# Codebase discovery and static ranking
# --------------------------------------------------------------------------- #


def locate_codebase(project_dir: str | None) -> Path | None:
    candidates: list[str] = []
    if project_dir:
        candidates.append(project_dir)
    for env in ("PROJECT_DIR", "PROJECT_PATH", "PROJECT_ROOT", "PROJECT_CODE"):
        value = os.environ.get(env)
        if value:
            candidates.append(value)
    candidates.extend(("/app/project_code", "/app/project", "/project", "/code", "."))
    for entry in candidates:
        try:
            root = Path(entry).expanduser().resolve()
        except (OSError, RuntimeError):
            continue
        if root.is_dir() and _contains_sources(root):
            return root
    return None


def _contains_sources(root: Path) -> bool:
    try:
        for path in root.rglob("*"):
            if path.is_file() and path.suffix.lower() in SRC_EXTS:
                return True
    except OSError:
        return False
    return False


def _is_excluded(parent_parts: tuple[str, ...]) -> bool:
    if not parent_parts:
        return False
    lowered = {part.lower() for part in parent_parts}
    under_src = "src" in lowered or "contracts" in lowered
    for part in parent_parts:
        low = part.lower()
        if under_src:
            if low in NON_SOURCE_UNDER_SRC:
                return True
        elif low in NON_SOURCE_DIRS:
            return True
    return False


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _extract_functions(text: str) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for match in RE_FUNC_SOL.finditer(text):
        modifiers = " ".join(match.group(3).split())
        signature = f"{match.group(1)}({match.group(2).strip()}) {modifiers}".strip()
        out.append({"name": match.group(1), "sig": signature})
    for match in RE_FUNC_VY.finditer(text):
        out.append({"name": match.group(1), "sig": match.group(1)})
    return out


def _state_names(text: str) -> list[str]:
    names: list[str] = []
    for name in RE_STATE.findall(text):
        if name not in names and len(name) < 40:
            names.append(name)
    return names[:16]


def _priority(rel: str, text: str) -> int:
    lower_name = rel.lower()
    lower_text = text.lower()
    score = min(lower_text.count("function ") + lower_text.count("\ndef "), 34)
    for hint in RISK_NAME_HINTS:
        if hint in lower_name:
            score += 9
        elif hint in lower_text:
            score += 2
    score += 3 * len(RE_RISK.findall(text))
    if any(tok in lower_text for tok in ("external", "public", "@external", "payable")):
        score += 5
    if ".call" in lower_text and "nonreentrant" not in lower_text:
        score += 4
    return score


def collect_sources(root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in SRC_EXTS:
            continue
        try:
            rel_path = path.relative_to(root)
            if _is_excluded(tuple(rel_path.parts[:-1])):
                continue
            if path.stat().st_size > MAX_FILE_BYTES:
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
            "rel": rel,
            "text": text,
            "contracts": contracts,
            "functions": _extract_functions(text),
            "state": _state_names(text),
            "priority": _priority(rel, text),
        })
    rows.sort(key=lambda r: (-int(r["priority"]), str(r["rel"])))
    return rows[:MAX_FILES_TRACKED]


def partition_batches(sources: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """Split the top-ranked files into up to MAX_BATCHES disjoint audit groups."""
    top = sources[: BATCH_SIZE * MAX_BATCHES]
    return [top[i : i + BATCH_SIZE] for i in range(0, len(top), BATCH_SIZE)]


# --------------------------------------------------------------------------- #
# Inference
# --------------------------------------------------------------------------- #


def _related_context(rec: dict[str, Any], by_name: dict[str, dict[str, Any]]) -> str:
    parts: list[str] = []
    for imported in RE_IMPORT.findall(str(rec["text"])):
        base = imported.rsplit("/", 1)[-1]
        other = by_name.get(base)
        if other and other["rel"] != rec["rel"]:
            parts.append(f"// {other['rel']}\n{str(other['text'])[:RELATED_CHARS]}")
        if len(parts) >= 2:
            break
    return "\n\n".join(parts)


def build_audit_prompt(batch: list[dict[str, Any]], by_name: dict[str, dict[str, Any]]) -> str:
    header = (
        "Audit the smart-contract sources below for high and critical severity "
        "vulnerabilities.\n"
        + AUDIT_CHECKLIST
        + "\nReturn strict JSON only in this exact shape:\n"
        '{"findings":[{"title":"Contract.function - concise bug name",'
        '"file":"exact/path/as/shown","contract":"Contract","function":"functionName",'
        '"line":123,"severity":"high|critical",'
        '"mechanism":"preconditions -> attacker action -> broken invariant",'
        '"impact":"specific fund loss / insolvency / privilege / permanent freeze",'
        '"description":"3-5 precise sentences naming the file, contract, function, the '
        'exact flawed logic, and the resulting impact"}]}\n'
        f"Report up to {PER_CALL_FINDINGS} findings. Include every distinct issue you "
        "can justify, but omit anything not clearly exploitable. Use only files, "
        "contracts, and functions that appear below.\n"
    )
    parts = [header]
    remaining = AUDIT_CHARS - len(header)
    for rec in batch:
        if remaining <= 0:
            break
        block = (
            f"\n\n===== FILE: {rec['rel']} =====\n"
            f"Contracts: {', '.join(rec['contracts'][:8])}\n{rec['text']}\n"
        )
        related = _related_context(rec, by_name)
        if related:
            block += f"\n----- IMPORTED CONTEXT -----\n{related}\n"
        if len(block) > remaining:
            block = block[:remaining] + "\n/* truncated */\n"
        parts.append(block)
        remaining -= len(block)
    return "".join(parts)


def audit_batch(
    inference_api: str | None,
    batch: list[dict[str, Any]],
    by_name: dict[str, dict[str, Any]],
) -> tuple[list[dict[str, Any]], bool]:
    """Run one deep-audit call. Returns (findings, budget_exhausted)."""
    if not batch:
        return [], False
    prompt = build_audit_prompt(batch, by_name)
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": prompt},
    ]
    try:
        content = call_model(inference_api, messages, 9000)
    except BudgetExhausted:
        return [], True
    except Exception:
        return [], False
    payload = parse_json_object(content)
    items = payload.get("findings") or payload.get("vulnerabilities") or []
    if not isinstance(items, list):
        return [], False
    return [x for x in items if isinstance(x, dict)], False


class BudgetExhausted(Exception):
    """Raised when the relay refuses a call because the per-problem budget is spent."""


def call_model(inference_api: str | None, messages: list[dict[str, str]], max_tokens: int) -> str:
    endpoint = (inference_api or os.environ.get("INFERENCE_API") or "").rstrip("/")
    if not endpoint:
        raise RuntimeError("no inference endpoint configured")
    body = json.dumps({
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
            request = urllib.request.Request(
                endpoint + "/inference", data=body, method="POST", headers=headers
            )
            with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:
                decoded = json.loads(response.read().decode("utf-8", "replace"))
            return _message_text(decoded)
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                raise BudgetExhausted() from exc
            last = exc
        except (OSError, ValueError, TimeoutError) as exc:
            last = exc
        if attempt == 0:
            time.sleep(1.5)
    raise RuntimeError(f"inference request failed: {last}")


def _message_text(payload: dict[str, Any]) -> str:
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        return ""
    first = choices[0]
    message = first.get("message") if isinstance(first, dict) else None
    if not isinstance(message, dict):
        return ""
    content = message.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(str(p.get("text") or "") for p in content if isinstance(p, dict))
    return ""


def parse_json_object(text: str) -> dict[str, Any]:
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
    escaped = False
    for idx in range(start, len(stripped)):
        ch = stripped[idx]
        if in_str:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
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


# --------------------------------------------------------------------------- #
# Finding normalization
# --------------------------------------------------------------------------- #


def _match_file(file_value: str, by_rel: dict[str, dict[str, Any]]) -> tuple[str, dict[str, Any]] | None:
    if not file_value:
        return None
    for rel, rec in by_rel.items():
        if file_value == rel or rel.endswith(file_value) or file_value.endswith(rel):
            return rel, rec
    tail = file_value.rsplit("/", 1)[-1]
    for rel, rec in by_rel.items():
        if rel.rsplit("/", 1)[-1] == tail:
            return rel, rec
    return None


def _line_of(text: str, function: str) -> int | None:
    if not function:
        return None
    idx = text.find(f"function {function}")
    if idx < 0:
        idx = text.find(f"def {function}")
    return None if idx < 0 else text.count("\n", 0, idx) + 1


def shape_finding(raw: dict[str, Any], by_rel: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    file_value = str(raw.get("file") or raw.get("path") or "").strip()
    matched = _match_file(file_value, by_rel)
    if matched is None:
        return None
    rel, rec = matched

    severity = str(raw.get("severity") or "").lower().strip()
    if severity not in {"high", "critical"}:
        return None

    function = str(raw.get("function") or "").strip().strip("`() ")
    if "." in function:
        function = function.split(".")[-1]
    valid_functions = {f["name"] for f in rec["functions"]}
    if function and function not in valid_functions:
        function = ""

    contract = str(raw.get("contract") or "").strip().strip("`")
    if not contract and rec["contracts"]:
        contract = str(rec["contracts"][0])

    mechanism = str(raw.get("mechanism") or "").strip()
    impact = str(raw.get("impact") or "").strip()
    description = str(raw.get("description") or "").strip()
    if len(mechanism) < 20 and len(description) < 100:
        return None

    locus = ".".join(x for x in (contract, function) if x)
    title = str(raw.get("title") or "").strip()
    if not title:
        title = f"{locus or rel} - high-impact vulnerability"
    elif locus and locus.lower() not in title.lower():
        title = f"{locus} - {title}"

    where = f"In `{rel}`"
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
    if not isinstance(line, int):
        line = _line_of(str(rec["text"]), function)

    return {
        "title": title[:220],
        "description": description[:3000],
        "severity": severity,
        "file": rel,
        "function": function,
        "line": line if isinstance(line, int) else None,
        "type": str(raw.get("type") or "logic"),
        "confidence": 0.9 if severity == "critical" else 0.85,
    }


def finalize(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ordered = sorted(
        items,
        key=lambda f: (
            f.get("severity") == "critical",
            float(f.get("confidence") or 0.0),
            len(str(f.get("description") or "")),
        ),
        reverse=True,
    )
    seen: set[tuple[str, str, str]] = set()
    out: list[dict[str, Any]] = []
    for item in ordered:
        key = (
            str(item.get("file") or "").lower(),
            str(item.get("function") or "").lower(),
            str(item.get("title") or "").lower()[:90],
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
        if len(out) >= MAX_REPORT:
            break
    return out


if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else None
    print(json.dumps(agent_main(target), indent=2))
