"""SN60 / Bitsec miner agent — budget-aware batched breadth.

Design goal: cover more of the codebase per problem than a one-file-per-call
auditor while staying inside the validator's hard per-problem inference budget
(3 successful model calls / 24k output tokens). Instead of spending one call on
one contract, this agent ranks every source file by risk, groups the most
suspicious contracts into a small number of batches, and audits each batch in a
single call — so three calls can reach roughly a dozen contracts rather than
three.

Every finding is emitted in the shape a semantic matcher rewards: an exact file
path, the contract and function it lives in, the concrete exploit mechanism, and
the resulting impact. The agent is self-contained (standard library only), reads
sources from ``project_dir`` (falling back to the Bitsec mount), reaches the
model only through the validator-provided inference proxy, and never raises: a
timeout, a budget ``429``, or a malformed model reply simply yields the findings
gathered so far.
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path

# --- source discovery / ranking --------------------------------------------
SOURCE_SUFFIXES = (".sol", ".vy")
SKIP_DIR_NAMES = {
    "test", "tests", "mock", "mocks", "example", "examples", "script",
    "scripts", "broadcast", "node_modules", "vendor", "vendors", "lib",
    "out", "artifacts", "cache", "interface", "interfaces", "mocks_",
}
RISKY_NAME_TERMS = (
    "vault", "router", "bridge", "proxy", "upgrade", "oracle", "govern",
    "treasury", "manager", "pool", "reward", "staking", "market", "reserve",
    "lend", "borrow", "collateral", "controller", "strategy", "auction",
    "token", "admin", "owner", "escrow", "distributor", "vesting",
)
RISKY_CODE_PATTERNS = (
    r"\bdelegatecall\b", r"\.call\s*\{", r"\bselfdestruct\b", r"\btx\.origin\b",
    r"\bassembly\b", r"\becrecover\b", r"\bpermit\b", r"\bonlyOwner\b",
    r"\bonlyRole\b", r"\bupgradeTo\b", r"\b_mint\b", r"\b_burn\b", r"\bwithdraw\b",
    r"\bredeem\b", r"\bliquidat", r"\bborrow\b", r"\brepay\b", r"\btransferFrom\b",
    r"\bsafeTransfer", r"\bunchecked\b", r"\breentran", r"\bflash", r"\bgetPrice\b",
    r"\blatestAnswer\b", r"\bslot0\b", r"\bnonce\b", r"\bsignature\b",
    r"\btotalSupply\b", r"\bbalanceOf\b", r"\binitialize\b",
)
CONTRACT_DEF = re.compile(
    r"\b(?:contract|library|abstract\s+contract)\s+([A-Za-z_]\w*)"
)
FUNCTION_DEF = re.compile(r"\bfunction\s+([A-Za-z_]\w*)\s*\(")

# --- budgets (per-problem container: 512MB / 0.25 CPU) ----------------------
MAX_FILE_BYTES = 220_000
MAX_CALLS = 3                 # hard cap: matches the proxy per-problem call budget
BATCH_COUNT = 3               # split the top targets across this many calls
FILES_PER_BATCH = 4           # contracts examined per call
MAX_BATCH_CHARS = 15_000      # source budget fed to the model per call
MAX_FINDINGS = 15
MAX_RUNTIME_SECONDS = 210.0
REQUEST_TIMEOUT_SECONDS = 140
CALL_MAX_TOKENS = 6_000       # 3 x 6k stays under the 24k per-problem token budget

SYSTEM_PROMPT = (
    "You are a senior smart-contract security auditor. You report only REAL, "
    "exploitable HIGH or CRITICAL vulnerabilities: logic flaws that let an "
    "attacker steal funds, escalate privilege, brick the protocol, or corrupt "
    "accounting. You ignore gas, style, and speculative issues with no concrete "
    "exploit path, and you are precise about the exact file, contract, and "
    "function a bug lives in."
)


def _resolve_project_root(project_dir: str | None) -> Path | None:
    candidates: list[str] = []
    if project_dir:
        candidates.append(project_dir)
    for env in ("PROJECT_DIR", "PROJECT_PATH", "PROJECT_ROOT", "PROJECT_CODE"):
        val = os.environ.get(env)
        if val:
            candidates.append(val)
    candidates += ["/app/project_code", "/app/project", "/project", "/code", "."]
    for cand in candidates:
        try:
            root = Path(cand).expanduser().resolve()
        except (OSError, RuntimeError):
            continue
        if root.is_dir() and _has_sources(root):
            return root
    return None


def _has_sources(root: Path) -> bool:
    try:
        for path in root.rglob("*"):
            if path.is_file() and path.suffix.lower() in SOURCE_SUFFIXES:
                return True
    except OSError:
        return False
    return False


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _risk_score(path: Path, content: str) -> int:
    score = 0
    name = path.name.lower()
    posix = path.as_posix().lower()
    for term in RISKY_NAME_TERMS:
        if term in name:
            score += 6
        elif term in posix:
            score += 2
    for pattern in RISKY_CODE_PATTERNS:
        hits = len(re.findall(pattern, content, flags=re.IGNORECASE))
        score += min(hits, 4) * 3
    score += min(content.count("function "), 20)
    if "constructor" in content:
        score += 2
    return score


def _discover(project_root: Path) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for path in sorted(project_root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        rel_parts = path.relative_to(project_root).parts[:-1]
        if any(part.lower() in SKIP_DIR_NAMES for part in rel_parts):
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        content = _read_text(path)
        if "function" not in content:
            continue
        contracts = CONTRACT_DEF.findall(content)
        if not contracts:
            continue
        records.append(
            {
                "rel": path.relative_to(project_root).as_posix(),
                "content": content,
                "contracts": contracts,
                "functions": set(FUNCTION_DEF.findall(content)),
                "score": _risk_score(path, content),
            }
        )
    records.sort(key=lambda r: (-int(r["score"]), str(r["rel"])))
    return records


def _make_batches(records: list[dict[str, object]]) -> list[list[dict[str, object]]]:
    """Group the top-ranked files into at most MAX_CALLS batches."""
    top = records[: BATCH_COUNT * FILES_PER_BATCH]
    batches: list[list[dict[str, object]]] = []
    for start in range(0, len(top), FILES_PER_BATCH):
        batch = top[start : start + FILES_PER_BATCH]
        if batch:
            batches.append(batch)
        if len(batches) >= MAX_CALLS:
            break
    return batches


def _build_prompt(batch: list[dict[str, object]]) -> str:
    sections: list[str] = [
        "Audit the following Solidity/Vyper source files for REAL HIGH or "
        "CRITICAL vulnerabilities. Reason about access control, external calls, "
        "reentrancy, accounting/oracle math, and initialization/upgrade paths.",
        "",
        "Return STRICT JSON only (no prose) of this exact shape:",
        '{"findings": [{'
        '"title": "<Contract>.<function> — <specific bug>", '
        '"file": "<exact file path from the headers below>", '
        '"contract": "<ContractName>", '
        '"function": "<function the bug is in>", '
        '"severity": "high|critical", '
        '"mechanism": "<precondition -> attacker action -> effect>", '
        '"impact": "<funds stolen / privilege escalation / DoS / insolvency>", '
        '"description": "<2-4 sentences naming the file, contract and function, '
        'then the mechanism and the impact>"'
        "}]}",
        "",
        "Rules: report only issues with a concrete exploit path; name the real "
        "function each bug lives in; do not invent files or functions absent from "
        'the source below. If nothing is genuinely exploitable, return {"findings": []}.',
    ]
    remaining = MAX_BATCH_CHARS
    for record in batch:
        rel = str(record["rel"])
        contracts = ", ".join(record["contracts"][:6]) or "(unnamed)"
        budget = max(1500, remaining // max(1, len(batch)))
        body = str(record["content"])[:budget]
        remaining -= len(body)
        sections += [
            "",
            f"===== FILE: {rel} =====",
            f"Contracts: {contracts}",
            body,
        ]
    return "\n".join(sections)


def _post_inference(inference_api: str | None, prompt: str) -> tuple[str, int]:
    """Return (content, http_status). status 429 signals the budget is spent."""
    endpoint = (inference_api or os.environ.get("INFERENCE_API") or "").rstrip("/")
    if not endpoint:
        return "", 0
    api_key = os.environ.get("INFERENCE_API_KEY", "").strip()
    body = json.dumps(
        {
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "response_format": {"type": "json_object"},
            "max_tokens": CALL_MAX_TOKENS,
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        endpoint + "/inference",
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "x-inference-api-key": api_key},
    )
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        return _extract_content(payload), 200
    except urllib.error.HTTPError as exc:
        return "", exc.code
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        return "", 0


def _extract_content(payload: dict) -> str:
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
        return "".join(
            part.get("text", "")
            for part in content
            if isinstance(part, dict) and part.get("type") == "text"
        )
    return ""


def _parse_findings(content: str) -> list[dict[str, object]]:
    text = content.strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\n?", "", text)
        text = re.sub(r"\n?```$", "", text).strip()
    obj = None
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        start, depth = text.find("{"), 0
        if start != -1:
            for i in range(start, len(text)):
                depth += 1 if text[i] == "{" else -1 if text[i] == "}" else 0
                if depth == 0:
                    try:
                        obj = json.loads(text[start : i + 1])
                    except json.JSONDecodeError:
                        obj = None
                    break
    if not isinstance(obj, dict):
        return []
    items = obj.get("findings") or obj.get("vulnerabilities") or obj.get("candidates")
    return [it for it in items if isinstance(it, dict)] if isinstance(items, list) else []


def _known(batch: list[dict[str, object]]) -> tuple[set[str], set[str], dict[str, str]]:
    files: set[str] = set()
    functions: set[str] = set()
    default_contract: dict[str, str] = {}
    for record in batch:
        rel = str(record["rel"])
        files.add(rel)
        functions |= set(record["functions"])  # type: ignore[arg-type]
        contracts = record["contracts"]
        if isinstance(contracts, list) and contracts:
            default_contract[rel] = str(contracts[0])
    return files, functions, default_contract


def _normalize(
    raw: dict[str, object],
    files: set[str],
    functions: set[str],
    default_contract: dict[str, str],
) -> dict[str, object] | None:
    severity = str(raw.get("severity") or "").strip().lower()
    if severity not in {"high", "critical"}:
        return None

    file_path = str(raw.get("file") or raw.get("path") or "").strip()
    if file_path not in files:
        # Best-effort: match by basename to one of the batch files.
        base = file_path.rsplit("/", 1)[-1]
        file_path = next((f for f in files if f.endswith(base) and base), "")
    if not file_path:
        file_path = next(iter(files), "")
    if not file_path:
        return None

    contract = str(raw.get("contract") or default_contract.get(file_path, "")).strip()
    function = str(raw.get("function") or "").strip().strip("()")
    if function and functions and function not in functions:
        function = function.split(".")[-1]
        if function not in functions:
            function = ""

    mechanism = str(raw.get("mechanism") or "").strip()
    impact = str(raw.get("impact") or "").strip()
    description = str(raw.get("description") or "").strip()
    title = str(raw.get("title") or "").strip()

    loc = f"{contract}.{function}" if contract and function else (contract or function)
    if not title:
        title = f"{loc} — {severity} severity issue" if loc else "High-severity issue"
    elif loc and loc.lower() not in title.lower():
        title = f"{loc} — {title}"

    if len(description) < 100 or (function and function not in description):
        segs = [f"In `{file_path}`"]
        if contract:
            segs[0] += f", contract `{contract}`"
        if function:
            segs[0] += f", function `{function}()`"
        segs[0] += "."
        if mechanism:
            segs.append(f"Mechanism: {mechanism.rstrip('.')}.")
        if impact:
            segs.append(f"Impact: {impact.rstrip('.')}.")
        rebuilt = " ".join(segs).strip()
        if len(rebuilt) > len(description):
            description = rebuilt
    if len(description) < 80:
        return None

    return {
        "title": title[:200],
        "description": description,
        "severity": severity,
        "file": file_path,
        "function": function,
        "confidence": 0.9 if severity == "critical" else 0.8,
    }


def _dedupe(findings: list[dict[str, object]]) -> list[dict[str, object]]:
    seen: set[tuple[str, str]] = set()
    out: list[dict[str, object]] = []
    ordered = sorted(
        findings,
        key=lambda f: (f["severity"] == "critical", float(f["confidence"])),
        reverse=True,
    )
    for f in ordered:
        key = (
            str(f["file"]).lower(),
            str(f["function"]).lower() or str(f["title"]).lower()[:40],
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def agent_main(
    project_dir: str | None = None,
    inference_api: str | None = None,
) -> dict:
    findings: list[dict[str, object]] = []
    try:
        project_root = _resolve_project_root(project_dir)
        if project_root is None:
            return {"vulnerabilities": findings}

        deadline = time.monotonic() + MAX_RUNTIME_SECONDS
        records = _discover(project_root)
        if not records:
            return {"vulnerabilities": findings}

        collected: list[dict[str, object]] = []
        calls = 0
        for batch in _make_batches(records):
            if calls >= MAX_CALLS or time.monotonic() > deadline:
                break
            prompt = _build_prompt(batch)
            content, status = _post_inference(inference_api, prompt)
            calls += 1
            if status == 429:
                break  # per-problem inference budget exhausted; keep what we have
            if not content:
                continue
            files, functions, default_contract = _known(batch)
            for raw in _parse_findings(content):
                norm = _normalize(raw, files, functions, default_contract)
                if norm is not None:
                    collected.append(norm)

        findings = _dedupe(collected)[:MAX_FINDINGS]
    except Exception:
        # Never crash the sandbox run: a crash scores as invalid for the problem,
        # whereas returning the findings gathered so far is always safe.
        pass
    return {"vulnerabilities": findings}


if __name__ == "__main__":
    import sys

    print(json.dumps(agent_main(sys.argv[1] if len(sys.argv) > 1 else None), indent=2))
