from __future__ import annotations

"""SN60 / Bitsec miner agent — budget-aware batched audit.

Tuned to the validator's per-problem inference budget: at most 3 successful model
calls and 24,000 output tokens per problem (the 4th call, or the call past the
token budget, returns HTTP 429). The budget caps CALLS and OUTPUT tokens — not
INPUT — so the way to cover a whole codebase in 3 calls is to pack several
contracts into each call's input and ask for every high/critical issue across
them.

Why this should out-detect the king under this budget: the pinned model is weak
(the reigning king confirms ~1 real high/critical issue per round, often zero, and
most rounds end 0-0), so the winnable rounds are the ones where this agent lands a
genuine true positive the king does not. A one-contract-per-call agent (like the
king) can only reach ~3 contracts before the call budget is spent, so a real bug in
any other contract is unreachable for it. This agent instead:

  * BATCHES the ranked contracts — it packs several of the most-suspicious contracts
    into each of its (up to) 3 calls, so it audits ~12 contracts within the same
    budget and can find a bug outside the king's narrow window (a clean 1-0 win).
    Batching related contracts together also gives the model cross-contract context.
  * GUIDES the weak model with an explicit checklist of high/critical vulnerability
    classes, and keeps the source per contract large enough to reason over.
  * STAYS within budget by design — it makes at most 3 calls, stops the moment the
    proxy signals the budget is spent (429), and never crashes (a crash scores as
    an invalid run).
  * EMITS a small, confidence-ranked, matcher-shaped set (a correct finding scores a
    true positive anywhere in the set, so it never drops its best shot, and it never
    floods — noise cannot manufacture a true positive and only dilutes precision).

Self-contained (stdlib only). Reads source from ``project_dir`` (defaults to the
Bitsec mount ``/app/project_code``) and reaches the model only through the
validator-provided inference proxy.
"""

import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path

# --- discovery / ranking ----------------------------------------------------
SOURCE_SUFFIXES = (".sol", ".vy")
EXCLUDED_DIR_NAMES = {
    "test", "tests", "mock", "mocks", "example", "examples", "script",
    "scripts", "broadcast", "node_modules", "vendor", "vendors", "lib", "libs",
    "out", "artifacts", "cache", "coverage", "interfaces", "interface",
    "mocking", "fixtures", "fixture",
}
SUSPICIOUS_NAME_TERMS = (
    "vault", "router", "bridge", "proxy", "upgrade", "oracle", "govern",
    "treasury", "manager", "pool", "reward", "staking", "stake", "market",
    "reserve", "lend", "borrow", "collateral", "controller", "strategy",
    "auction", "token", "admin", "owner", "escrow", "distributor", "vesting",
    "farm", "gauge", "minter", "swap", "pair", "factory", "comptroller",
)
SUSPICIOUS_CONTENT_PATTERNS = (
    r"\bdelegatecall\b", r"\.call\s*\{", r"\bcall\.value\b", r"\bselfdestruct\b",
    r"\btx\.origin\b", r"\bassembly\b", r"\becrecover\b", r"\bpermit\b",
    r"\bonlyOwner\b", r"\bonlyRole\b", r"\bupgradeTo\b", r"\b_mint\b", r"\b_burn\b",
    r"\bwithdraw\b", r"\bredeem\b", r"\bliquidat", r"\bborrow\b", r"\brepay\b",
    r"\btransferFrom\b", r"\bsafeTransfer", r"\bunchecked\b", r"\breentran",
    r"\bflash", r"\bgetPrice\b", r"\blatestAnswer\b", r"\bslot0\b", r"\bnonce\b",
    r"\bsignature\b", r"\btotalSupply\b", r"\bbalanceOf\b", r"\binitialize\b",
    r"\bapprove\b", r"\bpriceOf\b", r"\bgetReserves\b", r"\bmsg\.value\b",
)
CONTRACT_NAME_PATTERN = re.compile(
    r"\b(?:contract|library|abstract\s+contract)\s+([A-Za-z_][A-Za-z0-9_]*)"
)
FUNCTION_DEF_PATTERN = re.compile(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")

# --- budgets (validator: 3 calls / 24k output tokens per problem) -----------
MAX_FILE_BYTES = 220_000
TOP_TARGETS = 12               # ranked contracts we try to cover (across the batches)
MAX_BATCHES = 3                # == the validator's per-problem call budget
CONTRACTS_PER_BATCH = 4        # contracts packed into one call (coverage within budget)
PER_CONTRACT_CHARS = 5_000     # source per contract in a batch (enough to reason over)
MAX_CANDIDATES_PER_CALL = 5    # findings the model may surface per batched call
MAX_EMIT = 3                   # king-sized final set (king realizes ~1.8/problem)
CONFIDENCE_FLOOR = 0.30        # drop only explicit throwaways; never the best shot
MIN_DESCRIPTION_CHARS = 80     # match the king + the screener floor
GLOBAL_DEADLINE_SECONDS = 1400.0
REQUEST_TIMEOUT_SECONDS = 150
MAX_RETRIES = 2                # transient only; failed calls do NOT cost the budget

SYSTEM_PROMPT = (
    "You are a world-class smart-contract security auditor competing to find REAL, "
    "exploitable HIGH or CRITICAL vulnerabilities across a set of contracts. You only "
    "report an issue when you can name the exact file and function, the concrete "
    "on-chain exploit path, and the material impact. You never report gas, style, "
    "missing events, informational notes, or speculative issues — a wrong or vague "
    "finding is worse than no finding. Be concise."
)

VULN_CHECKLIST = (
    "- Reentrancy: state updated after an external call / call{value}; cross-function "
    "or read-only reentrancy.\n"
    "- Access control: privileged or state-changing function missing the owner/role "
    "check; wrong modifier; public setter for critical config (oracle, fees, roles).\n"
    "- Price/oracle manipulation: spot price from an AMM reserve/slot0 used without "
    "TWAP; stale/unchecked oracle answer; manipulable getPrice feeding value math.\n"
    "- Accounting/share math: first-depositor or share-inflation attack; rounding "
    "that favors the attacker; mint/burn or totalSupply math that breaks solvency.\n"
    "- Unchecked external call: ignored low-level call/transfer return; unsafe ERC20 "
    "assumptions.\n"
    "- delegatecall / upgradeable storage collision; uninitialized or re-initializable "
    "proxy; unprotected initialize().\n"
    "- Signature/auth: missing nonce or replay protection; ecrecover(0) / malleable "
    "or unbound signatures; permit misuse.\n"
    "- Unsafe cast / over-underflow in unchecked blocks; incorrect decimals.\n"
    "- Fund custody/withdrawal: anyone can withdraw others' funds; wrong accounting "
    "lets balance exceed deposits; forced-send / self-destruct assumptions.\n"
    "- Flash-loan-amplified manipulation of any of the above."
)


class _BudgetExhausted(Exception):
    """Raised when the proxy refuses further inference for this problem (HTTP 429)."""


# ---------------------------------------------------------------------------
# source discovery + ranking
# ---------------------------------------------------------------------------
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


def _score_source(path: Path, content: str) -> int:
    score = 0
    name = path.name.lower()
    posix = path.as_posix().lower()
    for term in SUSPICIOUS_NAME_TERMS:
        if term in name:
            score += 6
        elif term in posix:
            score += 2
    for pattern in SUSPICIOUS_CONTENT_PATTERNS:
        hits = len(re.findall(pattern, content, flags=re.IGNORECASE))
        score += min(hits, 4) * 3
    score += min(content.count("function "), 24)
    score += min(content.count("external"), 8)
    score += min(content.count("public"), 8)
    if "constructor" in content:
        score += 2
    return score


def _discover(project_root: Path) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for path in sorted(project_root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        parts = path.relative_to(project_root).parts[:-1]
        if any(part.lower() in EXCLUDED_DIR_NAMES for part in parts):
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        content = _read_text(path)
        if "function" not in content:
            continue
        contracts = CONTRACT_NAME_PATTERN.findall(content)
        if not contracts:
            continue
        records.append(
            {
                "path": path,
                "rel": path.relative_to(project_root).as_posix(),
                "content": content,
                "contracts": contracts,
                "score": _score_source(path, content),
            }
        )
    records.sort(key=lambda r: (-int(r["score"]), str(r["rel"])))
    return records


def _batches(records: list[dict[str, object]]) -> list[list[dict[str, object]]]:
    """Partition the top-ranked contracts into up to MAX_BATCHES batches (contiguous
    by rank, so the most-suspicious contracts land in the first call — the one most
    likely to run before the token budget bites)."""
    ranked = records[: min(TOP_TARGETS, MAX_BATCHES * CONTRACTS_PER_BATCH)]
    return [
        ranked[i : i + CONTRACTS_PER_BATCH]
        for i in range(0, len(ranked), CONTRACTS_PER_BATCH)
    ][:MAX_BATCHES]


# ---------------------------------------------------------------------------
# inference
# ---------------------------------------------------------------------------
def _post_inference(
    inference_api: str | None,
    messages: list[dict[str, str]],
    *,
    deadline: float,
) -> str:
    endpoint = (inference_api or os.environ.get("INFERENCE_API") or "").rstrip("/")
    if not endpoint:
        raise ValueError("inference endpoint is not configured.")
    api_key = os.environ.get("INFERENCE_API_KEY", "").strip()
    body = json.dumps(
        {
            "messages": messages,
            "response_format": {"type": "json_object"},
            "max_tokens": 8000,
        }
    ).encode("utf-8")
    headers = {"Content-Type": "application/json", "x-inference-api-key": api_key}
    last: Exception | None = None
    for attempt in range(MAX_RETRIES + 1):
        remaining = deadline - time.monotonic()
        if remaining <= 5:
            break
        timeout = min(REQUEST_TIMEOUT_SECONDS, max(10.0, remaining - 3))
        try:
            request = urllib.request.Request(
                endpoint + "/inference", data=body, method="POST", headers=headers
            )
            with urllib.request.urlopen(request, timeout=timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
            return _extract_content(payload)
        except urllib.error.HTTPError as exc:
            # 429 == the per-problem budget is spent; retrying will not recover, so
            # signal the caller to stop making calls and finalize.
            if exc.code == 429:
                raise _BudgetExhausted() from exc
            last = exc
        except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
            last = exc
        # transient failure: a failed call does not count against the budget, so retry
        if attempt < MAX_RETRIES and (deadline - time.monotonic()) > 20:
            time.sleep(2)
    raise RuntimeError(f"inference failed: {last}")


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


# ---------------------------------------------------------------------------
# prompt (one batch of contracts) + matcher-shaped normalization
# ---------------------------------------------------------------------------
def _build_batch_prompt(batch: list[dict[str, object]]) -> str:
    parts = [
        "Audit the following Solidity/Vyper contracts for REAL, exploitable HIGH or "
        "CRITICAL vulnerabilities. They are from one codebase and may interact.\n",
        "Check specifically for these high/critical classes; reason through protocol "
        "logic, access control, external calls, and value/accounting math:",
        VULN_CHECKLIST,
        "\nReport ONLY issues with a concrete on-chain exploit path and material "
        "impact, and set `file` to the EXACT path shown for the contract the bug is "
        "in. If nothing is genuinely exploitable, return an empty list — do not "
        "invent or pad. Be concise.\n",
        "Return STRICT JSON, no prose, of this exact shape:",
        '{"findings": [{'
        '"title": "<Contract>.<function> — <specific bug>", '
        '"file": "<exact file path from below>", '
        '"contract": "<ContractName>", '
        '"function": "<functionName the bug is in>", '
        '"line": <int or null>, '
        '"severity": "high|critical", '
        '"confidence": <0.0-1.0 how sure you are it is a REAL exploitable bug>, '
        '"mechanism": "<precondition -> attacker action -> effect>", '
        '"impact": "<funds stolen / privilege escalation / insolvency / DoS>", '
        '"description": "<2-4 sentences naming file, contract, function, then mechanism and impact>"'
        "}]}",
        f"Report at most {MAX_CANDIDATES_PER_CALL} findings total across all the files "
        "below, strongest first, each naming the real function it lives in. Never "
        "invent functions or files not shown.\n",
    ]
    for record in batch:
        rel = record["rel"]
        contracts = ", ".join(record["contracts"][:6]) or "(unnamed)"
        source = str(record["content"])[:PER_CONTRACT_CHARS]
        truncated = " (truncated)" if len(str(record["content"])) > PER_CONTRACT_CHARS else ""
        parts += [
            f"\n===== FILE: {rel} =====",
            f"Contracts: {contracts}{truncated}",
            source,
        ]
    return "\n".join(parts)


def _valid_functions(content: str) -> set[str]:
    return set(FUNCTION_DEF_PATTERN.findall(content))


def _confidence(raw: dict[str, object]) -> float:
    try:
        value = float(raw.get("confidence"))
    except (TypeError, ValueError):
        value = 0.6
    return max(0.0, min(1.0, value))


def _normalize(
    raw: dict[str, object],
    batch_by_rel: dict[str, dict[str, object]],
    default_record: dict[str, object],
    valid_fns_for: dict[str, set[str]],
) -> dict[str, object] | None:
    severity = str(raw.get("severity") or "").strip().lower()
    if severity not in {"high", "critical"}:
        return None
    # Attribute the finding to the file it names (findings span a batch of files).
    file_path = str(raw.get("file") or "").strip()
    record = batch_by_rel.get(file_path)
    if record is None and file_path:
        base = file_path.rsplit("/", 1)[-1]
        for rel, rec in batch_by_rel.items():
            if rel.endswith(base):
                record = rec
                file_path = rel
                break
    if record is None:
        record = default_record
        file_path = file_path or str(record["rel"])
    valid_fns = valid_fns_for.setdefault(
        str(record["rel"]), _valid_functions(str(record["content"]))
    )

    contract = str(
        raw.get("contract") or (record["contracts"][0] if record["contracts"] else "")
    ).strip()
    function = str(raw.get("function") or "").strip().strip("()")
    if function and valid_fns and function not in valid_fns:
        function = function.split(".")[-1]
        if function not in valid_fns:
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

    if len(description) < MIN_DESCRIPTION_CHARS or (function and function not in description):
        segs = []
        where = f"In `{file_path}`"
        if contract:
            where += f", contract `{contract}`"
        if function:
            where += f", function `{function}()`"
        segs.append(where + ".")
        if mechanism:
            segs.append(f"Mechanism: {mechanism.rstrip('.')}.")
        if impact:
            segs.append(f"Impact: {impact.rstrip('.')}.")
        rebuilt = " ".join(segs).strip()
        description = rebuilt if len(rebuilt) > len(description) else description
    if len(description) < MIN_DESCRIPTION_CHARS:
        return None

    return {
        "title": title[:200],
        "description": description,
        "severity": severity,
        "file": file_path,
        "function": function,
        "line": raw.get("line") if isinstance(raw.get("line"), int) else None,
        "type": str(raw.get("type") or raw.get("vulnerability_type") or "logic"),
        "confidence": _confidence(raw),
    }


def _bug_token(finding: dict[str, object]) -> str:
    title = str(finding.get("title") or "")
    suffix = title.split("—", 1)[-1] if "—" in title else title
    return " ".join(re.findall(r"[a-z0-9]+", suffix.lower())[:6])


def _select(candidates: list[dict[str, object]]) -> list[dict[str, object]]:
    """Dedupe, then emit the few strongest by the model's own confidence. A correct
    finding scores a true positive anywhere in the set, so the single best candidate
    is always kept; the floor only removes explicit throwaways."""
    best: dict[tuple[str, str, str], dict[str, object]] = {}
    for f in candidates:
        function = str(f["function"]).lower()
        discriminator = _bug_token(f) if function else str(f["title"]).lower()[:48]
        key = (str(f["file"]).lower(), function, discriminator)
        current = best.get(key)
        if current is None or float(f["confidence"]) > float(current["confidence"]):
            best[key] = f
    ranked = sorted(
        best.values(),
        key=lambda f: (float(f["confidence"]), f["severity"] == "critical"),
        reverse=True,
    )
    kept = [f for f in ranked if float(f["confidence"]) >= CONFIDENCE_FLOOR][:MAX_EMIT]
    if not kept and ranked:
        kept = [ranked[0]]
    return kept


# ---------------------------------------------------------------------------
# entrypoint
# ---------------------------------------------------------------------------
def agent_main(
    project_dir: str | None = None,
    inference_api: str | None = None,
) -> dict:
    findings: list[dict[str, object]] = []
    project_root = _resolve_project_root(project_dir)
    if project_root is None:
        return {"vulnerabilities": findings}

    deadline = time.monotonic() + GLOBAL_DEADLINE_SECONDS
    records = _discover(project_root)
    if not records:
        return {"vulnerabilities": findings}

    valid_fns_for: dict[str, set[str]] = {}
    candidates: list[dict[str, object]] = []

    for batch in _batches(records):
        if time.monotonic() > deadline:
            break
        batch_by_rel = {str(r["rel"]): r for r in batch}
        prompt = _build_batch_prompt(batch)
        try:
            content = _post_inference(
                inference_api,
                [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                deadline=deadline,
            )
        except _BudgetExhausted:
            break  # per-problem budget spent — finalize with what we have
        except (RuntimeError, ValueError):
            continue
        for raw in _parse_findings(content):
            norm = _normalize(raw, batch_by_rel, batch[0], valid_fns_for)
            if norm is not None:
                candidates.append(norm)

    findings = _select(candidates)
    return {"vulnerabilities": findings}


if __name__ == "__main__":  # local smoke check only (no network)
    import sys

    print(json.dumps(agent_main(sys.argv[1] if len(sys.argv) > 1 else None), indent=2))
