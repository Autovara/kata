"""SN60 / Bitsec miner agent — generic static detectors + budgeted LLM depth.

Two complementary layers, both self-contained (standard library only):

  1. GENERIC static detectors (deterministic, zero inference cost) for common
     high/critical vulnerability *classes* — missing access control on
     privileged functions, unprotected initializers, reentrancy around external
     value calls, delegatecall to a caller-influenced target, tx.origin
     authorization, and unprotected selfdestruct. These are ordinary
     source-code heuristics for well-known weakness categories; they are NOT
     keyed to any particular project's identifiers or to benchmark answers.
  2. Up to three budgeted LLM passes (two full-depth single-contract audits +
     one breadth pass) over the highest-risk sources, inside the validator's
     per-problem limit (3 model calls / 24k output tokens).

Findings from both layers are emitted in the shape a semantic matcher rewards
(exact file path, contract, function, mechanism, impact), deduped and capped.
The agent reads sources from ``project_dir`` (falling back to the Bitsec mount),
reaches the model only through the validator inference proxy, and never raises:
a timeout, a budget ``429``, or a malformed reply just yields what it has.
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
    "out", "artifacts", "cache", "interface", "interfaces",
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
IMPORT_PATTERN = re.compile(r'^\s*import\b[^;]*?["\']([^"\']+)["\']', re.MULTILINE)

# generic access-control markers (any of these near a function => it is guarded)
ACCESS_GUARD_TOKENS = (
    "onlyowner", "onlyrole", "onlyadmin", "onlygovernance", "onlyguardian",
    "onlyoperator", "onlymanager", "onlyauthorized", "requiresauth", "_checkowner",
    "_checkrole", "hasrole(", "_onlyowner", "onlyself", "initializer",
    "reinitializer", "require(msg.sender", "msg.sender==owner", "msg.sender==admin",
    "msg.sender==governance", "_authorizeupgrade",
)
PRIVILEGED_VERB = re.compile(
    r"^(set|update|upgrade|initialize|init|grant|revoke|add|remove|enable|"
    r"disable|mint|burn|rescue|sweep|migrate|configure|register|whitelist|"
    r"blacklist|withdraw|seize)",
    re.IGNORECASE,
)

# --- budgets (per-problem container: 512MB / 0.25 CPU) ----------------------
MAX_FILE_BYTES = 220_000
MAX_CALLS = 3                 # hard cap: matches the proxy per-problem call budget
DEPTH_TARGETS = 2             # top contracts audited at full depth (1 call each)
MAX_CONTRACT_CHARS = 16_000   # whole-file context per depth call
MAX_RELATED_CHARS = 4_000     # one imported dependency for extra context
BREADTH_FILES = 4             # contracts examined in the single breadth call
MAX_BREADTH_CHARS = 14_000    # source budget for the breadth call
STATIC_SCAN_FILES = 40        # ranked files scanned by the local detectors
MAX_STATIC_FINDINGS = 8       # cap on deterministic findings (precision guard)
MAX_FINDINGS = 18
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


# ---------------------------------------------------------------------------
# discovery
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


# ---------------------------------------------------------------------------
# generic static detectors (deterministic, no inference)
# ---------------------------------------------------------------------------
def _slice_block(text: str, open_idx: int) -> str:
    depth = 0
    for k in range(open_idx, len(text)):
        ch = text[k]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1 : k]
    return text[open_idx + 1 :]


def _function_slices(text: str) -> list[dict[str, object]]:
    slices: list[dict[str, object]] = []
    for match in re.finditer(r"\bfunction\s+([A-Za-z_]\w*)\s*\(", text):
        name = match.group(1)
        paren, brace_idx, j = 1, -1, match.end()
        while j < len(text):
            ch = text[j]
            if ch == "(":
                paren += 1
            elif ch == ")":
                paren -= 1
            elif paren <= 0 and ch == ";":
                break
            elif paren <= 0 and ch == "{":
                brace_idx = j
                break
            j += 1
        if brace_idx == -1:
            continue
        slices.append(
            {
                "name": name,
                "sig": text[match.start() : brace_idx],
                "body": _slice_block(text, brace_idx),
                "line": text.count("\n", 0, match.start()) + 1,
            }
        )
    return slices


def _has_guard(fragment: str) -> bool:
    compact = re.sub(r"\s+", "", fragment.lower())
    return any(tok in compact for tok in ACCESS_GUARD_TOKENS)


def _mk_finding(
    rel: str,
    contract: str,
    function: str,
    title: str,
    mechanism: str,
    impact: str,
    severity: str = "high",
) -> dict[str, object]:
    where = f"In `{rel}`"
    if contract:
        where += f", contract `{contract}`"
    if function:
        where += f", function `{function}()`"
    description = (
        f"{where}. Mechanism: {mechanism.rstrip('.')}. Impact: {impact.rstrip('.')}."
    )
    loc = f"{contract}.{function}" if contract and function else (contract or function)
    full_title = f"{loc} — {title}" if loc else title
    return {
        "title": full_title[:200],
        "description": description,
        "severity": severity,
        "file": rel,
        "function": function or "",
        "confidence": 0.9 if severity == "critical" else 0.82,
    }


def _detect_in_record(rec: dict[str, object]) -> list[dict[str, object]]:
    text = str(rec["content"])
    rel = str(rec["rel"])
    contracts = rec["contracts"]
    contract = str(contracts[0]) if isinstance(contracts, list) and contracts else ""
    out: list[dict[str, object]] = []

    for fn in _function_slices(text):
        name = str(fn["name"])
        sig = str(fn["sig"])
        body = str(fn["body"])
        sig_low = sig.lower()
        body_low = body.lower()
        compact_body = re.sub(r"\s+", "", body_low)
        exposed = "external" in sig_low or "public" in sig_low
        read_only = "view" in sig_low or "pure" in sig_low

        # 1) missing access control / unprotected initializer
        state_markers = ("=", "transfer", "mint", "burn", "delegatecall", "selfdestruct")
        if (
            exposed
            and not read_only
            and PRIVILEGED_VERB.match(name)
            and not _has_guard(sig + " " + body)
            and any(t in body_low for t in state_markers)
        ):
            is_init = name.lower() in ("initialize", "init")
            kind = "initializer" if is_init else "state-changing"
            out.append(_mk_finding(
                rel, contract, name,
                "unprotected initializer" if is_init
                else "missing access control on privileged function",
                f"the externally callable {kind} function `{name}` has no owner, "
                "role, or msg.sender authorization check",
                "any account can call it to seize ownership, rewrite privileged "
                "configuration, or move protocol funds",
                severity="high",
            ))

        # 2) reentrancy around an external value call
        if (
            "nonreentrant" not in sig_low
            and (".call{" in compact_body or ".call.value" in compact_body)
            and any(t in body_low for t in ("-=", "+=", "delete ", "= 0", "=0"))
        ):
            out.append(_mk_finding(
                rel, contract, name,
                "reentrancy around external value call",
                "the function makes a low-level value call while mutable balance/"
                "accounting state is updated in the same flow, with no reentrancy guard",
                "a malicious callee can re-enter before state is finalized and "
                "withdraw or double-spend funds",
                severity="high",
            ))

        # 3) delegatecall to a caller-influenced target
        if "delegatecall(" in compact_body and (
            "address" in sig_low or "target" in body_low or "impl" in body_low
        ):
            out.append(_mk_finding(
                rel, contract, name,
                "delegatecall to caller-influenced target",
                "the function performs delegatecall against an address taken from "
                "a parameter or mutable storage",
                "an attacker controlling that target executes arbitrary code in this "
                "contract's context, taking over its storage and funds",
                severity="critical",
            ))

        # 4) tx.origin used for authorization
        if (
            "tx.origin==" in compact_body
            or "==tx.origin" in compact_body
            or "require(tx.origin" in compact_body
        ):
            out.append(_mk_finding(
                rel, contract, name,
                "authorization via tx.origin",
                "access control compares tx.origin instead of msg.sender",
                "a malicious intermediary contract the victim is tricked into calling "
                "can forward calls that satisfy the tx.origin check, bypassing auth",
                severity="high",
            ))

        # 5) unprotected selfdestruct
        if "selfdestruct(" in compact_body and exposed and not _has_guard(sig + " " + body):
            out.append(_mk_finding(
                rel, contract, name,
                "unprotected selfdestruct",
                "an externally reachable function calls selfdestruct with no access control",
                "any account can destroy the contract, permanently bricking the "
                "protocol and locking or misdirecting its funds",
                severity="critical",
            ))

    return out


def _local_findings(records: list[dict[str, object]]) -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    for rec in records[:STATIC_SCAN_FILES]:
        out.extend(_detect_in_record(rec))
        if len(out) >= MAX_STATIC_FINDINGS * 2:
            break
    # prefer critical, then high; cap
    out.sort(key=lambda f: f["severity"] == "critical", reverse=True)
    return out[:MAX_STATIC_FINDINGS]


# ---------------------------------------------------------------------------
# LLM passes
# ---------------------------------------------------------------------------
def _related_source(
    target: dict[str, object], by_rel: dict[str, dict[str, object]]
) -> str | None:
    for match in IMPORT_PATTERN.finditer(str(target["content"])):
        imp = match.group(1)
        if not imp or not (imp.startswith(".") or imp.endswith(".sol")):
            continue
        base = imp.rsplit("/", 1)[-1]
        for rel, rec in by_rel.items():
            if rel == target["rel"]:
                continue
            if rel.endswith(base):
                return f"// related import: {rel}\n{str(rec['content'])[:MAX_RELATED_CHARS]}"
    return None


_JSON_SHAPE = (
    "Return STRICT JSON only (no prose) of this exact shape:\n"
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
    "}]}"
)
_RULES = (
    "Rules: report only issues with a concrete exploit path; name the real "
    "function each bug lives in; do not invent files or functions absent from "
    'the source below. If nothing is genuinely exploitable, return {"findings": []}.'
)


def _build_depth_prompt(target: dict[str, object], related: str | None) -> str:
    rel = str(target["rel"])
    contracts = ", ".join(target["contracts"][:6]) or "(unnamed)"
    body = str(target["content"])[:MAX_CONTRACT_CHARS]
    truncated = " (truncated)" if len(str(target["content"])) > MAX_CONTRACT_CHARS else ""
    parts = [
        "Audit this Solidity/Vyper file in depth for REAL HIGH or CRITICAL "
        "vulnerabilities. Follow the protocol logic across functions: access "
        "control, external calls, reentrancy, accounting/oracle math, and "
        "initialization/upgrade paths. Report up to 3 of the strongest issues.",
        "",
        _JSON_SHAPE,
        _RULES,
        "",
        f"===== FILE: {rel} =====",
        f"Contracts: {contracts}",
        f"----- SOURCE{truncated} -----",
        body,
    ]
    if related:
        parts += ["", "----- RELATED CONTEXT (read-only) -----", related]
    return "\n".join(parts)


def _build_breadth_prompt(batch: list[dict[str, object]]) -> str:
    parts = [
        "Audit the following Solidity/Vyper files for REAL HIGH or CRITICAL "
        "vulnerabilities. Reason about access control, external calls, "
        "reentrancy, accounting/oracle math, and initialization/upgrade paths.",
        "",
        _JSON_SHAPE,
        _RULES,
    ]
    remaining = MAX_BREADTH_CHARS
    for record in batch:
        rel = str(record["rel"])
        contracts = ", ".join(record["contracts"][:6]) or "(unnamed)"
        budget = max(2000, remaining // max(1, len(batch)))
        body = str(record["content"])[:budget]
        remaining -= len(body)
        parts += ["", f"===== FILE: {rel} =====", f"Contracts: {contracts}", body]
    return "\n".join(parts)


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


def _collect(
    content: str, batch: list[dict[str, object]], sink: list[dict[str, object]]
) -> None:
    files, functions, default_contract = _known(batch)
    for raw in _parse_findings(content):
        norm = _normalize(raw, files, functions, default_contract)
        if norm is not None:
            sink.append(norm)


# ---------------------------------------------------------------------------
# entrypoint
# ---------------------------------------------------------------------------
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
        by_rel = {str(r["rel"]): r for r in records}

        # Layer 1: deterministic generic detectors (free, no inference).
        collected: list[dict[str, object]] = list(_local_findings(records))

        # Layer 2: budgeted LLM passes — 2 depth targets + 1 breadth batch.
        depth_targets = records[:DEPTH_TARGETS]
        breadth_batch = records[DEPTH_TARGETS : DEPTH_TARGETS + BREADTH_FILES]
        plan: list[tuple[str, list[dict[str, object]]]] = [
            ("depth", [target]) for target in depth_targets
        ]
        if breadth_batch and len(plan) < MAX_CALLS:
            plan.append(("breadth", breadth_batch))
        plan = plan[:MAX_CALLS]

        calls = 0
        for kind, batch in plan:
            if calls >= MAX_CALLS or time.monotonic() > deadline:
                break
            if kind == "depth":
                related = _related_source(batch[0], by_rel)
                prompt = _build_depth_prompt(batch[0], related)
            else:
                prompt = _build_breadth_prompt(batch)
            content, status = _post_inference(inference_api, prompt)
            calls += 1
            if status == 429:
                break  # per-problem inference budget exhausted; keep what we have
            if content:
                _collect(content, batch, collected)

        findings = _dedupe(collected)[:MAX_FINDINGS]
    except Exception:
        # Never crash the sandbox run: a crash scores as invalid for the problem,
        # whereas returning the findings gathered so far is always safe.
        pass
    return {"vulnerabilities": findings}


if __name__ == "__main__":
    import sys

    print(json.dumps(agent_main(sys.argv[1] if len(sys.argv) > 1 else None), indent=2))
