from __future__ import annotations

"""SN60 / Bitsec miner agent — depth-first, self-critiquing auditor.

Why this design
---------------
The pinned semantic scorer credits a true positive only when a finding names the
right *file*, *function*, *core mechanism*, and *impact* of a curated HIGH/CRITICAL
issue. Detection score (``true_positives / total_expected``) is the primary
promotion signal, and its tie-breaks are true-positive count then precision. So
the goal is: on the contracts curated issues actually live in, find *every* real
exploitable high/critical issue and drop the ones that would not survive scrutiny.

Rather than spread shallow single-pass audits across many files, this agent goes
deep on the highest-value contracts and runs a **two-pass** audit on each:

  1. **Detect pass** — a full audit of the whole contract for all real, distinct
     HIGH/CRITICAL vulnerabilities.
  2. **Self-critique pass** — the model is shown its own candidate findings and the
     source again, told to *drop* anything not concretely exploitable (protecting
     precision) and to *hunt for additional* issues it missed the first time,
     function by function (protecting recall).

The two passes for each target run as an independent chain, and the chains run
**concurrently** across targets, so the extra depth costs little wall-clock: model
calls are network-bound on the validator proxy. Every surviving finding is forced
into the exact shape the scorer matches on and its function is validated against
the real source, so hallucinated locations are discarded.

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
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from pathlib import Path

# --- discovery / ranking ----------------------------------------------------
SOL_SUFFIXES = (".sol", ".vy")
EXCLUDED_DIR_NAMES = {
    "test", "tests", "mock", "mocks", "example", "examples", "script", "scripts",
    "broadcast", "node_modules", "vendor", "vendors", "lib", "libs", "out",
    "artifacts", "cache", "coverage", "forge-std", "openzeppelin", "solmate",
    "interfaces", "interface",
}
SUSPICIOUS_NAME_TERMS = (
    "vault", "router", "bridge", "proxy", "upgrade", "oracle", "govern",
    "treasury", "manager", "pool", "reward", "staking", "stake", "market",
    "reserve", "lend", "borrow", "collateral", "controller", "strategy",
    "auction", "token", "admin", "owner", "swap", "escrow", "distributor",
    "farm", "mint", "sale", "crowdsale", "timelock", "wallet", "fund",
)
SUSPICIOUS_CONTENT_PATTERNS = (
    r"\bdelegatecall\b", r"\.call\s*\{", r"\bcall\.value\b", r"\bselfdestruct\b",
    r"\btx\.origin\b", r"\bassembly\b", r"\becrecover\b", r"\bpermit\b",
    r"\bonlyOwner\b", r"\bonlyRole\b", r"\bupgradeTo\b", r"\b_mint\b", r"\b_burn\b",
    r"\bwithdraw\b", r"\bredeem\b", r"\bliquidat", r"\bborrow\b", r"\brepay\b",
    r"\btransferFrom\b", r"\bsafeTransfer", r"\bunchecked\b", r"\breentran",
    r"\bflash", r"\bgetPrice\b", r"\blatestAnswer\b", r"\bslot0\b", r"\bnonce\b",
    r"\bsignature\b", r"\btotalSupply\b", r"\bbalanceOf\b", r"\bapprove\b",
    r"\btransferOwnership\b", r"\binitialize\b", r"\bmsg\.value\b",
)
CONTRACT_NAME_PATTERN = re.compile(
    r"\b(?:contract|library|abstract\s+contract)\s+([A-Za-z_][A-Za-z0-9_]*)"
)
FUNCTION_DEF_PATTERN = re.compile(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
IMPORT_PATTERN = re.compile(r'^\s*import\b[^;]*?["\']([^"\']+)["\']', re.MULTILINE)

# --- budgets ----------------------------------------------------------------
MAX_FILE_BYTES = 220_000
DEEP_TARGETS = 5             # contracts we audit in depth (two passes each)
MAX_WORKERS = 5
MAX_CONTRACT_CHARS = 24_000
MAX_RELATED_CHARS = 4_000
MAX_FINDINGS_PER_TARGET = 4
MAX_FINDINGS = 12
MAX_RUNTIME_SECONDS = 215.0
DETECT_TIMEOUT_SECONDS = 100
CRITIQUE_TIMEOUT_SECONDS = 90
MAX_RETRIES = 1

SYSTEM_PROMPT = (
    "You are a principal smart-contract security auditor. You find only REAL, "
    "exploitable HIGH or CRITICAL vulnerabilities — logic flaws that let an "
    "attacker steal funds, escalate privilege, brick the protocol, or corrupt "
    "accounting. You ignore gas, style, missing events, and speculative issues "
    "with no concrete exploit path. You are meticulous and precise about WHERE "
    "the bug is: the exact file, contract, and function."
)


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
            if path.is_file() and path.suffix.lower() in SOL_SUFFIXES:
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
    if "constructor" in content:
        score += 2
    if content.count("function ") and content.count("function ") == content.count(");"):
        score -= 6
    return score


def _discover(project_root: Path) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for path in sorted(project_root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in SOL_SUFFIXES:
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


def _related_source(target: dict[str, object], by_rel: dict[str, dict[str, object]]) -> str | None:
    """Best-effort: pull one directly-imported local file for cross-file context."""
    for match in IMPORT_PATTERN.finditer(str(target["content"])):
        imp = match.group(1)
        if not imp or not (imp.startswith(".") or imp.endswith(".sol")):
            continue
        base = imp.rsplit("/", 1)[-1]
        for rel, rec in by_rel.items():
            if rel == target["rel"]:
                continue
            if rel.endswith(base):
                text = str(rec["content"])
                return f"// related import: {rel}\n{text[:MAX_RELATED_CHARS]}"
    return None


# ---------------------------------------------------------------------------
# inference
# ---------------------------------------------------------------------------
def _post_inference(
    inference_api: str | None,
    messages: list[dict[str, str]],
    timeout: int,
    max_tokens: int = 8000,
) -> str:
    endpoint = (inference_api or os.environ.get("INFERENCE_API") or "").rstrip("/")
    if not endpoint:
        raise ValueError("INFERENCE_API is not configured.")
    api_key = os.environ.get("INFERENCE_API_KEY", "").strip()
    body = json.dumps(
        {
            "messages": messages,
            "response_format": {"type": "json_object"},
            "max_tokens": max_tokens,
        }
    ).encode("utf-8")
    headers = {"Content-Type": "application/json", "x-inference-api-key": api_key}
    last: Exception | None = None
    for attempt in range(MAX_RETRIES + 1):
        try:
            request = urllib.request.Request(
                endpoint + "/inference", data=body, method="POST", headers=headers
            )
            with urllib.request.urlopen(request, timeout=timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
            return _extract_content(payload)
        except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
            last = exc
            if attempt < MAX_RETRIES:
                time.sleep(1.5 * (attempt + 1))
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


def _parse_json_object(content: str) -> dict | None:
    text = content.strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\n?", "", text)
        text = re.sub(r"\n?```$", "", text).strip()
    try:
        obj = json.loads(text)
        return obj if isinstance(obj, dict) else None
    except json.JSONDecodeError:
        pass
    start, depth = text.find("{"), 0
    if start == -1:
        return None
    for i in range(start, len(text)):
        depth += 1 if text[i] == "{" else -1 if text[i] == "}" else 0
        if depth == 0:
            try:
                obj = json.loads(text[start : i + 1])
                return obj if isinstance(obj, dict) else None
            except json.JSONDecodeError:
                return None
    return None


def _parse_findings(content: str) -> list[dict[str, object]]:
    obj = _parse_json_object(content)
    if not isinstance(obj, dict):
        return []
    items = obj.get("findings") or obj.get("vulnerabilities") or obj.get("candidates")
    return [it for it in items if isinstance(it, dict)] if isinstance(items, list) else []


# ---------------------------------------------------------------------------
# per-target two-pass audit
# ---------------------------------------------------------------------------
_JSON_SHAPE = (
    '{"findings": [{'
    '"title": "<Contract>.<function> — <specific bug>", '
    '"contract": "<ContractName>", '
    '"function": "<functionName the bug is in>", '
    '"file": "<FILE>", '
    '"line": <int or null>, '
    '"severity": "high|critical", '
    '"mechanism": "<how an attacker triggers it: precondition -> action -> effect>", '
    '"impact": "<concrete consequence: funds stolen / privilege escalation / DoS / insolvency>", '
    '"description": "<3-5 sentences naming the file, contract and function, then the mechanism and impact>"'
    "}]}"
)


def _build_detect_prompt(target: dict[str, object], related: str | None) -> str:
    rel = target["rel"]
    contracts = ", ".join(target["contracts"][:6]) or "(unnamed)"
    content = str(target["content"])[:MAX_CONTRACT_CHARS]
    truncated = " (truncated)" if len(str(target["content"])) > MAX_CONTRACT_CHARS else ""
    parts = [
        "Audit this Solidity file for ALL real, distinct HIGH/CRITICAL "
        "vulnerabilities. Examine every state-changing function in turn — a file "
        "usually has more than one exploitable issue.\n",
        f"File path (use EXACTLY this as `file`): {rel}",
        f"Contracts defined here: {contracts}\n",
        "Reason through protocol logic, access control, external calls and "
        "reentrancy, accounting/oracle math, initialization/upgrade paths, and "
        "signature/replay handling. Report ONLY issues with a concrete exploit "
        "path and material impact.\n",
        "Return STRICT JSON, no prose, of this exact shape:",
        _JSON_SHAPE.replace("<FILE>", str(rel)),
        f"Rules: report up to {MAX_FINDINGS_PER_TARGET} genuinely-exploitable "
        "issues; each MUST name the real function it lives in; if nothing is "
        'genuinely exploitable, return {"findings": []}. Never invent functions '
        "or files not in the source below.\n",
        f"----- SOURCE{truncated} -----",
        content,
    ]
    if related:
        parts += ["\n----- RELATED CONTEXT (read-only) -----", related[:MAX_RELATED_CHARS]]
    return "\n".join(parts)


def _build_critique_prompt(
    target: dict[str, object], candidates: list[dict[str, object]]
) -> str:
    rel = target["rel"]
    content = str(target["content"])[:MAX_CONTRACT_CHARS]
    slim = [
        {
            "title": c.get("title"),
            "function": c.get("function"),
            "severity": c.get("severity"),
            "mechanism": c.get("mechanism", ""),
        }
        for c in candidates
    ]
    return "\n".join(
        [
            "You previously produced these candidate findings for the Solidity "
            f"file `{rel}`:",
            json.dumps(slim, ensure_ascii=False),
            "",
            "Now do two things, using the source below:",
            "1. VERIFY: drop any candidate that is not a concretely exploitable "
            "HIGH/CRITICAL issue (wrong, speculative, low-impact, or best-practice "
            "nit). Keep only real ones.",
            "2. EXTEND: carefully re-read every state-changing function and add any "
            "ADDITIONAL real HIGH/CRITICAL vulnerabilities you missed the first "
            "time.",
            "",
            "Return the FINAL consolidated list as STRICT JSON, no prose, of this "
            "exact shape:",
            _JSON_SHAPE.replace("<FILE>", str(rel)),
            f"Include at most {MAX_FINDINGS_PER_TARGET} findings, each naming the "
            "real function it lives in. Do not invent functions or files not in "
            "the source.\n",
            "----- SOURCE -----",
            content,
        ]
    )


def _valid_functions(content: str) -> set[str]:
    return set(FUNCTION_DEF_PATTERN.findall(content))


def _normalize(
    raw: dict[str, object], target: dict[str, object], valid_fns: set[str]
) -> dict[str, object] | None:
    severity = str(raw.get("severity") or "").strip().lower()
    if severity not in {"high", "critical"}:
        return None
    contract = str(raw.get("contract") or (target["contracts"][0] if target["contracts"] else "")).strip()
    function = str(raw.get("function") or "").strip().strip("()")
    if function and valid_fns and function not in valid_fns:
        function = function.split(".")[-1]
        if function not in valid_fns:
            function = ""
    file_path = str(raw.get("file") or target["rel"]).strip() or str(target["rel"])
    mechanism = str(raw.get("mechanism") or "").strip()
    impact = str(raw.get("impact") or "").strip()
    description = str(raw.get("description") or "").strip()
    title = str(raw.get("title") or "").strip()

    loc = f"{contract}.{function}" if contract and function else (contract or function)
    if not title:
        title = f"{loc} — {severity} severity issue" if loc else "High-severity issue"
    elif loc and loc.lower() not in title.lower():
        title = f"{loc} — {title}"

    if len(description) < 80 or (function and function not in description):
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
    if len(description) < 80:
        return None

    return {
        "title": title[:200],
        "description": description,
        "severity": severity,
        "file": file_path,
        "function": function,
        "line": raw.get("line") if isinstance(raw.get("line"), int) else None,
        "type": str(raw.get("type") or raw.get("vulnerability_type") or "logic"),
        "confidence": 0.9 if severity == "critical" else 0.8,
    }


def _audit_target_twopass(
    inference_api: str | None,
    target: dict[str, object],
    by_rel: dict[str, dict[str, object]],
    detect_timeout: int,
    critique_timeout: int,
    deadline: float,
) -> list[dict[str, object]]:
    related = _related_source(target, by_rel)
    valid_fns = _valid_functions(str(target["content"]))

    # Pass 1 — detect
    try:
        detect_raw = _post_inference(
            inference_api,
            [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": _build_detect_prompt(target, related)},
            ],
            timeout=detect_timeout,
        )
    except (RuntimeError, ValueError):
        return []
    candidates = [
        c for c in (_normalize(r, target, valid_fns) for r in _parse_findings(detect_raw))
        if c is not None
    ][:MAX_FINDINGS_PER_TARGET]

    # Pass 2 — self-critique (verify + extend). Skip if out of time.
    if time.monotonic() > deadline - 15 or not candidates:
        return candidates
    try:
        critique_raw = _post_inference(
            inference_api,
            [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": _build_critique_prompt(target, candidates)},
            ],
            timeout=critique_timeout,
        )
    except (RuntimeError, ValueError):
        return candidates
    refined = [
        c for c in (_normalize(r, target, valid_fns) for r in _parse_findings(critique_raw))
        if c is not None
    ][:MAX_FINDINGS_PER_TARGET]
    # Prefer the refined set, but never let a flaky critique erase real work:
    # if critique returned nothing, keep the detect-pass candidates.
    return refined if refined else candidates


def _title_core(title: str) -> str:
    """Title without its `Contract.function — ` prefix, normalized for dedupe."""
    core = title.split("—", 1)[-1] if "—" in title else title
    return re.sub(r"\s+", " ", core).strip().lower()[:60]


def _dedupe(findings: list[dict[str, object]]) -> list[dict[str, object]]:
    seen_fn: set[tuple[str, str]] = set()
    seen_title: set[tuple[str, str]] = set()
    out: list[dict[str, object]] = []
    order = sorted(
        findings,
        key=lambda f: (f["severity"] == "critical", float(f["confidence"])),
        reverse=True,
    )
    for f in order:
        file_key = str(f["file"]).lower()
        fn = str(f["function"]).lower()
        title_key = (file_key, _title_core(str(f["title"])))
        # Same file+function, or same file+issue described in the title, is a dup —
        # this collapses the case where function validation emptied one copy.
        if fn and (file_key, fn) in seen_fn:
            continue
        if title_key in seen_title:
            continue
        if fn:
            seen_fn.add((file_key, fn))
        seen_title.add(title_key)
        out.append(f)
    return out


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

    deadline = time.monotonic() + MAX_RUNTIME_SECONDS
    records = _discover(project_root)
    if not records:
        return {"vulnerabilities": findings}
    by_rel = {str(r["rel"]): r for r in records}
    targets = records[:DEEP_TARGETS]

    collected: list[dict[str, object]] = []
    workers = max(1, min(MAX_WORKERS, len(targets)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(
                _audit_target_twopass,
                inference_api,
                target,
                by_rel,
                DETECT_TIMEOUT_SECONDS,
                CRITIQUE_TIMEOUT_SECONDS,
                deadline,
            ): target
            for target in targets
        }
        for future in list(futures):
            budget = deadline - time.monotonic()
            if budget <= 0:
                break
            try:
                collected.extend(future.result(timeout=budget))
            except (FutureTimeout, Exception):
                continue

    findings = _dedupe(collected)[:MAX_FINDINGS]
    return {"vulnerabilities": findings}


if __name__ == "__main__":  # local smoke check only (no network)
    import sys

    print(json.dumps(agent_main(sys.argv[1] if len(sys.argv) > 1 else None), indent=2))
