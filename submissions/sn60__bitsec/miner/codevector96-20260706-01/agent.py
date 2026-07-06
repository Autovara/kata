from __future__ import annotations

"""SN60 / Bitsec miner agent — wide-coverage, triage-ranked auditor.

Why this beats a sequential depth-first agent
---------------------------------------------
The pinned semantic scorer counts a finding as a true positive only when it names
the right *file*, *function*, *core mechanism*, and *impact* of a curated
HIGH/CRITICAL issue. Detection score (``true_positives / total_expected``) is the
primary promotion signal, so the whole game is **recall of real, correctly-located
issues** — surface a curated vulnerability the king missed and you out-detect it.

A sequential agent that audits one contract per model call is starved by the
per-project wall-clock budget: a reasoning model can take a minute or more per
call, so only a few of the most-suspicious contracts ever get looked at, and any
curated bug living in the 4th+ ranked contract is silently missed. This agent
removes that bottleneck in three ways:

  1. **Model-guided triage.** One cheap call turns a compact whole-repo map
     (contracts, functions, risk signals) into a ranked short-list, so target
     selection uses the model's judgement instead of a regex score alone — with a
     deterministic heuristic fallback if the call is slow or fails.

  2. **Concurrent deep audits.** The short-listed contracts are audited *in
     parallel*. Model calls are network-bound on the validator proxy, so fanning
     them out covers many more contracts inside the same wall-clock budget than
     running them back-to-back. This is the core recall win.

  3. **Matcher-shaped normalization.** Every finding is forced into the exact
     shape the scorer matches on — ``Contract.function — <bug>`` title and a
     description that names file, contract, function, then mechanism and impact —
     and its function is validated against the real source so hallucinated
     locations are dropped (protecting precision on tie-breaks).

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
# Contracts whose *name* implies value custody / privilege / accounting are the
# ones curated HIGH/CRITICAL issues almost always live in.
SUSPICIOUS_NAME_TERMS = (
    "vault", "router", "bridge", "proxy", "upgrade", "oracle", "govern",
    "treasury", "manager", "pool", "reward", "staking", "stake", "market",
    "reserve", "lend", "borrow", "collateral", "controller", "strategy",
    "auction", "token", "admin", "owner", "swap", "escrow", "distributor",
    "farm", "mint", "sale", "crowdsale", "timelock", "wallet", "fund",
)
# Content signals that correlate with exploitable logic (external calls, value
# movement, access control, low-level ops, signature/oracle handling).
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
# Per-project container is small (512MB / 0.25 CPU) but the expensive work is
# network I/O against the proxy, so a modest thread pool is safe and lets us
# cover many contracts within the wall clock.
MAX_FILE_BYTES = 220_000
CANDIDATE_POOL = 14          # heuristic short-list handed to triage
DEEP_TARGETS = 8             # contracts we deeply audit (vs a sequential ~2-3)
MAX_WORKERS = 8
MAX_CONTRACT_CHARS = 22_000  # whole-file context cap per target
MAX_RELATED_CHARS = 4_000
MAX_FINDINGS_PER_TARGET = 3
MAX_FINDINGS = 12
MAX_RUNTIME_SECONDS = 210.0
TRIAGE_TIMEOUT_SECONDS = 60
AUDIT_TIMEOUT_SECONDS = 150
MAX_RETRIES = 1

SYSTEM_PROMPT = (
    "You are a senior smart-contract security auditor. You find only REAL, "
    "exploitable HIGH or CRITICAL vulnerabilities — logic flaws that let an "
    "attacker steal funds, escalate privilege, brick the protocol, or corrupt "
    "accounting. You ignore gas, style, missing events, and speculative issues "
    "with no concrete exploit path. You are precise about WHERE the bug is: the "
    "exact file, contract, and function."
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
    # prefer files with real logic surface (functions, external calls, state)
    score += min(content.count("function "), 24)
    if "constructor" in content:
        score += 2
    # de-emphasise pure interfaces / abstract-only files that carry no logic
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
                "functions": FUNCTION_DEF_PATTERN.findall(content),
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
    if isinstance(content, list):  # some providers return content parts
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
    # salvage the outermost balanced JSON object from a noisy completion
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
# phase 1: model-guided triage (with heuristic fallback)
# ---------------------------------------------------------------------------
def _build_triage_prompt(candidates: list[dict[str, object]]) -> str:
    lines = [
        "You are triaging a Solidity codebase to decide which files most likely "
        "contain REAL exploitable HIGH/CRITICAL vulnerabilities (fund theft, "
        "privilege escalation, protocol insolvency, broken accounting).",
        "",
        "Here is the candidate file map (path — contracts — key functions):",
    ]
    for idx, rec in enumerate(candidates):
        fns = ", ".join(list(dict.fromkeys(rec["functions"]))[:12]) or "(none)"
        contracts = ", ".join(rec["contracts"][:4]) or "(unnamed)"
        lines.append(f"[{idx}] {rec['rel']} — {contracts} — fns: {fns}")
    lines += [
        "",
        f"Pick the {DEEP_TARGETS} files (by index) most worth a deep audit, most "
        "suspicious first. Prefer files that custody value, gate privilege, do "
        "accounting/oracle math, handle upgrades/initialization, or make external "
        "calls. Avoid pure interfaces and libraries with no state.",
        'Return STRICT JSON only: {"targets": [<index>, ...]}',
    ]
    return "\n".join(lines)


def _triage_rank(
    inference_api: str | None,
    candidates: list[dict[str, object]],
    deadline: float,
) -> list[dict[str, object]]:
    """Ask the model to re-rank the heuristic short-list; fall back to heuristics."""
    if len(candidates) <= DEEP_TARGETS or time.monotonic() > deadline - 30:
        return candidates[:DEEP_TARGETS]
    timeout = int(min(TRIAGE_TIMEOUT_SECONDS, max(15, deadline - time.monotonic() - 20)))
    try:
        content = _post_inference(
            inference_api,
            [
                {"role": "system", "content": "You are a precise triage assistant. Output only JSON."},
                {"role": "user", "content": _build_triage_prompt(candidates)},
            ],
            timeout=timeout,
            max_tokens=2000,
        )
    except (RuntimeError, ValueError):
        return candidates[:DEEP_TARGETS]
    obj = _parse_json_object(content)
    order = obj.get("targets") if isinstance(obj, dict) else None
    if not isinstance(order, list):
        return candidates[:DEEP_TARGETS]
    picked: list[dict[str, object]] = []
    seen: set[int] = set()
    for raw_idx in order:
        try:
            idx = int(raw_idx)
        except (TypeError, ValueError):
            continue
        if 0 <= idx < len(candidates) and idx not in seen:
            seen.add(idx)
            picked.append(candidates[idx])
        if len(picked) >= DEEP_TARGETS:
            break
    # backfill from heuristic order so we never audit fewer than intended
    for rec in candidates:
        if len(picked) >= DEEP_TARGETS:
            break
        if rec not in picked:
            picked.append(rec)
    return picked[:DEEP_TARGETS]


# ---------------------------------------------------------------------------
# phase 2: per-target deep audit + matcher-shaped normalization
# ---------------------------------------------------------------------------
def _build_audit_prompt(target: dict[str, object], related: str | None) -> str:
    rel = target["rel"]
    contracts = ", ".join(target["contracts"][:6]) or "(unnamed)"
    content = str(target["content"])[:MAX_CONTRACT_CHARS]
    truncated = " (truncated)" if len(str(target["content"])) > MAX_CONTRACT_CHARS else ""
    parts = [
        "Audit this Solidity file for ALL real, distinct HIGH/CRITICAL "
        "vulnerabilities. Do not stop at the first one — a file often has more "
        "than one exploitable issue.\n",
        f"File path (use EXACTLY this as `file`): {rel}",
        f"Contracts defined here: {contracts}\n",
        "Reason through protocol logic, access control, external calls and "
        "reentrancy, accounting/oracle math, initialization/upgrade paths, and "
        "signature/replay handling. Report ONLY issues with a concrete exploit "
        "path and material impact.\n",
        "Return STRICT JSON, no prose, of this exact shape:",
        '{"findings": [{'
        '"title": "<Contract>.<function> — <specific bug>", '
        '"contract": "<ContractName>", '
        '"function": "<functionName the bug is in>", '
        '"file": "' + str(rel) + '", '
        '"line": <int or null>, '
        '"severity": "high|critical", '
        '"mechanism": "<how an attacker triggers it: precondition -> action -> effect>", '
        '"impact": "<concrete consequence: funds stolen / privilege escalation / DoS / insolvency>", '
        '"description": "<3-5 sentences naming the file, contract and function, then the mechanism and impact>"'
        "}]}",
        f"Rules: report up to {MAX_FINDINGS_PER_TARGET} of the most severe, "
        "genuinely-exploitable issues; each MUST name the real function it lives "
        'in; if nothing is genuinely exploitable, return {"findings": []}. Never '
        "invent functions or files that are not in the source below.\n",
        f"----- SOURCE{truncated} -----",
        content,
    ]
    if related:
        parts += ["\n----- RELATED CONTEXT (read-only) -----", related[:MAX_RELATED_CHARS]]
    return "\n".join(parts)


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
    # keep the model honest: the function must exist in this source
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

    # Build a matcher-complete description: file + contract + function, then
    # mechanism, then impact — exactly the fields the semantic scorer checks.
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
        return None  # too thin to match; drop it

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


def _audit_target(
    inference_api: str | None,
    target: dict[str, object],
    by_rel: dict[str, dict[str, object]],
    timeout: int,
) -> list[dict[str, object]]:
    related = _related_source(target, by_rel)
    prompt = _build_audit_prompt(target, related)
    try:
        content = _post_inference(
            inference_api,
            [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            timeout=timeout,
        )
    except (RuntimeError, ValueError):
        return []
    valid_fns = _valid_functions(str(target["content"]))
    out: list[dict[str, object]] = []
    for raw in _parse_findings(content)[:MAX_FINDINGS_PER_TARGET]:
        norm = _normalize(raw, target, valid_fns)
        if norm is not None:
            out.append(norm)
    return out


def _dedupe(findings: list[dict[str, object]]) -> list[dict[str, object]]:
    seen: set[tuple[str, str]] = set()
    out: list[dict[str, object]] = []
    order = sorted(
        findings,
        key=lambda f: (f["severity"] == "critical", float(f["confidence"])),
        reverse=True,
    )
    for f in order:
        key = (str(f["file"]).lower(), str(f["function"]).lower() or str(f["title"]).lower()[:40])
        if key in seen:
            continue
        seen.add(key)
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

    candidates = records[:CANDIDATE_POOL]
    targets = _triage_rank(inference_api, candidates, deadline)

    collected: list[dict[str, object]] = []
    remaining = max(20.0, deadline - time.monotonic())
    per_call_timeout = int(min(AUDIT_TIMEOUT_SECONDS, remaining))
    workers = max(1, min(MAX_WORKERS, len(targets)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        future_map = {
            pool.submit(_audit_target, inference_api, target, by_rel, per_call_timeout): target
            for target in targets
        }
        for future in list(future_map):
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
