from __future__ import annotations

"""SN60 / Bitsec miner agent — high-precision auditor with wider coverage.

Design rationale
----------------
The reigning king is a depth-first, matcher-tuned auditor that runs one high-
precision pass over its top-4 most-suspicious contracts. It is strong precisely
because it is *precise*: it names file, contract, function, mechanism and impact
exactly as the semantic scorer expects, and it does not drown real findings in
noise. Two challengers that simply ran broad, many-call concurrent audits lost to
it — extra breadth on the pinned model tends to add false positives faster than
true positives, and detection score (``true_positives / total_expected``) with a
precision tie-break does not reward noise.

So this agent keeps the king's winning recipe and adds only the two recall levers
the king actually lacks, each designed *not* to cost precision:

  1. **Triage-guided coverage.** It audits a few more contracts than the king's
     fixed top-4 (default 6), and it chooses them with a cheap model triage over a
     compact whole-repo map — so a curated bug sitting in a contract the king's
     pure regex ranking under-rates is still covered. Heuristic fallback if triage
     is slow or fails.

  2. **Additive recall sweep.** On the two highest-value contracts it runs a second
     pass that is shown the issues already found and asked *only for ADDITIONAL,
     distinct* high/critical issues in other functions. It never drops or rewrites
     an existing finding, so it can raise recall without the risk that a
     "verify-and-prune" pass would erase a real one on a weaker model.

Every finding is normalized to the exact matcher shape (``Contract.function —
<bug>`` title; description naming file, contract, function, then mechanism and
impact), its function validated against the real source, and near-duplicates
collapsed — so more coverage does not become more noise. All audits run
concurrently, because model calls are network-bound on the validator proxy, so the
extra depth costs little wall-clock.

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

# --- budgets (tuned for the pinned small MoE model) -------------------------
MAX_FILE_BYTES = 220_000
CANDIDATE_POOL = 12          # heuristic short-list handed to triage
TOP_TARGETS = 6             # contracts we audit (king uses 4)
SWEEP_TARGETS = 2           # top contracts that also get an additive recall sweep
MAX_WORKERS = 6
MAX_CONTRACT_CHARS = 16_000
MAX_RELATED_CHARS = 4_000
MAX_FINDINGS_PER_TARGET = 3
MAX_FINDINGS = 8
MAX_RUNTIME_SECONDS = 210.0
TRIAGE_TIMEOUT_SECONDS = 50
AUDIT_TIMEOUT_SECONDS = 140
SWEEP_TIMEOUT_SECONDS = 90
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
# triage — model-guided target selection (heuristic fallback)
# ---------------------------------------------------------------------------
def _build_triage_prompt(candidates: list[dict[str, object]]) -> str:
    lines = [
        "Triage this Solidity codebase: pick the files most likely to contain REAL "
        "exploitable HIGH/CRITICAL vulnerabilities (fund theft, privilege "
        "escalation, insolvency, broken accounting).",
        "",
        "Candidate files (path — contracts — key functions):",
    ]
    for idx, rec in enumerate(candidates):
        fns = ", ".join(list(dict.fromkeys(rec["functions"]))[:12]) or "(none)"
        contracts = ", ".join(rec["contracts"][:4]) or "(unnamed)"
        lines.append(f"[{idx}] {rec['rel']} — {contracts} — fns: {fns}")
    lines += [
        "",
        f"Return STRICT JSON only: {{\"targets\": [<index>, ...]}} listing the "
        f"{TOP_TARGETS} most suspicious file indices, most suspicious first. Prefer "
        "files that custody value, gate privilege, do accounting/oracle math, "
        "handle upgrades/initialization, or make external calls.",
    ]
    return "\n".join(lines)


def _triage_rank(
    inference_api: str | None,
    candidates: list[dict[str, object]],
    deadline: float,
) -> list[dict[str, object]]:
    if len(candidates) <= TOP_TARGETS or time.monotonic() > deadline - 30:
        return candidates[:TOP_TARGETS]
    timeout = int(min(TRIAGE_TIMEOUT_SECONDS, max(15, deadline - time.monotonic() - 20)))
    try:
        content = _post_inference(
            inference_api,
            [
                {"role": "system", "content": "You are a precise triage assistant. Output only JSON."},
                {"role": "user", "content": _build_triage_prompt(candidates)},
            ],
            timeout=timeout,
            max_tokens=1500,
        )
    except (RuntimeError, ValueError):
        return candidates[:TOP_TARGETS]
    obj = _parse_json_object(content)
    order = obj.get("targets") if isinstance(obj, dict) else None
    if not isinstance(order, list):
        return candidates[:TOP_TARGETS]
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
        if len(picked) >= TOP_TARGETS:
            break
    for rec in candidates:
        if len(picked) >= TOP_TARGETS:
            break
        if rec not in picked:
            picked.append(rec)
    return picked[:TOP_TARGETS]


# ---------------------------------------------------------------------------
# per-target audit + additive recall sweep + matcher-shaped normalization
# ---------------------------------------------------------------------------
def _build_audit_prompt(target: dict[str, object], related: str | None) -> str:
    rel = target["rel"]
    contracts = ", ".join(target["contracts"][:6]) or "(unnamed)"
    content = str(target["content"])[:MAX_CONTRACT_CHARS]
    truncated = " (truncated)" if len(str(target["content"])) > MAX_CONTRACT_CHARS else ""
    parts = [
        "Audit this Solidity file for real HIGH/CRITICAL vulnerabilities.\n",
        f"File path (use EXACTLY this as `file`): {rel}",
        f"Contracts defined here: {contracts}\n",
        "Think through protocol logic, access control, external calls and "
        "reentrancy, accounting/oracle math, and upgrade/init paths. Report ONLY "
        "issues with a concrete exploit path and material impact.\n",
        "Return STRICT JSON, no prose, of this exact shape:",
        _json_shape(rel),
        f"Rules: at most {MAX_FINDINGS_PER_TARGET} findings; each MUST name the real "
        'function it lives in; if nothing is genuinely exploitable, return '
        '{"findings": []}. Do not invent functions or files not in the source.\n',
        f"----- SOURCE{truncated} -----",
        content,
    ]
    if related:
        parts += ["\n----- RELATED CONTEXT (read-only) -----", related[:MAX_RELATED_CHARS]]
    return "\n".join(parts)


def _build_sweep_prompt(target: dict[str, object], found: list[dict[str, object]]) -> str:
    rel = target["rel"]
    content = str(target["content"])[:MAX_CONTRACT_CHARS]
    already = "; ".join(
        f"{f.get('function') or '?'}: {str(f.get('title') or '').split('—')[-1].strip()}"
        for f in found
    ) or "(none)"
    return "\n".join(
        [
            f"You already reported these HIGH/CRITICAL issues in `{rel}`: {already}.",
            "",
            "Re-read every OTHER state-changing function and report only ADDITIONAL, "
            "DISTINCT real HIGH/CRITICAL vulnerabilities not already listed above. Do "
            "not repeat the ones above. If there are no additional ones, return "
            '{"findings": []}.',
            "",
            "Return STRICT JSON, no prose, of this exact shape:",
            _json_shape(rel),
            "Each finding MUST name the real function it lives in. Do not invent "
            "functions or files not in the source.\n",
            "----- SOURCE -----",
            content,
        ]
    )


def _json_shape(rel: object) -> str:
    return (
        '{"findings": [{'
        '"title": "<Contract>.<function> — <specific bug>", '
        '"contract": "<ContractName>", '
        '"function": "<functionName the bug is in>", '
        '"file": "' + str(rel) + '", '
        '"line": <int or null>, '
        '"severity": "high|critical", '
        '"mechanism": "<attacker path: precondition -> action -> effect>", '
        '"impact": "<funds stolen / privilege escalation / DoS / insolvency>", '
        '"description": "<2-4 sentences naming file, contract, function, then mechanism and impact>"'
        "}]}"
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


def _audit_target(
    inference_api: str | None,
    target: dict[str, object],
    by_rel: dict[str, dict[str, object]],
    do_sweep: bool,
    deadline: float,
) -> list[dict[str, object]]:
    related = _related_source(target, by_rel)
    valid_fns = _valid_functions(str(target["content"]))
    try:
        audit_raw = _post_inference(
            inference_api,
            [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": _build_audit_prompt(target, related)},
            ],
            timeout=AUDIT_TIMEOUT_SECONDS,
        )
    except (RuntimeError, ValueError):
        return []
    found = [
        c for c in (_normalize(r, target, valid_fns) for r in _parse_findings(audit_raw))
        if c is not None
    ][:MAX_FINDINGS_PER_TARGET]

    # Additive recall sweep on the highest-value contracts only.
    if do_sweep and found and time.monotonic() < deadline - 20:
        try:
            sweep_raw = _post_inference(
                inference_api,
                [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": _build_sweep_prompt(target, found)},
                ],
                timeout=SWEEP_TIMEOUT_SECONDS,
            )
            extra = [
                c for c in (_normalize(r, target, valid_fns) for r in _parse_findings(sweep_raw))
                if c is not None
            ]
            found = found + extra  # additive: never drop the first-pass findings
        except (RuntimeError, ValueError):
            pass
    return found


def _title_core(title: str) -> str:
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

    candidates = records[:CANDIDATE_POOL]
    targets = _triage_rank(inference_api, candidates, deadline)

    collected: list[dict[str, object]] = []
    workers = max(1, min(MAX_WORKERS, len(targets)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {}
        for rank, target in enumerate(targets):
            do_sweep = rank < SWEEP_TARGETS
            futures[pool.submit(_audit_target, inference_api, target, by_rel, do_sweep, deadline)] = target
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
