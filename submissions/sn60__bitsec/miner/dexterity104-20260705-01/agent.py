from __future__ import annotations

"""SN60 / Bitsec miner agent — breadth-then-depth whole-contract auditor.

Why this should out-detect the incumbent king (same pinned model, better agent):
the pinned semantic scorer only credits a finding when it pins the right (1)
file, (2) function, (3) core vulnerability mechanism, and (4) impact of a real
curated high/critical issue. The primary promotion signal is the detection score
(true positives / total expected), so RECALL is what wins — precision is only a
tiebreaker. The incumbent maximizes precision by looking at very few contracts
and emitting a tiny finding set, which structurally caps how many real issues it
can reach. This agent instead widens the reachable set while keeping every
finding matcher-shaped:

  * BREADTH first — it ranks every source file and analyzes many more of them
    than the incumbent, covering the primary body of each before spending extra
    budget, so vulnerabilities that live outside the few top-ranked contracts are
    still reached.
  * DEPTH where it matters — large contracts are split into overlapping chunks so
    a bug in the tail of a big file is not truncated away.
  * CONTEXT — each analysis is fed several directly-imported local contracts, so
    cross-contract logic (vault<->strategy, pool<->oracle, proxy<->impl) is
    visible and the model can reason about real exploit paths, not fragments.
  * SHAPE — every finding is forced into the form the matcher rewards: the title
    is ``Contract.function — <bug>`` and the description names the file, contract
    and function, then the concrete mechanism and impact. Functions are verified
    against the real source so hallucinated locations are dropped.
  * PRECISION guardrails — the model is told to report only genuinely exploitable
    high/critical issues and to return nothing for a clean file, findings are
    deduped, and the set is ranked by severity/confidence and capped, so the extra
    breadth does not devolve into noise.

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
# File/dir name hints for contracts that concentrate value or privilege.
SUSPICIOUS_NAME_TERMS = (
    "vault", "router", "bridge", "proxy", "upgrade", "oracle", "govern",
    "treasury", "manager", "pool", "reward", "staking", "stake", "market",
    "reserve", "lend", "borrow", "collateral", "controller", "strategy",
    "auction", "token", "admin", "owner", "escrow", "distributor", "vesting",
    "farm", "gauge", "minter", "swap", "pair", "factory", "comptroller",
)
# Content hints for high-risk primitives.
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
IMPORT_PATTERN = re.compile(r'^\s*import\b[^;]*?["\']([^"\']+)["\']', re.MULTILINE)

# --- budgets (per-project container: 512MB / 0.25 CPU) ----------------------
# Reliability first: the whole run stays well under the sandbox execution
# timeout, degrading to fewer contracts (never a timeout) on slow inference.
MAX_FILE_BYTES = 220_000
MAX_TARGET_FILES = 26          # distinct contracts we try to reach (breadth)
MAX_INFERENCE_CALLS = 36       # hard ceiling on model calls (files + tail chunks)
MAX_CONTRACT_CHARS = 20_000    # per-chunk whole-contract context cap
CHUNK_OVERLAP_CHARS = 1_500    # overlap so a bug on a chunk seam is not split
MAX_CHUNKS_PER_FILE = 3        # cap depth per file so one giant file can't starve breadth
MAX_RELATED_CHARS = 6_000      # per imported context file
MAX_RELATED_FILES = 3          # imported local contracts fed as context
MAX_FINDINGS_PER_TARGET = 4    # genuine issues we let the model report per analysis
MAX_FINDINGS = 50              # global cap (kept under the scorer's 100 ceiling)
MIN_DESCRIPTION_CHARS = 90
GLOBAL_DEADLINE_SECONDS = 1500.0
REQUEST_TIMEOUT_SECONDS = 110
MAX_RETRIES = 1

SYSTEM_PROMPT = (
    "You are a world-class smart-contract security auditor. You report only REAL, "
    "exploitable HIGH or CRITICAL vulnerabilities — logic and access-control flaws "
    "that let an attacker steal or freeze funds, escalate privilege, mint/inflate "
    "balances, manipulate prices/oracles, or corrupt protocol accounting. You "
    "ignore gas, style, missing events, and speculative issues that have no "
    "concrete exploit path. You are exact about WHERE each bug lives (contract and "
    "function) and HOW it is triggered."
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
    # Reward files with real logic surface (functions + external-call risk).
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


def _chunks(content: str) -> list[tuple[int, int, str]]:
    """Split a contract into overlapping chunks so long files are not truncated.

    Returns (chunk_index, chunk_count, text). Small files yield a single chunk.
    """
    if len(content) <= MAX_CONTRACT_CHARS:
        return [(0, 1, content)]
    pieces: list[str] = []
    start = 0
    step = MAX_CONTRACT_CHARS - CHUNK_OVERLAP_CHARS
    while start < len(content) and len(pieces) < MAX_CHUNKS_PER_FILE:
        pieces.append(content[start : start + MAX_CONTRACT_CHARS])
        start += step
    count = len(pieces)
    return [(i, count, text) for i, text in enumerate(pieces)]


def _build_units(records: list[dict[str, object]]) -> list[dict[str, object]]:
    """Breadth-first analysis units: every file's primary chunk first (by rank),
    then the overflow chunks of large files if budget remains."""
    ranked = records[:MAX_TARGET_FILES]
    per_file_chunks = [(rec, _chunks(str(rec["content"]))) for rec in ranked]
    max_depth = max((len(chunks) for _, chunks in per_file_chunks), default=0)
    units: list[dict[str, object]] = []
    for depth in range(max_depth):
        for rec, chunks in per_file_chunks:
            if depth >= len(chunks):
                continue
            index, count, text = chunks[depth]
            units.append(
                {
                    "record": rec,
                    "rel": rec["rel"],
                    "chunk_index": index,
                    "chunk_count": count,
                    "text": text,
                }
            )
    return units


def _related_sources(
    record: dict[str, object], by_rel: dict[str, dict[str, object]]
) -> str | None:
    """Pull a few directly-imported local contracts for cross-contract context."""
    collected: list[str] = []
    used: set[str] = {str(record["rel"])}
    for match in IMPORT_PATTERN.finditer(str(record["content"])):
        if len(collected) >= MAX_RELATED_FILES:
            break
        imp = match.group(1)
        if not imp or not (imp.startswith(".") or imp.endswith(".sol") or imp.endswith(".vy")):
            continue
        base = imp.rsplit("/", 1)[-1]
        for rel, rec in by_rel.items():
            if rel in used:
                continue
            if rel.endswith(base):
                text = str(rec["content"])[:MAX_RELATED_CHARS]
                collected.append(f"// related import: {rel}\n{text}")
                used.add(rel)
                break
    if not collected:
        return None
    return "\n\n".join(collected)


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
            "max_tokens": 4000,
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
        except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
            last = exc
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
    if isinstance(content, list):  # some providers return content parts
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
        # Salvage the outermost JSON object from a noisy completion.
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
# per-target analysis + matcher-shaped normalization
# ---------------------------------------------------------------------------
def _build_prompt(unit: dict[str, object], related: str | None) -> str:
    record = unit["record"]
    rel = record["rel"]
    contracts = ", ".join(record["contracts"][:8]) or "(unnamed)"
    text = str(unit["text"])
    chunk_index = int(unit["chunk_index"])
    chunk_count = int(unit["chunk_count"])
    chunk_note = (
        f" (part {chunk_index + 1} of {chunk_count} of a large file)"
        if chunk_count > 1
        else ""
    )
    parts = [
        "Audit this Solidity/Vyper source for REAL, exploitable HIGH or CRITICAL "
        "vulnerabilities.\n",
        f"File path (use EXACTLY this as `file`): {rel}{chunk_note}",
        f"Contracts defined here: {contracts}\n",
        "Reason through protocol logic, access control, external calls, "
        "accounting/oracle math, share/collateral math, reentrancy, and "
        "initialize/upgrade paths. Enumerate EVERY distinct issue that has a "
        "concrete exploit path and material impact — do not stop at the first "
        "one — but report ONLY genuine ones.\n",
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
        '"description": "<2-4 sentences naming the file, contract and function, then the mechanism and impact>"'
        "}]}",
        f"Rules: report at most {MAX_FINDINGS_PER_TARGET} of the strongest, distinct "
        "findings; each MUST name the real function it lives in; if nothing is "
        'genuinely exploitable in this source, return {"findings": []}. Never '
        "invent functions or files that are not in the source below.\n",
        f"----- SOURCE{chunk_note} -----",
        text,
    ]
    if related:
        parts += [
            "\n----- RELATED CONTEXT (read-only, do NOT report bugs in these) -----",
            related,
        ]
    return "\n".join(parts)


def _valid_functions(content: str) -> set[str]:
    return set(FUNCTION_DEF_PATTERN.findall(content))


def _normalize(
    raw: dict[str, object], record: dict[str, object], valid_fns: set[str]
) -> dict[str, object] | None:
    severity = str(raw.get("severity") or "").strip().lower()
    if severity not in {"high", "critical"}:
        return None
    contract = str(
        raw.get("contract") or (record["contracts"][0] if record["contracts"] else "")
    ).strip()
    function = str(raw.get("function") or "").strip().strip("()")
    # Keep the model honest: the function must exist somewhere in the real file.
    if function and valid_fns and function not in valid_fns:
        function = function.split(".")[-1]
        if function not in valid_fns:
            function = ""
    file_path = str(raw.get("file") or record["rel"]).strip() or str(record["rel"])
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
    # mechanism, then impact — exactly the anchors the scorer looks for.
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


def _bug_token(finding: dict[str, object]) -> str:
    """Short normalized signature of the bug, so two *distinct* issues in the same
    function are not collapsed while near-identical duplicates (e.g. the same bug
    re-reported from an overlapping chunk) still are."""
    title = str(finding.get("title") or "")
    suffix = title.split("—", 1)[-1] if "—" in title else title
    tokens = re.findall(r"[a-z0-9]+", suffix.lower())
    return " ".join(tokens[:6])


def _dedupe(findings: list[dict[str, object]]) -> list[dict[str, object]]:
    seen: set[tuple[str, str, str]] = set()
    out: list[dict[str, object]] = []
    order = sorted(
        findings,
        key=lambda f: (f["severity"] == "critical", float(f["confidence"])),
        reverse=True,
    )
    for f in order:
        function = str(f["function"]).lower()
        discriminator = _bug_token(f) if function else str(f["title"]).lower()[:48]
        key = (str(f["file"]).lower(), function, discriminator)
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

    deadline = time.monotonic() + GLOBAL_DEADLINE_SECONDS
    records = _discover(project_root)
    if not records:
        return {"vulnerabilities": findings}
    by_rel = {str(r["rel"]): r for r in records}

    valid_fns_cache: dict[str, set[str]] = {}
    per_target_counts: dict[str, int] = {}
    related_cache: dict[str, str | None] = {}
    collected: list[dict[str, object]] = []
    calls = 0

    for unit in _build_units(records):
        if calls >= MAX_INFERENCE_CALLS or time.monotonic() > deadline:
            break
        record = unit["record"]
        rel = str(unit["rel"])
        if per_target_counts.get(rel, 0) >= MAX_FINDINGS_PER_TARGET:
            continue  # already have enough strong findings for this file
        if rel not in related_cache:
            related_cache[rel] = _related_sources(record, by_rel)
        prompt = _build_prompt(unit, related_cache[rel])
        calls += 1
        try:
            content = _post_inference(
                inference_api,
                [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                deadline=deadline,
            )
        except (RuntimeError, ValueError):
            continue
        if rel not in valid_fns_cache:
            valid_fns_cache[rel] = _valid_functions(str(record["content"]))
        valid_fns = valid_fns_cache[rel]
        for raw in _parse_findings(content):
            norm = _normalize(raw, record, valid_fns)
            if norm is None:
                continue
            if per_target_counts.get(rel, 0) >= MAX_FINDINGS_PER_TARGET:
                break
            collected.append(norm)
            per_target_counts[rel] = per_target_counts.get(rel, 0) + 1

    findings = _dedupe(collected)[:MAX_FINDINGS]
    return {"vulnerabilities": findings}


if __name__ == "__main__":  # local smoke check only (no network)
    import sys

    print(json.dumps(agent_main(sys.argv[1] if len(sys.argv) > 1 else None), indent=2))
