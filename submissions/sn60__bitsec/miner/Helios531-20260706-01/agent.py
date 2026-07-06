"""SN60 Bitsec miner agent (Helios531 challenger).

Approach: broad-but-budgeted coverage with cross-contract context, static
vulnerability hinting, and truncation-safe source extraction.

Improvements over the depth-first king:
- Audit up to TARGET_BUDGET contracts (broader coverage) with a per-target time
  budget so one slow contract can't starve the rest.
- For each target, resolve its LOCAL import chain and pass it as read-only
  context, so interaction bugs (oracle manipulation, callback reentrancy,
  trusted-helper assumptions) are visible instead of hidden behind file
  boundaries.
- Run cheap regex detectors for classic high/critical patterns (CEI violations,
  tx.origin auth, delegatecall targets, ecrecover, block-value price sources,
  unchecked arithmetic, fee-on-transfer accounting, missing reentrancy guards)
  and inject them as function+line hints to prime the model toward real bugs.
- Build a compact per-contract risk map to focus reasoning.
- When a large contract exceeds the source cap, extract the FULL bodies of
  risk-flagged functions beyond the cap so dangerous code is never lost to
  truncation.
- Optional refinement pass (when time permits) to confirm findings against the
  actual function body, lifting precision.
- Force every finding into the scorer's matcher shape and infer a source line.

Self-contained (stdlib only). Reads source from ``project_dir`` (defaults to the
Bitsec mount /app/project_code) and reaches the model only through the
validator-provided inference proxy.
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path

# --- configuration -----------------------------------------------------------
SOURCE_SUFFIXES = (".sol", ".vy")
IGNORED_DIRS = frozenset({
    "test", "tests", "mock", "mocks", "example", "examples", "script",
    "scripts", "broadcast", "node_modules", "vendor", "vendors", "lib",
    "out", "artifacts", "cache", "interfaces", "interface", "deps",
})

TARGET_BUDGET = 6
SOURCE_CHAR_CAP = 20_000
FUNCTION_BODY_CAP = 6_000
CONTEXT_CHAR_CAP = 8_000
FINDING_LIMIT = 8
DEADLINE_SECONDS = 280.0
PER_TARGET_SECONDS = 75.0
REFINE_RESERVE_SECONDS = 70.0
REQUEST_TIMEOUT = 150
REQUEST_RETRIES = 2
MAX_FILE_BYTES = 250_000
MIN_DESCRIPTION_CHARS = 80
MIN_IMPACT_CHARS = 40
MAX_RELATED_FILES = 4
MAX_HINTS_PER_TARGET = 8
MAX_REFINE_TARGETS = 3

# Terse impact labels that the AuditAgent scorer treats as "partially described
# consequences" (partial match, NOT a true positive). A complete impact is a
# full sentence naming who is harmed, what is lost, and how the attacker profits.
THIN_IMPACT_TOKENS = (
    "funds stolen", "fund stolen", "stolen", "drained", "loss of funds",
    "lose funds", "money stolen", "value stolen", "value lost", "fund loss",
    "privilege escalation", "dos", "denial of service", "insolvency",
    "theft", "loss", "drain", "stolen funds", "fund drain", "account drained",
)

PROJECT_ENV_KEYS = ("PROJECT_CODE", "PROJECT_DIR", "PROJECT_PATH", "PROJECT_ROOT")
PROJECT_FALLBACKS = ("/app/project_code", "/app/project", "/project", "/code", ".")

# Suspicion signals.
HOT_NAME_TERMS = (
    "vault", "router", "bridge", "proxy", "upgrade", "oracle", "govern",
    "treasury", "manager", "pool", "reward", "staking", "market", "reserve",
    "lend", "borrow", "collateral", "controller", "strategy", "auction",
    "swapper", "exchanger", "settlement", "custody", "admin", "owner",
    "guard", "registry", "factory", "beacon", "multicall", "permittable",
)
HOT_CONTENT_PATTERNS = tuple(
    map(re.compile, (
        r"\bdelegatecall\b", r"\.call\s*\(", r"\bcall\.value\b",
        r"\bselfdestruct\b", r"\btx\.origin\b", r"\bassembly\b",
        r"\becrecover\b", r"\bpermit\b", r"\bonlyOwner\b", r"\bonlyRole\b",
        r"\bhasRole\b", r"\bupgradeTo\b", r"\b_mint\b", r"\b_burn\b",
        r"\bwithdraw\b", r"\bredeem\b", r"\bliquidat", r"\bborrow\b",
        r"\brepay\b", r"\btransferFrom\b", r"\bsafeTransfer", r"\bunchecked\b",
        r"\breentran", r"\bflash", r"\bgetPrice\b", r"\blatestAnswer\b",
        r"\bslot0\b", r"\bnonce\b", r"\bsignature\b", r"\bskim\b", r"\bsync\b",
        r"\bpricePerShare\b", r"\bconvertTo\b", r"\bdeposit\b", r"\bswap\b",
        r"\bexecute\b", r"\bpull\b", r"\bpush\b", r"\bcreate2\b",
    ))
)

CONTRACT_HEADER = re.compile(
    r"\b(?:contract|library|abstract\s+contract|interface)\s+([A-Za-z_][A-Za-z0-9_]*)"
)
FUNCTION_HEADER = re.compile(
    r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)"
)
FUNCTION_SIG_OPEN = re.compile(
    r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)[^{;]*\{", re.DOTALL
)
RECEIVE_FALLBACK = re.compile(r"\b(?:receive|fallback)\s*\(\s*\)\s*(?:external|public)?[^\{]*\{")
IMPORT_LINE = re.compile(r'^\s*import\s+[^;]*?["\']([^"\']+)["\']', re.MULTILINE)
FALLBACK_IMPORT = re.compile(r'\bfrom\s+([A-Za-z0-9_./-]+)\s+import')

SYSTEM_PROMPT = (
    "You are a senior smart-contract security auditor hunting REAL, exploitable "
    "HIGH or CRITICAL vulnerabilities in Solidity / Vyper code. A finding counts "
    "only if an attacker can take a concrete action that steals funds, gains "
    "unauthorized privilege, bricks the protocol, or corrupts accounting. Ignore "
    "gas optimisations, style, missing events, and speculative issues with no "
    "working exploit path. Be precise about WHERE the bug lives (file, contract, "
    "function). When given HINTS, treat each as a lead to verify, not a confirmed "
    "bug. When given RELATED CONTEXT, reason about cross-contract interactions "
    "(oracles, callbacks, trusted callers, inherited state, shared storage)."
)


# ---------------------------------------------------------------------------
# project + source discovery
# ---------------------------------------------------------------------------
def resolve_project(project_dir: str | None) -> Path | None:
    candidates: list[str] = []
    if project_dir:
        candidates.append(project_dir)
    for key in PROJECT_ENV_KEYS:
        value = os.environ.get(key)
        if value:
            candidates.append(value)
    candidates.extend(PROJECT_FALLBACKS)
    for raw in candidates:
        try:
            root = Path(raw).expanduser().resolve()
        except (OSError, RuntimeError):
            continue
        if root.is_dir() and _contains_sources(root):
            return root
    return None


def _contains_sources(root: Path) -> bool:
    try:
        for path in root.rglob("*"):
            if path.is_file() and path.suffix.lower() in SOURCE_SUFFIXES:
                return True
    except OSError:
        return False
    return False


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def discover_sources(project_root: Path) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for path in sorted(project_root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        relative_parts = path.relative_to(project_root).parts
        if any(part.lower() in IGNORED_DIRS for part in relative_parts[:-1]):
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        content = read_text(path)
        if "function" not in content and "contract" not in content:
            continue
        contracts = CONTRACT_HEADER.findall(content)
        if not contracts:
            continue
        records.append({
            "path": path,
            "rel": path.relative_to(project_root).as_posix(),
            "content": content,
            "contracts": contracts,
            "score": _sus_score(path, content),
        })
    records.sort(key=lambda r: (-int(r["score"]), str(r["rel"])))
    return records


def _sus_score(path: Path, content: str) -> int:
    score = 0
    name = path.name.lower()
    posix = path.as_posix().lower()
    for term in HOT_NAME_TERMS:
        if term in name:
            score += 6
        elif term in posix:
            score += 2
    for pattern in HOT_CONTENT_PATTERNS:
        hits = len(pattern.findall(content))
        score += min(hits, 4) * 3
    score += min(content.count("function "), 20)
    if "constructor" in content:
        score += 2
    if "delegatecall" in content or ".call(" in content:
        score += 4
    return score


def collect_imports(target: dict[str, object], by_rel: dict[str, dict[str, object]]) -> str:
    """Pull up to MAX_RELATED_FILES directly-imported local files for context."""
    target_rel = str(target["rel"])
    target_content = str(target["content"])
    wanted: list[str] = []
    for match in IMPORT_LINE.finditer(target_content):
        wanted.append(match.group(1))
    for match in FALLBACK_IMPORT.finditer(target_content):
        wanted.append(match.group(1))
    chunks: list[str] = []
    taken = 0
    per_cap = max(800, CONTEXT_CHAR_CAP // max(1, MAX_RELATED_FILES))
    for imp in wanted:
        if taken >= MAX_RELATED_FILES:
            break
        if not imp or imp.startswith("@") or imp.startswith("https"):
            continue
        base = imp.rsplit("/", 1)[-1]
        if base.endswith(".sol"):
            base = base[:-4]
        for rel, rec in by_rel.items():
            if rel == target_rel:
                continue
            if rel.endswith(base) or Path(rel).name == imp.rsplit("/", 1)[-1]:
                text = str(rec["content"])[:per_cap]
                chunks.append(f"// related: {rel}\n{text}")
                taken += 1
                break
    return "\n\n".join(chunks)[:CONTEXT_CHAR_CAP] if chunks else ""


# ---------------------------------------------------------------------------
# function + line geometry
# ---------------------------------------------------------------------------
def function_name_at_offset(content: str, offset: int) -> str:
    last = "(module)"
    for match in FUNCTION_HEADER.finditer(content):
        if match.start() <= offset:
            last = match.group(1)
        else:
            break
    return last


def line_at_offset(content: str, offset: int) -> int:
    return content.count("\n", 0, offset) + 1


def extract_function_body(content: str, function_name: str) -> str | None:
    """Return a function's signature + full body via brace matching."""
    pattern = (
        rf"\bfunction\s+{re.escape(function_name)}\s*\([^)]*\)[^{{;]*\{{"
        if function_name != "(constructor)"
        else r"\bconstructor\s*\([^)]*\)[^{;]*\{"
    )
    match = re.search(pattern, content, re.DOTALL)
    if match is None:
        return None
    cursor = match.end() - 1
    depth = 1
    while depth > 0 and cursor < len(content) - 1:
        cursor += 1
        char = content[cursor]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
    return content[match.start():cursor + 1][:FUNCTION_BODY_CAP]


def valid_function_names(content: str) -> set[str]:
    return set(FUNCTION_HEADER.findall(content)) | {"constructor"}


def infer_line(content: str, function_name: str) -> int | None:
    if not function_name or function_name == "(module)":
        return None
    pattern = (
        rf"\bfunction\s+{re.escape(function_name)}\s*\("
        if function_name != "constructor"
        else r"\bconstructor\s*\("
    )
    match = re.search(pattern, content)
    if match is None:
        return None
    return content.count("\n", 0, match.start()) + 1


# ---------------------------------------------------------------------------
# static vulnerability hints (cheap regex detectors -> leads for the model)
# ---------------------------------------------------------------------------
HINT_DETECTORS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("tx.origin", re.compile(r"\btx\.origin\b"),
     "tx.origin used for auth (phishable)"),
    ("delegatecall", re.compile(r"\bdelegatecall\b"),
     "delegatecall (verify target / storage layout)"),
    ("selfdestruct", re.compile(r"\bselfdestruct\b"),
     "selfdestruct present (value redirection)"),
    ("ecrecover", re.compile(r"\becrecover\b"),
     "ecrecover (chainId / null sig / malleability)"),
    ("block.price", re.compile(r"block\.(timestamp|number|hash|difficulty)"),
     "block value usable as price/seed (manipulable)"),
    ("unchecked", re.compile(r"\bunchecked\s*\{"),
     "unchecked arithmetic block (overflow/underflow)"),
    ("assembly.call", re.compile(r"assembly\b[^}]*?\b(call|delegatecall|staticcall)\b"),
     "assembly external call (unchecked return value)"),
    ("create2", re.compile(r"\bcreate2\b"),
     "create2 (address-prediction / metaproxy)"),
    ("skim", re.compile(r"\b(?:skim|sync)\s*\("),
     "skim/sync (donation / accounting drift)"),
    ("balanceOf.self", re.compile(r"balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)"),
     "balanceOf(this) accounting (donation / sandwich)"),
)
WITHDRAW_TERMS = re.compile(
    r"\b(withdraw|redeem|claim|transfer|send|payOut|release|exit|unwrap)\s*\("
)
EXTERNAL_CALL = re.compile(r"\.(call|transfer|send)\s*\(?")
STATE_WRITE = re.compile(
    r"\b\w+\s*(?:=|\+=|-=|\*=|/=)(?!=)"
    r"|\]\s*(?:=|\+=|-=|\*=|/=)(?!=)"
    r"|\b(?:balances|_balances|shares|amounts|deposits|"
    r"userData|userBalance|balanceOf)\s*\[[^\]]+\]\s*(?:=|\+=|-=|\*=|/=)(?!=)"
)


def detect_static_hints(content: str) -> list[str]:
    """Return function+line leads for patterns that frequently hide real bugs."""
    hints: list[str] = []
    seen: set[str] = set()
    for _, pattern, message in HINT_DETECTORS:
        for match in pattern.finditer(content):
            fn = function_name_at_offset(content, match.start())
            line = line_at_offset(content, match.start())
            key = f"{fn}:{message}"
            if key in seen:
                continue
            seen.add(key)
            hints.append(f"`{fn}` line {line}: {message}")
            if len(hints) >= MAX_HINTS_PER_TARGET:
                return hints
    # CEI / reentrancy shape: external call followed shortly by a state write.
    for call in EXTERNAL_CALL.finditer(content):
        call_fn = function_name_at_offset(content, call.start())
        if not WITHDRAW_TERMS.search(content[max(0, call.start() - 200):call.start() + 1]):
            continue
        window = content[call.end():call.end() + 400]
        if STATE_WRITE.search(window):
            line = line_at_offset(content, call.start())
            key = f"{call_fn}:CEI"
            if key in seen:
                continue
            seen.add(key)
            hints.append(
                f"`{call_fn}` line {line}: external call precedes state write "
                "(reentrancy / checks-effects-interactions)"
            )
            if len(hints) >= MAX_HINTS_PER_TARGET:
                return hints
    return hints


def build_risk_map(content: str) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for match in FUNCTION_HEADER.finditer(content):
        name = match.group(1)
        window = content[match.start():match.start() + 600]
        risks = [
            label for label, hit in (
                ("external-call", ".call(" in window or "delegatecall" in window),
                ("value-transfer", bool(re.search(
                    r"\b(transfer|send|withdraw|redeem|transferFrom)\s*\(", window))),
                ("auth", "onlyOwner" in window or "onlyRole" in window or "hasRole" in window),
                ("unchecked", "unchecked" in window),
                ("assembly", "assembly" in window),
            )
            if hit
        ]
        if not risks:
            continue
        role = "external" if "external" in window or "public" in window else "internal"
        entries.append({"name": name, "role": role, "risks": risks})
        if len(entries) >= 16:
            break
    return entries


# ---------------------------------------------------------------------------
# inference
# ---------------------------------------------------------------------------
def call_model(inference_api: str | None, messages: list[dict[str, str]]) -> str:
    endpoint = (inference_api or os.environ.get("INFERENCE_API") or "").rstrip("/")
    if not endpoint:
        raise ValueError("INFERENCE_API is not configured")
    api_key = os.environ.get("INFERENCE_API_KEY", "").strip()
    body = json.dumps({
        "messages": messages,
        "response_format": {"type": "json_object"},
        "max_tokens": 8000,
    }).encode("utf-8")
    headers = {"Content-Type": "application/json", "x-inference-api-key": api_key}
    last_error: Exception | None = None
    for attempt in range(REQUEST_RETRIES + 1):
        try:
            request = urllib.request.Request(
                endpoint + "/inference", data=body, method="POST", headers=headers
            )
            with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
            return extract_content(payload)
        except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
            last_error = exc
            if attempt < REQUEST_RETRIES:
                time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"inference failed: {last_error}")


def extract_content(payload: dict) -> str:
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
        return "".join(
            part.get("text", "")
            for part in content
            if isinstance(part, dict) and part.get("type") == "text"
        )
    return ""


def parse_findings(content: str) -> list[dict[str, object]]:
    text = content.strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\n?", "", text)
        text = re.sub(r"\n?```$", "", text).strip()
    parsed: object = None
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        depth = 0
        if start != -1:
            for i in range(start, len(text)):
                depth += 1 if text[i] == "{" else -1 if text[i] == "}" else 0
                if depth == 0:
                    try:
                        parsed = json.loads(text[start:i + 1])
                    except json.JSONDecodeError:
                        parsed = None
                    break
    if not isinstance(parsed, dict):
        return []
    items = parsed.get("findings") or parsed.get("vulnerabilities") or parsed.get("candidates")
    return [it for it in items if isinstance(it, dict)] if isinstance(items, list) else []


# ---------------------------------------------------------------------------
# per-target audit + matcher-shaped normalization
# ---------------------------------------------------------------------------
def build_audit_prompt(
    target: dict[str, object],
    related: str,
    risk_map: list[dict[str, object]],
    hints: list[str],
) -> str:
    rel = str(target["rel"])
    full_content = str(target["content"])
    contracts = ", ".join(target["contracts"][:6]) or "(unnamed)"
    truncated = len(full_content) > SOURCE_CHAR_CAP
    source_view = full_content[:SOURCE_CHAR_CAP]
    # Truncation recovery: append full bodies of risk-flagged fns beyond the cap.
    if truncated:
        tail_funcs: list[str] = []
        for entry in risk_map:
            name = str(entry["name"])
            body = extract_function_body(full_content, name)
            if body and full_content.find("function " + name) >= SOURCE_CHAR_CAP:
                tail_funcs.append(f"// (beyond source view) {name}\n{body}")
        if tail_funcs:
            source_view += "\n\n" + "\n\n".join(tail_funcs)[:SOURCE_CHAR_CAP // 2]
    risk_lines = "\n".join(
        f"- {entry['name']} [{entry['role']}]: {', '.join(entry['risks'])}"
        for entry in risk_map
    ) or "(none detected)"
    hint_lines = "\n".join(f"- {hint}" for hint in hints) or "(no static leads)"
    parts = [
        "Audit this file for REAL HIGH/CRITICAL vulnerabilities. Return STRICT json.",
        f"File path (use EXACTLY as `file`): {rel}",
        f"Contracts defined here: {contracts}",
        "Static leads (VERIFY each; discard if not actually exploitable):",
        hint_lines,
        "Function risk map:",
        risk_lines,
        "",
        "Think through access control, external-call side effects and ordering "
        "(reentrancy), oracle/price manipulation, arithmetic (unchecked / scaling "
        "/ rounding), upgrade/init authorization, and cross-contract trust when "
        "RELATED CONTEXT is provided.",
        "",
        "SCORING (read carefully): a finding is accepted ONLY if it (1) names the "
        "correct contract, (2) names the correct function, (3) accurately describes "
        "the core issue, AND (4) accurately describes the FULL consequences. If the "
        "consequences are missing or vague the finding counts as a PARTIAL match and "
        "scores zero. Therefore `impact` MUST be one complete sentence naming WHO is "
        "harmed (depositors / the protocol / LPs), WHAT they lose (funds / ownership "
        "/ accounting integrity), and HOW the attacker profits. Never write a terse "
        "label like 'funds stolen'; write the full exploit outcome, e.g. 'An attacker "
        "reenters withdraw() before balances update, draining all depositor funds and "
        "transferring their value to themselves.' `mechanism` MUST be a concrete "
        "precondition -> attacker action -> code effect chain.",
        "",
        'Return json of this exact shape: {"findings": [{'
        '"title": "<Contract>.<function> - <specific bug>", '
        '"contract": "<exact ContractName declared in source>", '
        '"function": "<functionName the bug is in; must exist in source>", '
        '"file": "' + rel + '", '
        '"severity": "high" or "critical", '
        '"mechanism": "<precondition -> attacker action -> code effect>", '
        '"impact": "<full sentence: who is harmed, what is lost, how attacker profits>", '
        '"description": "<file + contract + function, then mechanism, '
        'then the full impact>"}]}',
        "Rules: at most 2 findings; each MUST name a real function present in the "
        'source; if nothing is genuinely exploitable return {"findings": []}.',
        f"----- SOURCE{' (truncated, risk fns appended)' if truncated else ''} -----",
        source_view,
    ]
    if related:
        parts += ["", "----- RELATED CONTEXT (read-only; reason about interactions) -----",
                  related]
    return "\n".join(parts)


def build_refine_prompt(
    target: dict[str, object],
    findings: list[dict[str, object]],
) -> str:
    rel = str(target["rel"])
    content = str(target["content"])
    items: list[str] = []
    for finding in findings:
        fn = str(finding.get("function") or "")
        body = extract_function_body(content, fn) if fn else None
        items.append(
            "Candidate:\n"
            f"  function: {fn}\n"
            f"  severity: {finding.get('severity')}\n"
            f"  mechanism: {finding.get('mechanism', '')}\n"
            f"  impact: {finding.get('impact', '')}\n"
            f"  function body:\n{body or '(not found)'}"
        )
    return (
        "For each candidate vulnerability below, decide if it is a REAL exploitable "
        "HIGH/CRITICAL bug given the function body. Keep only the ones with a "
        "working exploit path. CRITICAL: rewrite `impact` as ONE COMPLETE sentence "
        "naming who is harmed, what they lose, and how the attacker profits — a "
        "terse label like 'funds stolen' makes the finding count as only a partial "
        "match (zero score). Refine `mechanism` into a concrete precondition -> "
        "action -> effect chain. Set keep=false if the bug is not actually "
        "exploitable from this function body."
        f" Source file: {rel}\n\n"
        + "\n\n".join(items)
        + '\n\nReturn json: {"findings": [{"function": "...", "severity": "...", '
        '"mechanism": "<precondition -> action -> effect>", '
        '"impact": "<full consequence sentence>", "keep": true|false}]}'
    )


def impact_is_thin(impact: str) -> bool:
    """Whether an impact is a terse label rather than a full consequence sentence.

    The AuditAgent scorer awards a true positive only when the consequences are
    "accurately described"; terse labels (e.g. "funds stolen") yield a partial
    match at best, which scores zero. A complete impact is a sentence naming who
    is harmed, what is lost, and how the attacker profits.
    """
    text = impact.strip().lower().rstrip(".")
    if len(text) < MIN_IMPACT_CHARS:
        return True
    bare = text.removeprefix("impact:").strip()
    if bare in THIN_IMPACT_TOKENS:
        return True
    return False


def shape_finding(
    raw: dict[str, object],
    target: dict[str, object],
    valid_fns: set[str],
) -> dict[str, object] | None:
    severity = str(raw.get("severity") or "").strip().lower()
    if severity not in {"high", "critical"}:
        return None
    contracts = target["contracts"]
    contract = str(raw.get("contract") or (contracts[0] if contracts else "")).strip()
    function = str(raw.get("function") or "").strip().strip("()")
    if function and valid_fns and function not in valid_fns:
        function = function.split(".")[-1]
        if function not in valid_fns:
            function = ""
    file_path = str(raw.get("file") or target["rel"]).strip() or str(target["rel"])
    mechanism = str(raw.get("mechanism") or "").strip().rstrip(".")
    impact = str(raw.get("impact") or "").strip().rstrip(".")
    description = str(raw.get("description") or "").strip()
    title = str(raw.get("title") or "").strip()
    location = (
        f"{contract}.{function}" if contract and function else (contract or function)
    )
    if not title:
        title = f"{location} - {severity} issue" if location else "High-severity issue"
    elif location and location.lower() not in title.lower():
        title = f"{location} - {title}"

    # Canonical description so the scorer's LLM sees every match criterion
    # (contract + function + mechanism + impact) in a standard layout. The
    # scorer reads this description to decide exact vs partial vs no match,
    # so surfacing all four signals maximizes the chance of an exact match.
    segments = [f"In `{file_path}`"]
    if contract:
        segments.append(f"contract `{contract}`")
    if function:
        segments.append(f"function `{function}()`")
    location_header = ", ".join(segments) + "."
    canonical = location_header
    if mechanism:
        canonical += f" Mechanism: {mechanism}."
    if impact:
        canonical += f" Impact: {impact}."

    if not mechanism and not impact:
        # Nothing concrete to match on; only keep if the model already wrote a
        # rich description that embeds both the issue and its consequences.
        if len(description) < MIN_DESCRIPTION_CHARS:
            return None
        final_description = description
    elif (
        len(description) >= MIN_DESCRIPTION_CHARS
        and function
        and function in description
        and contract
        and contract.lower() in description.lower()
        and not impact_is_thin(impact)
    ):
        # The model's description already carries all four signals; prefer it
        # but guarantee the impact is stated, not just implied.
        if impact and impact.lower() not in description.lower():
            final_description = canonical + " " + description
        else:
            final_description = description
    else:
        # Rebuild so all four match signals are explicit and ordered.
        final_description = canonical

    if len(final_description) < MIN_DESCRIPTION_CHARS:
        return None

    line = raw.get("line")
    if not isinstance(line, int):
        line = infer_line(str(target["content"]), function)

    # Thin impact = partial-match risk; demote confidence so dedup/ranking and
    # the FINDING_LIMIT naturally prefer findings with complete consequences.
    confidence = 0.90 if severity == "critical" else 0.80
    if impact_is_thin(impact):
        confidence -= 0.15

    return {
        "title": title[:200],
        "description": final_description,
        "severity": severity,
        "file": file_path,
        "function": function,
        "line": line,
        "mechanism": mechanism,
        "impact": impact,
        "confidence": round(confidence, 2),
    }


def apply_refinement(
    raw: dict[str, object],
    original: dict[str, object],
) -> dict[str, object] | None:
    if not raw.get("keep", True):
        return None
    keep = {**original}
    for field in ("severity", "mechanism", "impact"):
        value = str(raw.get(field) or "").strip().rstrip(".")
        if value:
            keep[field] = value
    if keep.get("severity", "high") not in {"high", "critical"}:
        return None
    # Rebuild the description so it reflects the refined mechanism + impact.
    # The scorer reads the description to decide exact vs partial, so a stale
    # pre-refinement description would throw away the refinement's work.
    file_path = str(keep.get("file") or "")
    contract = str(keep.get("contract") or "")
    function = str(keep.get("function") or "")
    mechanism = str(keep.get("mechanism") or "").rstrip(".")
    impact = str(keep.get("impact") or "").rstrip(".")
    segments = [f"In `{file_path}`"]
    if contract:
        segments.append(f"contract `{contract}`")
    if function:
        segments.append(f"function `{function}()`")
    canonical = ", ".join(segments) + "."
    if mechanism:
        canonical += f" Mechanism: {mechanism}."
    if impact:
        canonical += f" Impact: {impact}."
    keep["description"] = canonical
    confidence = 0.92 if keep.get("severity") == "critical" else 0.82
    if impact_is_thin(impact):
        confidence -= 0.15
    keep["confidence"] = round(confidence, 2)
    return keep


def deduplicate(findings: list[dict[str, object]]) -> list[dict[str, object]]:
    seen: set[tuple[str, str]] = set()
    ordered = sorted(
        findings,
        key=lambda f: (str(f["severity"]) == "critical", float(f["confidence"])),
        reverse=True,
    )
    output: list[dict[str, object]] = []
    for finding in ordered:
        key = (
            str(finding["file"]).lower(),
            str(finding["function"]).lower() or str(finding["title"]).lower()[:40],
        )
        if key in seen:
            continue
        seen.add(key)
        output.append(finding)
    return output


# ---------------------------------------------------------------------------
# entrypoint
# ---------------------------------------------------------------------------
def agent_main(
    project_dir: str | None = None,
    inference_api: str | None = None,
) -> dict:
    findings: list[dict[str, object]] = []
    project_root = resolve_project(project_dir)
    if project_root is None:
        return {"vulnerabilities": findings}

    deadline = time.monotonic() + DEADLINE_SECONDS
    records = discover_sources(project_root)
    if not records:
        return {"vulnerabilities": findings}
    by_rel = {str(record["rel"]): record for record in records}

    # Per-target deep audit.
    per_target: list[tuple[dict[str, object], list[dict[str, object]]]] = []
    for target in records[:TARGET_BUDGET]:
        if time.monotonic() > deadline:
            break
        target_started = time.monotonic()
        related = collect_imports(target, by_rel)
        risk_map = build_risk_map(str(target["content"]))
        hints = detect_static_hints(str(target["content"]))
        prompt = build_audit_prompt(target, related, risk_map, hints)
        try:
            content = call_model(
                inference_api,
                [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
            )
        except (RuntimeError, ValueError):
            continue
        if time.monotonic() - target_started > PER_TARGET_SECONDS:
            continue
        valid_fns = valid_function_names(str(target["content"]))
        shaped = [
            shaped
            for raw in parse_findings(content)
            if (shaped := shape_finding(raw, target, valid_fns)) is not None
        ]
        if shaped:
            per_target.append((target, shaped))

    # Optional refinement pass to lift precision (only if time remains).
    refined: list[dict[str, object]] = []
    refinable = per_target[:MAX_REFINE_TARGETS]
    for target, shaped in refinable:
        if time.monotonic() > deadline - REFINE_RESERVE_SECONDS or len(shaped) < 2:
            refined.extend(shaped)
            continue
        try:
            content = call_model(
                inference_api,
                [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": build_refine_prompt(target, shaped)},
                ],
            )
        except (RuntimeError, ValueError):
            refined.extend(shaped)
            continue
        decisions = {str(d.get("function")): d for d in parse_findings(content)}
        if not decisions:
            refined.extend(shaped)
            continue
        for finding in shaped:
            decision = decisions.get(str(finding.get("function")))
            if decision is None:
                refined.append(finding)
                continue
            applied = apply_refinement(decision, finding)
            if applied is not None:
                refined.append(applied)

    # Carry forward any findings from targets we didn't refine.
    for target, shaped in per_target[MAX_REFINE_TARGETS:]:
        refined.extend(shaped)

    findings = deduplicate(refined)[:FINDING_LIMIT]
    return {"vulnerabilities": findings}


if __name__ == "__main__":  # local smoke check only (no network)
    import sys

    print(json.dumps(agent_main(sys.argv[1] if len(sys.argv) > 1 else None), indent=2))
