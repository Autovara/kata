from __future__ import annotations

"""SN60 / Bitsec miner agent — king-superset, reliability-first, multi-language.

Design rationale
-----------------
The duel comparator (kata/challenge.py::sn60_variant_rank) ranks by the tuple
``(aggregated_score, true_positives, precision, f1, -invalid_runs)`` with a
*strict* ``>`` and ties keeping the king. Because ``aggregated_score`` is
``true_positives / total_expected`` and ``total_expected`` is identical for the
king and the candidate on a fixed benchmark, the first two tuple elements are
perfectly monotonic: the contest reduces to **more true positives wins; equal
true positives → higher precision (fewer false positives) wins.**

So the only two ways to beat the reigning king are:
  (1) find at least one true positive the king does not, or
  (2) match the king's true positives with strictly fewer false positives.

The king scans only ``.sol``/``.vy`` and only its top-4 files, 2 findings each.
That leaves two structural blind spots where the king scores a guaranteed zero
and (1) is therefore pure, unrecoverable upside:
  * non-EVM projects — CosmWasm/Rust, Move, Cairo — which are a real slice of
    the pinned benchmark and which a Solidity-only scanner cannot ever touch;
  * the 5th-and-deeper suspicious files of any project, past the king's 4-file
    cap.

This agent is a strict *superset* of the king rather than a re-shuffle of it:

  1. It first locks in the king's exact lever — the top-N Solidity files,
     analyzed depth-first, whole-file, matcher-shaped — so on a pure-Solidity
     project it never does worse than the king.
  2. Only then, with the remaining time budget, it extends into the king's
     blind spots (non-Solidity files first, since the king is a guaranteed zero
     there, then deeper Solidity files), each guarded by the wall-clock
     deadline so the high-value floor work is always completed first.
  3. It runs strictly SEQUENTIALLY. The prior multi-language iteration fanned
     inference calls out across a thread pool; against the sandbox's slow,
     shared, single-inference-proxy backend on a 0.25-CPU container that risks
     concurrent-request timeouts that silently drop findings — including the
     Solidity findings the king reliably banks. Sequential, deadline-checked
     execution is exactly how the (winning) king runs, and it makes the floor
     deterministic.
  4. It keeps the king's tight per-file discipline (2 findings/file) so that in
     the rare exact-tie case its precision is not diluted, while allowing a
     generous total ceiling so a real extra true positive is never truncated.

Self-contained (stdlib only). Reads source from ``project_dir`` (defaults to
the Bitsec mount ``/app/project_code``) and reaches the model only through the
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
EXCLUDED_DIR_NAMES = {
    "test", "tests", "mock", "mocks", "example", "examples", "script",
    "scripts", "broadcast", "node_modules", "vendor", "vendors", "lib",
    "out", "artifacts", "cache", "interfaces", "interface",
    # non-Solidity build/dependency noise
    "target", "build", ".build", "deps", "_build", ".aptos", ".move",
}
# Filename (stem) fragments that mark a source file as test/mock code even when
# it lives alongside real logic in the same directory (common in Rust/Move/
# Cairo crates, e.g. `contract_tests.rs`, `multi_tests.rs`, `test_utils.move`).
EXCLUDED_STEM_FRAGMENTS = ("test", "mock", "fixture")

# Terms suspicious across most account/asset-holding systems regardless of
# source language.
COMMON_SUSPICIOUS_TERMS = (
    "vault", "router", "bridge", "proxy", "upgrade", "oracle", "govern",
    "treasury", "manager", "pool", "reward", "staking", "market", "reserve",
    "lend", "borrow", "collateral", "controller", "strategy", "auction",
    "token", "admin", "owner", "fee", "price", "swap", "liquidity", "mint",
    "burn", "withdraw", "deposit", "claim", "registry", "domain",
)


class LangConfig:
    __slots__ = (
        "label", "suffixes", "unit_pattern", "function_pattern",
        "content_patterns", "import_pattern", "focus", "is_primary",
    )

    def __init__(self, label, suffixes, unit_pattern, function_pattern,
                 content_patterns, import_pattern, focus, is_primary):
        self.label = label
        self.suffixes = suffixes
        self.unit_pattern = unit_pattern
        self.function_pattern = function_pattern
        self.content_patterns = content_patterns
        self.import_pattern = import_pattern
        self.focus = focus
        self.is_primary = is_primary  # Solidity/Vyper — the king's own turf


LANG_CONFIGS: list[LangConfig] = [
    LangConfig(
        label="contract",
        suffixes=(".sol", ".vy"),
        unit_pattern=re.compile(r"\b(?:contract|library|abstract\s+contract)\s+([A-Za-z_][A-Za-z0-9_]*)"),
        function_pattern=re.compile(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\("),
        content_patterns=(
            r"\bdelegatecall\b", r"\.call\s*\{", r"\bcall\.value\b", r"\bselfdestruct\b",
            r"\btx\.origin\b", r"\bassembly\b", r"\becrecover\b", r"\bpermit\b",
            r"\bonlyOwner\b", r"\bonlyRole\b", r"\bupgradeTo\b", r"\b_mint\b", r"\b_burn\b",
            r"\bredeem\b", r"\bliquidat", r"\brepay\b",
            r"\btransferFrom\b", r"\bsafeTransfer", r"\bunchecked\b", r"\breentran",
            r"\bflash", r"\bgetPrice\b", r"\blatestAnswer\b", r"\bslot0\b", r"\bnonce\b",
            r"\bsignature\b", r"\btotalSupply\b", r"\bbalanceOf\b",
        ),
        import_pattern=re.compile(r'^\s*import\b[^;]*?["\']([^"\']+)["\']', re.MULTILINE),
        focus=(
            "access control, external-call/reentrancy ordering, arithmetic and rounding, "
            "oracle/price manipulation, upgrade/initializer paths, and signature/permit replay"
        ),
        is_primary=True,
    ),
    LangConfig(
        label="Rust module",
        suffixes=(".rs",),
        unit_pattern=re.compile(r"\b(?:pub\s+)?(?:struct|enum|mod)\s+([A-Za-z_][A-Za-z0-9_]*)"),
        function_pattern=re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*[<(]"),
        content_patterns=(
            r"#\[entry_point\]", r"\bexecute\b", r"\binstantiate\b", r"\bmigrate\b",
            r"\binfo\.sender\b", r"\bMessageInfo\b", r"\bassert_eq!\s*\(\s*info", r"\bonly_owner\b",
            r"\bUint128\b", r"\bDecimal\b", r"\bcheck_owner\b",
            r"\bunwrap\s*\(\s*\)", r"\bexpect\s*\(", r"\bas\s+u(?:8|16|32|64|128)\b",
            r"\bchecked_(?:add|sub|mul|div)\b", r"\bsaturating_", r"\bwrapping_",
            r"unsafe\s*\{", r"\bself_destruct\b", r"\bfee\b", r"\bslippage\b",
            r"\bBankMsg\b", r"\bWasmMsg\b", r"\bquery\b", r"\breply\b",
        ),
        import_pattern=re.compile(r"^\s*use\s+([A-Za-z0-9_:]+)\s*;", re.MULTILINE),
        focus=(
            "sender/capability access control (info.sender / only-owner checks on execute "
            "message variants), integer overflow and unsafe casts in balance or fee math, "
            "message-dispatch reentrancy (execute/reply callbacks), and unchecked external "
            "message construction (BankMsg/WasmMsg). The entry points are execute/instantiate/"
            "query dispatching over a message enum — audit each handler variant's authorization"
        ),
        is_primary=False,
    ),
    LangConfig(
        label="Move module",
        suffixes=(".move",),
        unit_pattern=re.compile(r"\bmodule\s+([A-Za-z_][A-Za-z0-9_:]*)"),
        function_pattern=re.compile(r"\b(?:public\s+)?(?:entry\s+)?fun\s+([A-Za-z_][A-Za-z0-9_]*)\s*[<(]"),
        content_patterns=(
            r"\bpublic\s+entry\s+fun\b", r"\bsigner\b", r"\bassert!\s*\(",
            r"\bhas\s+key\b", r"\bhas\s+store\b", r"\bmove_to\b", r"\bmove_from\b",
            r"\bborrow_global_mut\b", r"\bborrow_global\b", r"\bcoin::", r"\bwithdraw\b",
            r"\bdeposit\b", r"\bmint\b", r"\bburn\b", r"\btimestamp\b", r"\bexpiration\b",
        ),
        import_pattern=re.compile(r"^\s*use\s+([A-Za-z0-9_:]+)\s*;", re.MULTILINE),
        focus=(
            "capability/resource leakage (who can call public entry functions and acquire "
            "resources via borrow_global_mut), missing assert! authorization and bounds checks, "
            "signer/address confusion, and expiration or accounting arithmetic errors"
        ),
        is_primary=False,
    ),
    LangConfig(
        label="Cairo contract",
        suffixes=(".cairo",),
        unit_pattern=re.compile(r"\bmod\s+([A-Za-z_][A-Za-z0-9_]*)"),
        function_pattern=re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*[<(]"),
        content_patterns=(
            r"#\[external", r"#\[view", r"#\[storage", r"\bget_caller_address\b",
            r"\bassert\s*\(", r"\bstorage_read\b", r"\bstorage_write\b",
            r"\bfelt252\b", r"\bU256\b", r"\bfee\b", r"\bprice\b", r"\bposition\b",
        ),
        import_pattern=re.compile(r"^\s*use\s+([A-Za-z0-9_:]+)\s*;", re.MULTILINE),
        focus=(
            "caller-address access control on #[external] entry points, felt/u256 "
            "overflow-underflow, storage variable corruption, and signed-price or "
            "position-accounting manipulation"
        ),
        is_primary=False,
    ),
    LangConfig(
        label="Go module",
        suffixes=(".go",),
        unit_pattern=re.compile(r"\btype\s+([A-Za-z_][A-Za-z0-9_]*)\s+struct\b"),
        function_pattern=re.compile(r"\bfunc\s+(?:\([^)]*\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\("),
        content_patterns=(
            r"\bKeeper\b", r"\bHandler\b", r"\bMsgServer\b", r"\bBankKeeper\b",
            r"\bsdk\.Coins?\b", r"\bsdk\.Int\b", r"\bsdk\.Dec\b", r"\bmust", r"\bpanic\(",
            r"\bAuthority\b", r"\bGovernance\b", r"\bValidateBasic\b",
        ),
        import_pattern=re.compile(r'"\s*([A-Za-z0-9_./-]+)"'),
        focus=(
            "module keeper access control, coin/decimal arithmetic, message validation "
            "(ValidateBasic) gaps, and governance/authority bypass"
        ),
        is_primary=False,
    ),
]

LANG_BY_SUFFIX: dict[str, LangConfig] = {
    suf: cfg for cfg in LANG_CONFIGS for suf in cfg.suffixes
}

# --- budgets (per-project container: 512MB / 0.25 CPU, agent self-limited) ---
MAX_FILE_BYTES = 200_000
KING_FLOOR_TARGETS = 4         # top Solidity files analyzed first (the king's proven depth)
MAX_TOTAL_TARGETS = 9          # hard ceiling on files we will ever attempt in one run
MAX_CONTRACT_CHARS = 16_000
MAX_RELATED_CHARS = 5_000
MAX_FINDINGS_PER_FILE = 2      # king-parity per-file discipline (protects the precision tiebreak)
MAX_FINDINGS = 14              # generous total ceiling so a real extra TP is never truncated
MAX_RUNTIME_SECONDS = 200.0    # match the king's proven, safe wall-clock budget
MIN_SECONDS_PER_CALL = 18.0    # do not start a new analysis with less than this left
REQUEST_TIMEOUT_SECONDS = 150
MAX_RETRIES = 2


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
            if path.is_file() and path.suffix.lower() in LANG_BY_SUFFIX:
                return True
    except OSError:
        return False
    return False


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _score_source(path: Path, content: str, cfg: LangConfig) -> int:
    score = 0
    name = path.name.lower()
    posix = path.as_posix().lower()
    for term in COMMON_SUSPICIOUS_TERMS:
        if term in name:
            score += 6
        elif term in posix:
            score += 2
    for pattern in cfg.content_patterns:
        hits = len(re.findall(pattern, content, flags=re.IGNORECASE))
        score += min(hits, 4) * 3
    fn_count = len(cfg.function_pattern.findall(content))
    score += min(fn_count, 20)
    return score


def _discover_lang(project_root: Path, cfg: LangConfig) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for path in sorted(project_root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in cfg.suffixes:
            continue
        if any(part.lower() in EXCLUDED_DIR_NAMES for part in path.relative_to(project_root).parts[:-1]):
            continue
        stem_lower = path.stem.lower()
        if any(frag in stem_lower for frag in EXCLUDED_STEM_FRAGMENTS):
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        content = _read_text(path)
        if not content.strip():
            continue
        units = cfg.unit_pattern.findall(content)
        fns = cfg.function_pattern.findall(content)
        if not fns:
            continue
        records.append(
            {
                "path": path,
                "rel": path.relative_to(project_root).as_posix(),
                "content": content,
                "units": units,
                "lang": cfg,
                "score": _score_source(path, content, cfg),
            }
        )
    records.sort(key=lambda r: (-int(r["score"]), str(r["rel"])))
    return records


def _select_targets(project_root: Path) -> list[dict[str, object]]:
    """Order targets so the king's proven floor is always analyzed first, then
    the king's structural blind spots (non-Solidity first, then deeper Solidity)
    fill whatever wall-clock budget remains.

    On a pure-Solidity project this reduces to the king's own top-N-files
    selection, so the candidate never scores below the king there. On a project
    the king cannot read at all (pure Rust/Move/Cairo) the whole budget goes to
    that language — exactly the recall the king structurally forfeits.
    """
    primary: list[dict[str, object]] = []
    secondary: list[dict[str, object]] = []
    for cfg in LANG_CONFIGS:
        records = _discover_lang(project_root, cfg)
        if not records:
            continue
        if cfg.is_primary:
            primary.extend(records)
        else:
            secondary.extend(records)
    primary.sort(key=lambda r: (-int(r["score"]), str(r["rel"])))
    secondary.sort(key=lambda r: (-int(r["score"]), str(r["rel"])))

    # 1) King floor: the top Solidity files, depth-first, banked before anything
    #    speculative is attempted.
    floor = primary[:KING_FLOOR_TARGETS]
    # 2) King blind spots, highest marginal value first: every non-Solidity file
    #    (the king is a guaranteed zero there) ahead of the 5th+ Solidity files.
    rest = secondary + primary[KING_FLOOR_TARGETS:]
    ordered = floor + rest
    return ordered[:MAX_TOTAL_TARGETS]


def _related_source(target: dict[str, object], by_rel: dict[str, dict[str, object]]) -> str | None:
    """Best-effort: pull one directly-imported local file for extra context."""
    path = target["path"]
    assert isinstance(path, Path)
    cfg: LangConfig = target["lang"]  # type: ignore[assignment]
    for match in cfg.import_pattern.finditer(str(target["content"])):
        imp = match.group(1)
        if not imp:
            continue
        base = imp.rsplit("/", 1)[-1].rsplit("::", 1)[-1].rsplit(".", 1)[-1]
        if len(base) < 3:
            continue
        for rel, rec in by_rel.items():
            if rel == target["rel"]:
                continue
            if base.lower() in rel.lower():
                text = str(rec["content"])
                return f"// related import: {rel}\n{text[:MAX_RELATED_CHARS]}"
    return None


# ---------------------------------------------------------------------------
# inference
# ---------------------------------------------------------------------------
def _post_inference(
    inference_api: str | None,
    messages: list[dict[str, str]],
    timeout: float = REQUEST_TIMEOUT_SECONDS,
) -> str:
    endpoint = (inference_api or os.environ.get("INFERENCE_API") or "").rstrip("/")
    if not endpoint:
        raise ValueError("INFERENCE_API is not configured.")
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
                time.sleep(2 * (attempt + 1))
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
def _build_prompt(target: dict[str, object], related: str | None) -> str:
    cfg: LangConfig = target["lang"]  # type: ignore[assignment]
    rel = target["rel"]
    units = ", ".join(target["units"][:6]) or "(unnamed)"
    content = str(target["content"])[:MAX_CONTRACT_CHARS]
    truncated = " (truncated)" if len(str(target["content"])) > MAX_CONTRACT_CHARS else ""
    parts = [
        f"Audit this {cfg.label} source file for real HIGH/CRITICAL security vulnerabilities.\n",
        f"File path (use EXACTLY this as `file`): {rel}",
        f"{cfg.label.capitalize()}s / units defined here: {units}\n",
        f"Focus especially on: {cfg.focus}.\n",
        "Think through the protocol logic, access control, external calls, "
        "accounting/oracle math, and upgrade/init paths. Report ONLY issues with "
        "a concrete exploit path and material impact.\n",
        "Return STRICT JSON, no prose, of this exact shape:",
        '{"findings": [{'
        f'"title": "<{cfg.label}>.<function> — <specific bug>", '
        f'"contract": "<{cfg.label} or unit name>", '
        '"function": "<functionName the bug is in>", '
        '"file": "' + str(rel) + '", '
        '"line": <int or null>, '
        '"severity": "high|critical", '
        '"mechanism": "<how an attacker triggers it: precondition -> action -> effect>", '
        '"impact": "<concrete consequence: funds stolen / privilege escalation / DoS / insolvency>", '
        '"description": "<2-4 sentences naming the file, unit and function, then the mechanism and impact>"'
        "}]}",
        f"Rules: at most {MAX_FINDINGS_PER_FILE} findings; each MUST name the real function it lives "
        'in; if nothing is genuinely exploitable, return {"findings": []}. Do not '
        "invent functions or files that are not in the source below.\n",
        f"----- SOURCE{truncated} -----",
        content,
    ]
    if related:
        parts += ["\n----- RELATED CONTEXT (read-only) -----", related[:MAX_RELATED_CHARS]]
    return "\n".join(parts)


def _system_prompt(cfg: LangConfig) -> str:
    return (
        f"You are a senior {cfg.label.split()[0]} smart-contract security auditor. "
        "You find only REAL, exploitable HIGH or CRITICAL vulnerabilities — logic "
        "flaws that let an attacker steal funds, escalate privilege, brick the "
        "protocol, or corrupt accounting. You ignore gas, style, missing events, "
        "and speculative issues with no concrete exploit path. You are precise "
        "about WHERE the bug is."
    )


def _valid_functions(content: str, cfg: LangConfig) -> set[str]:
    return set(cfg.function_pattern.findall(content))


def _normalize(
    raw: dict[str, object], target: dict[str, object], valid_fns: set[str]
) -> dict[str, object] | None:
    severity = str(raw.get("severity") or "").strip().lower()
    if severity not in {"high", "critical"}:
        return None
    units = target["units"]
    contract = str(raw.get("contract") or (units[0] if units else "")).strip()
    function = str(raw.get("function") or "").strip().strip("()")
    if function and valid_fns and function not in valid_fns:
        function = function.split(".")[-1].split("::")[-1]
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
            where += f", `{contract}`"
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


def _analyze_target(
    target: dict[str, object],
    by_rel: dict[str, dict[str, object]],
    inference_api: str | None,
    timeout: float,
) -> list[dict[str, object]]:
    cfg: LangConfig = target["lang"]  # type: ignore[assignment]
    related = _related_source(target, by_rel)
    prompt = _build_prompt(target, related)
    try:
        content = _post_inference(
            inference_api,
            [
                {"role": "system", "content": _system_prompt(cfg)},
                {"role": "user", "content": prompt},
            ],
            timeout=timeout,
        )
    except (RuntimeError, ValueError):
        return []
    valid_fns = _valid_functions(str(target["content"]), cfg)
    out: list[dict[str, object]] = []
    for raw in _parse_findings(content):
        norm = _normalize(raw, target, valid_fns)
        if norm is not None:
            out.append(norm)
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
    targets = _select_targets(project_root)
    if not targets:
        return {"vulnerabilities": findings}
    by_rel = {str(t["rel"]): t for t in targets}

    # Strictly sequential, deadline-guarded — the king's proven Solidity floor is
    # attempted first (targets are ordered king-floor-first), and each further
    # blind-spot file is only started if enough wall-clock remains to finish it.
    collected: list[dict[str, object]] = []
    for target in targets:
        remaining = deadline - time.monotonic()
        if remaining < MIN_SECONDS_PER_CALL:
            break
        call_timeout = min(REQUEST_TIMEOUT_SECONDS, max(remaining - 2.0, 1.0))
        collected.extend(_analyze_target(target, by_rel, inference_api, call_timeout))

    findings = _dedupe(collected)[:MAX_FINDINGS]
    return {"vulnerabilities": findings}


if __name__ == "__main__":  # local smoke check only (no network)
    import sys

    print(json.dumps(agent_main(sys.argv[1] if len(sys.argv) > 1 else None), indent=2))
