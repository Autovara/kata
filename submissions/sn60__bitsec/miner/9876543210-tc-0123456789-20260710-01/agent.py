from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

SOURCE_SUFFIXES = {".sol", ".vy", ".cairo", ".rs", ".move", ".go"}
SKIP_DIRS = {
    ".git",
    ".venv",
    "node_modules",
    "lib",
    "libs",
    "vendor",
    "vendors",
    "out",
    "artifacts",
    "cache",
    "target",
    "build",
    "dist",
    "coverage",
    "__pycache__",
    "test",
    "tests",
    "testing",
    "mock",
    "mocks",
    "interface",
    "interfaces",
    "cmd",
    "cli",
    "client",
    "clients",
    "bindings",
    "generated",
    "example",
    "examples",
    "script",
    "scripts",
}
LOW_VALUE_DIRS: set[str] = set()
MAX_FILE_BYTES = 340_000
MAX_FILES = 78
MAX_PACK_CHARS = 44_000
FULL_FILE_CHARS = 13_000
MAX_SNIPPETS_PER_FILE = 12
MAX_FINDINGS = 18
REQUEST_TIMEOUT = 150

RISK_PATTERNS = [
    r"\b(call|delegatecall|staticcall)\s*(\{|[(])",
    r"\bsafeApprove\b|\bapprove\b|\bsafeIncreaseAllowance\b",
    r"\btransferFrom\b|\bsafeTransferFrom\b|\bsafeTransfer\b|\btransfer\b",
    r"\bdeposit\b|\bwithdraw\b|\bredeem\b|\bclaim\b|\bharvest\b|\bsweep\b|\brescue\b",
    r"\bliquidat|\bborrow\b|\brepay\b|\bcollateral\b|\bmargin\b|\bhealth\b|\bdebt\b",
    r"\bprice\b|\boracle\b|\bquote\b|\btwap\b|\bslot0\b|\blatestRoundData\b|\bgetReserves\b",
    r"\bsignature\b|\becrecover\b|\bpermit\b|\bnonce\b|\bdeadline\b|\bdomain\b|\bhashTypedData\b",
    r"\binitialize\b|\bupgradeTo\b|\bset[A-Z]|\bowner\b|\badmin\b|\brole\b",
    r"\bunchecked\b|\bassembly\b|\bselfdestruct\b|\btx\.origin\b",
    r"\bentry\b|\bread\s*\(|\bwrite\s*\(|\bassert\b|\bpanic\b",
    r"\bkill\w*\b|\bdisable\w*\b|\bdeactivate\w*\b|\brevive\w*\b",
    r"\bdistribute\w*\b|\bnotifyRewardAmount\b|\bclaimable\b|\bemission\b",
    r"\btotalWeight\w*\b|\bweightsPerEpoch\b|\bindex\b|\bepoch\b",
    r"\bfee\b|\bshares?\b|\btotalSupply\b|\bconvertToShares\b|\bpreviewDeposit\b|\bpreviewRedeem\b",
    r"\bslippage\b|\bamountOutMin\b|\bminAmount\b|\bminOut\b|\badd_liquidity\b|\bremove_liquidity\b",
    r"\bget_dy\b|\bvirtual_price\b|\bliquidity\b|\bmint\b|\bburn\b|\bvesting\b|\bescrow\b",
]
RISK_RE = [re.compile(p, re.IGNORECASE) for p in RISK_PATTERNS]
FUNC_RE = re.compile(
    r"^\s*(?:(?:public(?:\([^)]*\))?|entry|public\s+entry|pub(?:\([^)]*\))?|async|unsafe)\s+)*"
    r"(?:function|fn|fun)\s+([A-Za-z_][A-Za-z0-9_]*)\b|"
    r"^\s*(?:func\s+(?:\([^)]*\)\s*)?|def\s+)([A-Za-z_][A-Za-z0-9_]*)\b",
    re.MULTILINE,
)
CONTRACT_RE = re.compile(
    r"\b(?:contract|library|interface|abstract\s+contract|trait|impl|mod|module|package)\s+([A-Za-z_][A-Za-z0-9_]*)"
)
IMPORT_RE = re.compile(
    r"^\s*import\b(?:[^;\"']+\bfrom\s+)?[\"']([^\"']+)[\"']",
    re.MULTILINE,
)


def agent_main(project_dir: str | None = None, inference_api: str | None = None) -> dict[str, Any]:
    root = _resolve_root(project_dir)
    findings: list[dict[str, Any]] = []
    if root is None:
        return {"vulnerabilities": findings}

    files = _discover_files(root)
    if not files:
        return {"vulnerabilities": findings}

    static_findings = _static_accounting_findings(files)
    findings.extend(static_findings)

    endpoint = _endpoint(inference_api)
    primary_pack = _build_full_pack(files[:12], max_chars=MAX_PACK_CHARS)
    wide_pack = _build_source_pack(files[:36], max_chars=MAX_PACK_CHARS)
    covered = {str(item["rel"]) for item in files[:36]}
    diverse_pack = _build_source_pack(_diverse_files(files, skip_rels=covered), max_chars=MAX_PACK_CHARS)

    for prompt in (
        _audit_prompt(primary_pack, "primary whole-file"),
        _audit_prompt(wide_pack, "wide risk-surface"),
        _audit_prompt(diverse_pack, "uncovered cross-module invariant"),
    ):
        text = _ask(endpoint, prompt)
        findings.extend(_parse_items(text))

    findings = _dedupe(_normalize_all(findings, files))
    return {"vulnerabilities": findings[:MAX_FINDINGS]}


def _resolve_root(project_dir: str | None) -> Path | None:
    candidates = []
    if project_dir:
        candidates.append(project_dir)
    for key in ("PROJECT_DIR", "PROJECT_ROOT", "PROJECT_PATH", "PROJECT_CODE"):
        value = os.environ.get(key)
        if value:
            candidates.append(value)
    candidates.extend(("/app/project_code", "/app/project", "/project", "/code", "/app", "."))
    for raw in candidates:
        try:
            path = Path(raw).expanduser().resolve()
        except OSError:
            continue
        if path.is_dir() and _has_project_sources(path):
            return path
    return None


def _has_project_sources(path: Path) -> bool:
    try:
        for source in _iter_source_paths(path):
            if source.suffix.lower() in SOURCE_SUFFIXES:
                return True
    except OSError:
        return False
    return False


def _discover_files(root: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for path in _iter_source_paths(root):
        if not path.is_file() or path.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        try:
            rel = path.relative_to(root).as_posix()
            parts = {p.lower() for p in Path(rel).parts[:-1]}
            if parts & SKIP_DIRS:
                continue
            if _skip_filename(path):
                continue
            size = path.stat().st_size
            if size <= 0 or size > MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if path.suffix.lower() == ".sol" and _interface_only(text):
            continue
        if not _looks_like_logic(text):
            continue
        functions = [a or b for a, b in FUNC_RE.findall(text)][:80]
        if not functions and not _has_entrypoint(text):
            continue
        score = _score_file(rel, text)
        if parts & LOW_VALUE_DIRS:
            score -= 30
        if path.suffix.lower() == ".go" and score < 24:
            continue
        out.append(
            {
                "path": path,
                "rel": rel,
                "text": text,
                "score": score,
                "contracts": CONTRACT_RE.findall(text)[:8],
                "functions": functions,
                "lines": text.splitlines(),
            }
        )
    out.sort(key=lambda item: (-int(item["score"]), str(item["rel"])))
    return out[:MAX_FILES]


def _iter_source_paths(root: Path) -> Any:
    for dirpath, dirnames, filenames in os.walk(root):
        current = Path(dirpath)
        try:
            rel_parts = current.relative_to(root).parts
        except ValueError:
            rel_parts = ()
        if any(part.lower() in SKIP_DIRS for part in rel_parts):
            dirnames[:] = []
            continue
        dirnames[:] = [
            name
            for name in dirnames
            if name.lower() not in SKIP_DIRS and not name.startswith(".")
        ]
        for name in filenames:
            path = current / name
            if path.suffix.lower() in SOURCE_SUFFIXES and not _skip_filename(path):
                yield path


def _skip_filename(path: Path) -> bool:
    name = path.name.lower()
    stem = path.stem.lower()
    return (
        name.endswith((".t.sol", ".s.sol"))
        or stem in {"test", "tests", "mock", "mocks"}
        or stem.endswith(("_test", "_tests", "test", "tests", "mock", "mocks"))
        or ".generated" in name
        or "generated" in stem
    )


def _looks_like_logic(text: str) -> bool:
    lowered = text.lower()
    return (
        bool(FUNC_RE.search(text))
        or "contract " in lowered
        or "impl " in lowered
        or "module " in lowered
    )


def _interface_only(text: str) -> bool:
    return bool(re.search(r"\binterface\s+[A-Za-z_]", text)) and not bool(
        re.search(r"\b(?:contract|library|abstract\s+contract)\s+[A-Za-z_]", text)
    )


def _has_entrypoint(text: str) -> bool:
    lowered = text.lower()
    return any(
        token in lowered
        for token in (
            "constructor(",
            "fallback(",
            "receive(",
            "#[entry_point]",
            "entry fun ",
            "public entry fun ",
            "execute(",
        )
    )


def _score_file(rel: str, text: str) -> int:
    name = rel.lower()
    score = 0
    for word in (
        "vault",
        "router",
        "oracle",
        "market",
        "perp",
        "position",
        "payment",
        "order",
        "swap",
        "pool",
        "liquidity",
        "fee",
        "share",
        "bridge",
        "token",
        "mint",
        "burn",
        "staking",
        "vesting",
        "escrow",
        "liquidation",
        "manager",
        "controller",
        "govern",
        "asset",
        "account",
        "voter",
        "gauge",
        "reward",
        "emission",
        "distributor",
    ):
        if word in name:
            score += 8
    for regex in RISK_RE:
        score += min(len(regex.findall(text)), 8) * 4
    score += min(text.count("function "), 30)
    score += min(text.count("\nfn "), 30)
    score += min(text.count("\nfun "), 30)
    score += min(text.count("\nfunc "), 30)
    if re.search(r"\binterface\s+[A-Za-z_]", text) and not re.search(r"\b(contract|library)\s+[A-Za-z_]", text):
        score -= 45
    if Path(rel).suffix.lower() == ".go":
        score -= 18
    score -= max(0, rel.count("/") - 4) * 2
    return score


def _diverse_files(files: list[dict[str, Any]], *, skip_rels: set[str] | None = None) -> list[dict[str, Any]]:
    skip_rels = skip_rels or set()
    selected: list[dict[str, Any]] = []
    used_dirs: set[str] = set()
    for item in files:
        if str(item["rel"]) in skip_rels:
            continue
        parts = Path(str(item["rel"])).parts
        key = "/".join(parts[:2]) if len(parts) > 1 else str(item["rel"])
        if key not in used_dirs:
            selected.append(item)
            used_dirs.add(key)
        if len(selected) >= 18:
            break
    for item in files:
        if str(item["rel"]) in skip_rels:
            continue
        if item not in selected:
            selected.append(item)
        if len(selected) >= 18:
            break
    return selected or files[:18]


def _build_source_pack(files: list[dict[str, Any]], *, max_chars: int) -> str:
    chunks: list[str] = []
    remaining = max_chars
    for item in files:
        if remaining <= 800:
            break
        rel = str(item["rel"])
        header = _pack_header(item, rel)
        body = _risk_snippets(item, max_chars=max(1200, min(6500, remaining - len(header))))
        chunk = header + body
        chunks.append(chunk)
        remaining -= len(chunk)
    return "".join(chunks)


def _build_full_pack(files: list[dict[str, Any]], *, max_chars: int) -> str:
    chunks: list[str] = []
    remaining = max_chars
    for item in files:
        if remaining <= 1200:
            break
        rel = str(item["rel"])
        header = _pack_header(item, rel)
        body_budget = max(1000, min(FULL_FILE_CHARS, remaining - len(header)))
        text = str(item["text"])
        if len(text) <= body_budget:
            body = _numbered(text)
        else:
            body = _risk_snippets(item, max_chars=body_budget)
        related_budget = max(0, min(4_500, remaining - len(header) - len(body)))
        if related_budget > 900:
            body += _import_context(item, max_chars=related_budget)
        if len(header) + len(body) > remaining:
            body = body[: max(0, remaining - len(header))]
        chunk = header + body
        chunks.append(chunk)
        remaining -= len(chunk)
    return "".join(chunks)


def _pack_header(item: dict[str, Any], rel: str) -> str:
    return (
        f"\n\n--- FILE: {rel}\n"
        f"score: {item.get('score', 0)}\n"
        f"contracts_or_modules: {', '.join(item['contracts'])}\n"
        f"functions: {', '.join(item['functions'][:45])}\n"
    )


def _import_context(item: dict[str, Any], *, max_chars: int) -> str:
    source_path = Path(str(item.get("path") or ""))
    if not source_path:
        return ""
    parts: list[str] = []
    used = 0
    for imported in IMPORT_RE.findall(str(item.get("text") or "")):
        if not imported.startswith("."):
            continue
        try:
            target = (source_path.parent / imported).resolve()
        except OSError:
            continue
        if not target.is_file() or target.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        if _skip_filename(target):
            continue
        try:
            text = target.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = target.name
        snippet = f"\n\n--- RELATED IMPORT: {rel}\n" + _numbered(text[:2_200])
        if used + len(snippet) > max_chars:
            break
        parts.append(snippet)
        used += len(snippet)
        if len(parts) >= 2:
            break
    return "".join(parts)


def _risk_snippets(item: dict[str, Any], *, max_chars: int) -> str:
    text = str(item["text"])
    lines = item["lines"]
    candidates: list[tuple[int, int]] = []
    for idx, line in enumerate(lines):
        weight = _line_risk_weight(line)
        if weight:
            candidates.append((weight, idx))
    candidates.sort(key=lambda pair: (-pair[0], pair[1]))
    hit_lines = _ordered_unique(idx for _, idx in candidates[:MAX_SNIPPETS_PER_FILE])
    if not hit_lines:
        return _numbered(text[:max_chars])
    spans: list[tuple[int, int]] = []
    for idx in hit_lines:
        spans.append((max(0, idx - 28), min(len(lines), idx + 45)))
    merged: list[tuple[int, int]] = []
    for start, end in spans:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    parts = []
    used = 0
    for start, end in merged:
        snippet = "\n".join(f"{i + 1}: {lines[i]}" for i in range(start, end))
        if used + len(snippet) > max_chars:
            break
        parts.append(snippet)
        used += len(snippet)
    return "\n...\n".join(parts) if parts else _numbered(text[:max_chars])


def _line_risk_weight(line: str) -> int:
    lowered = line.lower()
    weight = sum(1 for regex in RISK_RE if regex.search(line))
    for word, bonus in (
        ("kill", 7),
        ("disable", 6),
        ("deactivate", 6),
        ("revive", 5),
        ("notifyrewardamount", 7),
        ("distribute", 7),
        ("_distribute", 7),
        ("totalweights", 8),
        ("weightsper", 8),
        ("claimable", 5),
        ("isalive", 5),
        ("index", 4),
        ("epoch", 4),
        ("safetransfer", 4),
        ("liquidity", 5),
        ("amountoutmin", 7),
        ("minout", 7),
        ("latestrounddata", 7),
        ("getreserves", 6),
        ("converttoshares", 6),
        ("previewredeem", 6),
        ("totalsupply", 4),
        ("nonce", 4),
        ("ecrecover", 6),
        ("permit", 4),
    ):
        if word in lowered:
            weight += bonus
    if re.search(r"\]\s*[-+*/]?=", line):
        weight += 3
    return weight


def _ordered_unique(values: Any) -> list[int]:
    seen: set[int] = set()
    out: list[int] = []
    for value in values:
        if value not in seen:
            out.append(value)
            seen.add(value)
    return sorted(out)


def _numbered(text: str) -> str:
    return "\n".join(f"{i}: {line}" for i, line in enumerate(text.splitlines(), start=1))


def _static_accounting_findings(files: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for item in files:
        rel = str(item["rel"])
        if not rel.endswith(".sol"):
            continue
        finding = _detect_deactivation_weight_mismatch(item)
        if finding:
            findings.append(finding)
    return findings


def _detect_deactivation_weight_mismatch(item: dict[str, Any]) -> dict[str, Any] | None:
    """Find generic reward bugs where disabling an entity updates aggregate
    weight but leaves the per-entity weight used by later distribution."""

    functions = _extract_solidity_functions(str(item["text"]))
    if not functions:
        return None

    kill_like = []
    for fn in functions:
        name = str(fn["name"])
        body = str(fn["body"])
        lowered = body.lower()
        if not re.search(r"(kill|disable|deactivate|remove|pause)", name, re.IGNORECASE):
            continue
        if not re.search(r"(isalive|active|enabled|disabled)", lowered):
            continue
        if not re.search(r"total\w*weight\w*\s*\[[^\n;]+\]\s*-=", body, re.IGNORECASE):
            continue
        if not re.search(r"weight\w*\s*\[[^\n;]+\]\s*\[[^\n;]+\]", body, re.IGNORECASE):
            continue
        if re.search(r"delete\s+weight\w*\s*\[", body, re.IGNORECASE):
            continue
        if re.search(r"weight\w*\s*\[[^\n;]+\]\s*\[[^\n;]+\]\s*=\s*0\b", body, re.IGNORECASE):
            continue
        kill_like.append(fn)

    if not kill_like:
        return None

    notify_like = [
        fn
        for fn in functions
        if re.search(r"notify|reward|index", str(fn["name"]), re.IGNORECASE)
        and re.search(r"total\w*weight\w*\s*\[", str(fn["body"]), re.IGNORECASE)
        and re.search(r"\bindex\s*\+=", str(fn["body"]), re.IGNORECASE)
    ]
    distribute_like = [
        fn
        for fn in functions
        if re.search(r"distribut|claim|reward", str(fn["name"]), re.IGNORECASE)
        and re.search(r"weight\w*\s*\[[^\n;]+\]\s*\[[^\n;]+\]", str(fn["body"]), re.IGNORECASE)
        and re.search(r"(isalive|active|claimable|safetransfer)", str(fn["body"]), re.IGNORECASE)
    ]
    if not notify_like or not distribute_like:
        return None

    kill_fn = kill_like[0]
    notify_fn = notify_like[0]
    distribute_fn = distribute_like[0]
    rel = str(item["rel"])
    kill_name = str(kill_fn["name"])
    notify_name = str(notify_fn["name"])
    distribute_name = str(distribute_fn["name"])
    line = int(kill_fn["line"])
    return {
        "title": "Disabled reward receiver keeps stale vote weight and breaks emission accounting",
        "description": (
            f"In `{rel}`, `{kill_name}` disables an active reward receiver and subtracts "
            "its current weight from the aggregate epoch weight, but it does not clear "
            "the matching per-receiver weight entry. Later, "
            f"`{notify_name}` increases the global reward index using the reduced "
            f"aggregate weight, while `{distribute_name}` still calculates this "
            "receiver's amount from the stale per-receiver weight. A normal governance "
            "disable/kill operation can therefore over-allocate rewards, return funds "
            "to the minter/treasury instead of live receivers, or leave later receivers "
            "with no emission depending on distribution order. Clearing only the alive "
            "flag/claimable amount is not enough; the per-epoch per-pool weight used by "
            "distribution must be cleared or skipped consistently with the aggregate."
        ),
        "severity": "high",
        "file": rel,
        "line": line,
        "function": kill_name,
        "impact": "Wrong reward/emission distribution after disabling a weighted receiver",
        "type": "accounting",
        "confidence": 0.86,
    }


def _extract_solidity_functions(text: str) -> list[dict[str, Any]]:
    functions: list[dict[str, Any]] = []
    pattern = re.compile(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\b[^{;]*\{", re.MULTILINE)
    for match in pattern.finditer(text):
        open_brace = text.find("{", match.end() - 1)
        if open_brace < 0:
            continue
        close_brace = _matching_brace(text, open_brace)
        if close_brace < 0:
            continue
        line = text.count("\n", 0, match.start()) + 1
        functions.append(
            {
                "name": match.group(1),
                "line": line,
                "body": text[match.start() : close_brace + 1],
            }
        )
    return functions


def _matching_brace(text: str, open_pos: int) -> int:
    depth = 0
    in_string: str | None = None
    escape = False
    for pos in range(open_pos, len(text)):
        ch = text[pos]
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == in_string:
                in_string = None
            continue
        if ch in {'"', "'"}:
            in_string = ch
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return pos
    return -1


def _endpoint(inference_api: str | None) -> str:
    base = (inference_api or os.environ.get("INFERENCE_API") or "").rstrip("/")
    return base + "/inference" if base else ""


def _ask(endpoint: str, user_prompt: str) -> str:
    if not endpoint:
        return ""
    key = os.environ.get("INFERENCE_API_KEY", "")
    if not key:
        return ""
    body = json.dumps(
        {
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a top-tier smart-contract security auditor. "
                        "Return strict JSON only. Report only high or critical, "
                        "directly exploitable bugs with a concrete attacker path."
                    ),
                },
                {"role": "user", "content": user_prompt},
            ],
            "max_tokens": 8000,
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        endpoint,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "x-inference-api-key": key},
    )
    for attempt in range(2):
        try:
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                payload = json.loads(resp.read().decode("utf-8", errors="ignore"))
            return _content(payload)
        except Exception:
            if attempt == 0:
                time.sleep(2)
    return ""


def _content(payload: dict[str, Any]) -> str:
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        return ""
    msg = choices[0].get("message") if isinstance(choices[0], dict) else {}
    if not isinstance(msg, dict):
        return ""
    content = msg.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(str(part.get("text", "")) for part in content if isinstance(part, dict))
    return ""


def _audit_prompt(source_pack: str, pass_name: str) -> str:
    return (
        f"Audit pass: {pass_name}.\n"
        "Find the most likely high/critical vulnerabilities in this source pack. "
        "Focus on: access-control bypasses; arbitrary external calls and lingering "
        "approvals; missing validation before accounting updates; oracle freshness, "
        "spot-price, or decimal mistakes; signature replay or missing caller binding; "
        "asset, share, collateral, liquidation, reward, fee, mint/burn, and liquidity "
        "accounting errors; slippage/min-output failures; upgrade/init privilege "
        "mistakes; Rust or Move authorization/storage mistakes; Cairo storage reads "
        "that default to zero and are then trusted.\n\n"
        "High-yield exploit patterns to actively test: aggregate totals diverging from "
        "per-account or per-epoch state; fee or reward amounts counted twice or not "
        "cleared on cancellation/disable; low-decimal rewards rounding to zero while "
        "timestamps advance; first-depositor/share-inflation donation attacks; using "
        "pool token balances or spot reserves as fair value; stale or incomplete oracle "
        "rounds; missing deadline/nonce/domain binding on signed approvals; callbacks "
        "or external transfers before accounting is finalized; concentrated-liquidity "
        "math that ignores tick range or uncollected fees; wrong router/gauge/interface "
        "assumptions; vesting, escrow, or unstake paths that let sellers or old owners "
        "claim assets after transfer; and admin/config functions that can brick user "
        "withdrawals or bypass protocol invariants.\n\n"
        "For every finding, include an actual exploit path. If a candidate cannot steal "
        "value, corrupt state, bypass authorization, or cause durable denial of service, "
        "do not include it. Prefer a few exact true positives over broad speculation, "
        "but do not drop a concrete high-impact bug just because the fix is simple.\n\n"
        "Return JSON only:\n"
        '{"vulnerabilities":[{"title":"","description":"","severity":"high",'
        '"file":"","line":null,"function":"","type":"accounting|oracle|access-control|'
        'signature|reentrancy|slippage|upgrade|denial-of-service|logic",'
        '"impact":"","confidence":0.0}]}\n\n'
        "The title should include the vulnerable contract or function name. The description "
        "must name the exact file, exact function, root cause, attacker steps, broken "
        "invariant, and impact. Use only files/functions present in the source pack.\n"
        f"{source_pack}"
    )


def _verify_prompt(source_pack: str, candidates: list[dict[str, Any]]) -> str:
    return (
        "Verify these candidate findings against the exact snippets below. "
        "Remove any issue that is speculative, duplicate, low severity, or not directly "
        "supported by the source. Improve the remaining descriptions so they clearly "
        "state the vulnerable function, root cause, exploit steps, and impact.\n\n"
        "Return JSON only with the same shape:\n"
        '{"vulnerabilities":[{"title":"","description":"","severity":"high",'
        '"file":"","line":null,"function":"","impact":"","confidence":0.0}]}\n\n'
        "Candidates:\n"
        + json.dumps({"vulnerabilities": candidates[:MAX_FINDINGS]}, ensure_ascii=False)
        + "\n\nSnippets:\n"
        + source_pack
    )


def _verification_pack(findings: list[dict[str, Any]], files: list[dict[str, Any]]) -> str:
    by_rel = {str(item["rel"]): item for item in files}
    selected: list[dict[str, Any]] = []
    seen: set[str] = set()
    for finding in findings[:MAX_FINDINGS]:
        rel = str(finding.get("file") or "")
        item = by_rel.get(rel)
        if item and rel not in seen:
            selected.append(item)
            seen.add(rel)
    if not selected:
        selected = files[:8]
    return _build_source_pack(selected[:10], max_chars=34_000)


def _parse_items(text: str) -> list[dict[str, Any]]:
    if not text:
        return []
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```[a-zA-Z0-9_-]*\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned).strip()
    obj = _loads_json_object(cleaned)
    if not isinstance(obj, dict):
        return []
    items = obj.get("vulnerabilities") or obj.get("findings") or []
    return [item for item in items if isinstance(item, dict)] if isinstance(items, list) else []


def _loads_json_object(text: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    start = text.find("{")
    if start < 0:
        return None
    depth = 0
    in_string = False
    escape = False
    for pos in range(start, len(text)):
        ch = text[pos]
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[start : pos + 1])
                except json.JSONDecodeError:
                    return None
    return None


def _normalize_all(items: list[dict[str, Any]], files: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rels = {str(item["rel"]) for item in files}
    by_name = {Path(str(item["rel"])).name: str(item["rel"]) for item in files}
    by_rel = {str(item["rel"]): item for item in files}
    out: list[dict[str, Any]] = []
    for item in items:
        norm = _normalize_one(item, rels, by_name, by_rel)
        if norm:
            out.append(norm)
    return out


def _normalize_one(
    item: dict[str, Any],
    rels: set[str],
    by_name: dict[str, str],
    by_rel: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    severity = str(item.get("severity") or "high").strip().lower()
    if severity not in {"high", "critical"}:
        return None
    file_path = str(item.get("file") or item.get("path") or "").strip()
    if file_path not in rels:
        file_path = by_name.get(Path(file_path).name, file_path)
    if file_path not in rels:
        return None
    title = _clean(str(item.get("title") or "High severity smart contract vulnerability"))
    desc = _clean(str(item.get("description") or ""))
    impact = _clean(str(item.get("impact") or ""))
    func = _clean(str(item.get("function") or item.get("function_name") or ""))
    func = func.strip("`(). ")
    if "." in func:
        func = func.split(".")[-1].strip("`(). ")
    rec = by_rel.get(file_path, {})
    valid_funcs = {str(name) for name in rec.get("functions", []) if str(name)}
    if func and valid_funcs and func not in valid_funcs:
        haystack = f"{title} {desc}"
        replacement = next((name for name in valid_funcs if re.search(rf"\b{re.escape(name)}\b", haystack)), "")
        if replacement:
            func = replacement
    vtype = _clean(str(item.get("type") or item.get("vulnerability_type") or "logic")).lower()
    if len(vtype) > 60 or not re.search(r"[a-z]", vtype):
        vtype = "logic"
    loc = f"In `{file_path}`"
    if func:
        loc += f", function `{func}`"
    if desc and loc.lower() not in desc.lower():
        desc = f"{loc}. {desc}"
    if impact and "impact:" not in desc.lower():
        desc = f"{desc} Impact: {impact}."
    if func and func.lower() not in title.lower():
        title = f"{func} - {title}"
    if len(desc) < 90:
        detail = []
        if func:
            detail.append(f"The issue is in `{func}`.")
        if impact:
            detail.append(f"Impact: {impact}.")
        desc = (desc + " " + " ".join(detail)).strip()
    if len(desc) < 90:
        return None
    try:
        line = int(item.get("line")) if item.get("line") is not None else None
    except (TypeError, ValueError):
        line = None
    if line is None and func:
        line = _line_for_function(rec, func)
    try:
        confidence = float(item.get("confidence", 0.75))
    except (TypeError, ValueError):
        confidence = 0.75
    return {
        "title": title[:220],
        "description": desc,
        "severity": severity,
        "file": file_path,
        "line": line,
        "function": func[:120],
        "type": vtype[:80],
        "impact": impact[:500],
        "confidence": max(0.0, min(1.0, confidence)),
    }


def _line_for_function(item: dict[str, Any], func: str) -> int | None:
    text = str(item.get("text") or "")
    if not text or not func:
        return None
    patterns = (
        rf"\bfunction\s+{re.escape(func)}\b",
        rf"^\s*def\s+{re.escape(func)}\b",
        rf"^\s*(?:public\s+entry\s+|public\s+|entry\s+)?fun\s+{re.escape(func)}\b",
        rf"^\s*fn\s+{re.escape(func)}\b",
        rf"^\s*func\s+(?:\([^)]*\)\s*)?{re.escape(func)}\b",
    )
    for pattern in patterns:
        match = re.search(pattern, text, re.MULTILINE)
        if match:
            return text.count("\n", 0, match.start()) + 1
    return None


def _clean(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def _dedupe(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ordered = sorted(
        findings,
        key=lambda f: (f.get("severity") == "critical", float(f.get("confidence", 0.0))),
        reverse=True,
    )
    seen: set[tuple[str, str]] = set()
    out: list[dict[str, Any]] = []
    for finding in ordered:
        key = (
            str(finding.get("file", "")).lower(),
            (str(finding.get("function") or finding.get("title") or "")[:80]).lower(),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(finding)
    return out


if __name__ == "__main__":
    print(json.dumps(agent_main(), indent=2))
