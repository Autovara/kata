from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

EXTS = (".sol", ".vy")
SKIP_DIRS = {
    ".git", ".github", "artifacts", "broadcast", "cache", "coverage", "dist",
    "docs", "example", "examples", "lib", "node_modules", "out", "script",
    "scripts", "test", "tests", "vendor", "vendors",
}
SOFT_SKIP_IN_SRC = {"test", "tests", "mock", "mocks"}

FUNC_SOL = re.compile(
    r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*([^{};]*)(?:;|\{)",
    re.MULTILINE,
)
FUNC_VY = re.compile(r"^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", re.MULTILINE)
CONTRACT = re.compile(
    r"^\s*(?:abstract\s+contract|contract|library|interface)\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
IMPORT = re.compile(r'^\s*import\b[^;]*?["\']([^"\']+)["\']', re.MULTILINE)
STATE_VAR = re.compile(
    r"^\s*(?:mapping\s*\([^;]+|[A-Za-z_][A-Za-z0-9_<>,\[\]. ]+)\s+"
    r"(?:public|private|internal|constant|immutable|override|\s)*"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:=|;)",
    re.MULTILINE,
)

RISK_PATTERNS: tuple[tuple[str, int, str], ...] = (
    (r"\bdelegatecall\b", 15, "delegatecall"),
    (r"\bselfdestruct\b", 14, "selfdestruct"),
    (r"\btx\.origin\b", 12, "tx.origin"),
    (r"\bassembly\b", 8, "assembly"),
    (r"\bunchecked\s*\{", 7, "unchecked arithmetic"),
    (r"\.call\s*(?:\{|[\(\{])", 10, "low-level call"),
    (r"\bcallcode\b|\bstaticcall\b", 7, "raw call"),
    (r"\becrecover\b|\bpermit\b|\bnonces?\b|\bsignature\b", 9, "signature/auth"),
    (r"\binitialize\s*\(|\breinitializer\b|\bupgradeTo", 12, "upgrade/init"),
    (r"\bonlyOwner\b|\bonlyRole\b|\bDEFAULT_ADMIN_ROLE\b", 4, "privileged path"),
    (r"\bwithdraw\b|\bredeem\b|\bdeposit\b|\bclaim\b|\bharvest\b", 7, "fund flow"),
    (r"\bborrow\b|\brepay\b|\bliquidat|\bcollateral\b", 9, "lending"),
    (r"\bswap\b|\bamountOut\b|\bamountIn\b|\bslippage\b", 8, "swap"),
    (r"\boracle\b|\bprice\b|\btwap\b|\bchainlink\b|\blatestRoundData\b", 9, "oracle"),
    (r"\bflashLoan\b|\bflash\b", 8, "flash loan"),
    (r"\btransferFrom\b|\bsafeTransfer\b|\btransfer\b", 5, "token transfer"),
    (r"\bmsg\.value\b|\bbalanceOf\b|\btotalSupply\b", 5, "accounting"),
    (r"\bblock\.timestamp\b|\bblock\.number\b", 4, "time dependency"),
    (r"\bdelete\b|\bpop\s*\(|\bpush\s*\(", 4, "array mutation"),
)
RISK_RE = re.compile("|".join(f"(?:{p})" for p, _w, _n in RISK_PATTERNS), re.IGNORECASE)

NAME_HINTS = (
    "vault", "pool", "router", "bridge", "proxy", "upgrade", "oracle", "govern",
    "treasury", "manager", "market", "lend", "borrow", "collateral", "controller",
    "strategy", "auction", "token", "admin", "owner", "swap", "staking", "reward",
    "escrow", "factory", "registry", "liquid", "position", "order", "settle",
)

MAX_FILES = 90
MAX_BYTES = 380_000
MAP_CHARS = 30_000
FULL_BATCH_CHARS = 45_000
FOCUS_BATCH_CHARS = 48_000
RELATED_CHARS = 6_000
MAX_FINDINGS = 18
RUN_BUDGET = 230.0
HTTP_TIMEOUT = 155

AUDITOR = (
    "You are a senior smart-contract security auditor in a competitive audit. "
    "Return only concrete high or critical exploits with a plausible attacker, "
    "triggering path, violated invariant, and material loss/privilege impact. "
    "No style, gas, informational, or low-confidence reports. Strict JSON only."
)


def agent_main(project_dir: str | None = None, inference_api: str | None = None) -> dict:
    findings: list[dict[str, Any]] = []
    root = _project_root(project_dir)
    if root is None:
        return {"vulnerabilities": findings}

    started = time.monotonic()
    records = _discover(root)
    if not records:
        return {"vulnerabilities": findings}

    rel_map = {r["rel"]: r for r in records}
    by_name = {Path(str(r["rel"])).name: r for r in records}
    raw: list[dict[str, Any]] = []

    targets, first_hits = _triage(inference_api, records)
    raw.extend(first_hits)
    ordered = _ordered_targets(targets, records)

    if time.monotonic() - started < RUN_BUDGET:
        raw.extend(_audit_full(inference_api, ordered[:9], by_name))
    if time.monotonic() - started < RUN_BUDGET:
        raw.extend(_audit_focused(inference_api, ordered, by_name))

    for item in raw:
        norm = _normalize(item, rel_map)
        if norm is not None:
            findings.append(norm)
    return {"vulnerabilities": _dedupe(findings)}


def _project_root(project_dir: str | None) -> Path | None:
    candidates: list[str] = []
    if project_dir:
        candidates.append(project_dir)
    for env in ("PROJECT_DIR", "PROJECT_PATH", "PROJECT_ROOT", "PROJECT_CODE", "INFERENCE_PROJECT_DIR"):
        val = os.environ.get(env)
        if val:
            candidates.append(val)
    candidates.extend(("/app/project_code", "/app/project", "/project", "/code", "."))
    for raw in candidates:
        try:
            root = Path(raw).expanduser().resolve()
        except (OSError, RuntimeError):
            continue
        if root.is_dir() and _has_sources(root):
            return root
    return None


def _has_sources(root: Path) -> bool:
    try:
        for path in root.rglob("*"):
            if path.is_file() and path.suffix.lower() in EXTS:
                return True
    except OSError:
        return False
    return False


def _skip(parts: tuple[str, ...]) -> bool:
    lowered = [p.lower() for p in parts]
    in_src = "src" in lowered or "contracts" in lowered
    for part in lowered:
        if part in SOFT_SKIP_IN_SRC:
            return True
        if not in_src and part in SKIP_DIRS:
            return True
    return False


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _functions(text: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for match in FUNC_SOL.finditer(text):
        tail = " ".join(match.group(3).split())
        name = match.group(1)
        out.append({
            "name": name,
            "sig": f"{name}({match.group(2).strip()}) {tail}".strip(),
            "line": text.count("\n", 0, match.start()) + 1,
            "risk": _function_risk(text, match.start()),
        })
    for match in FUNC_VY.finditer(text):
        out.append({
            "name": match.group(1),
            "sig": match.group(1),
            "line": text.count("\n", 0, match.start()) + 1,
            "risk": _function_risk(text, match.start()),
        })
    return out


def _function_risk(text: str, start: int) -> int:
    end = text.find("\nfunction ", start + 10)
    if end < 0:
        end = text.find("\ndef ", start + 5)
    if end < 0:
        end = min(len(text), start + 4500)
    chunk = text[start:end]
    score = 0
    for pattern, weight, _name in RISK_PATTERNS:
        if re.search(pattern, chunk, re.IGNORECASE):
            score += weight
    if "onlyOwner" not in chunk and "onlyRole" not in chunk:
        if re.search(r"\b(set|update|change|configure|pause|mint|sweep|rescue)\w*\s*\(", chunk):
            score += 7
    if ".call" in chunk and "nonReentrant" not in chunk and "nonreentrant" not in chunk.lower():
        score += 8
    return score


def _score(rel: str, text: str, funcs: list[dict[str, Any]]) -> int:
    low_name = rel.lower()
    low_text = text.lower()
    score = min(low_text.count("function ") + low_text.count("\ndef "), 35)
    score += min(sum(int(f.get("risk") or 0) for f in funcs), 85)
    for term in NAME_HINTS:
        if term in low_name:
            score += 9
        elif term in low_text:
            score += 2
    for pattern, weight, _name in RISK_PATTERNS:
        count = len(re.findall(pattern, text, re.IGNORECASE))
        score += min(count * weight, weight * 5)
    if re.search(r"\b(external|public)\b", text):
        score += 6
    if ".call" in low_text and "nonreentrant" not in low_text:
        score += 10
    if "interface " in low_text and "contract " not in low_text:
        score -= 12
    return score


def _discover(root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in EXTS:
            continue
        try:
            rel_path = path.relative_to(root)
            if _skip(tuple(rel_path.parts[:-1])):
                continue
            if path.stat().st_size > MAX_BYTES:
                continue
        except OSError:
            continue
        text = _read(path)
        if not any(tok in text for tok in ("function", "contract ", "library ", "\ndef ")):
            continue
        rel = rel_path.as_posix()
        funcs = _functions(text)
        contracts = CONTRACT.findall(text)
        if not contracts and path.suffix.lower() == ".vy":
            contracts = [path.stem]
        rows.append({
            "path": path,
            "rel": rel,
            "text": text,
            "contracts": contracts,
            "functions": funcs,
            "score": _score(rel, text, funcs),
        })
    rows.sort(key=lambda r: (-int(r["score"]), len(str(r["text"])), str(r["rel"])))
    return rows[:MAX_FILES]


def _state_vars(text: str) -> list[str]:
    out: list[str] = []
    for name in STATE_VAR.findall(text):
        if name not in out and len(name) < 48:
            out.append(name)
        if len(out) >= 18:
            break
    return out


def _risk_lines(text: str, limit: int = 20) -> list[str]:
    lines: list[str] = []
    for idx, line in enumerate(text.splitlines(), 1):
        if RISK_RE.search(line):
            compact = " ".join(line.strip().split())
            if compact:
                lines.append(f"{idx}: {compact[:190]}")
        if len(lines) >= limit:
            break
    return lines


def _risk_kinds(text: str) -> list[str]:
    kinds: list[str] = []
    for pattern, _weight, name in RISK_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE) and name not in kinds:
            kinds.append(name)
    return kinds[:12]


def _digest(records: list[dict[str, Any]]) -> str:
    chunks: list[str] = []
    for rec in records:
        funcs = sorted(rec["functions"], key=lambda f: -int(f.get("risk") or 0))
        chunks.append(json.dumps({
            "file": rec["rel"],
            "contracts": rec["contracts"][:8],
            "score": rec["score"],
            "state": _state_vars(str(rec["text"])),
            "risk_kinds": _risk_kinds(str(rec["text"])),
            "functions": [
                {
                    "name": f["name"],
                    "sig": str(f["sig"])[:155],
                    "line": f.get("line"),
                    "risk": f.get("risk"),
                }
                for f in funcs[:28]
            ],
            "risk_lines": _risk_lines(str(rec["text"]), 18),
        }, separators=(",", ":")))
        if len("\n".join(chunks)) > MAP_CHARS:
            break
    return "\n".join(chunks)[:MAP_CHARS]


def _request(inference_api: str | None, messages: list[dict[str, str]], max_tokens: int) -> str:
    endpoint = (inference_api or os.environ.get("INFERENCE_API") or "").rstrip("/")
    if not endpoint:
        raise RuntimeError("missing inference endpoint")
    body = json.dumps({"messages": messages, "max_tokens": max_tokens}).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "x-inference-api-key": os.environ.get("INFERENCE_API_KEY", ""),
    }
    last: Exception | None = None
    for attempt in range(2):
        try:
            req = urllib.request.Request(endpoint + "/inference", data=body, method="POST", headers=headers)
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                return _content(json.loads(resp.read().decode("utf-8", "replace")))
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                raise
            last = exc
        except (OSError, ValueError, TimeoutError) as exc:
            last = exc
        if attempt < 1:
            time.sleep(1.2)
    raise RuntimeError(f"inference failed: {last}")


def _content(payload: dict[str, Any]) -> str:
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        return ""
    first = choices[0] if isinstance(choices[0], dict) else {}
    msg = first.get("message") if isinstance(first, dict) else None
    if not isinstance(msg, dict):
        return ""
    content = msg.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(str(part.get("text") or "") for part in content if isinstance(part, dict))
    return ""


def _parse_json(text: str) -> dict[str, Any]:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```[a-zA-Z]*\s*", "", stripped)
        stripped = re.sub(r"\s*```$", "", stripped)
    try:
        obj = json.loads(stripped)
        return obj if isinstance(obj, dict) else {}
    except json.JSONDecodeError:
        pass
    start = stripped.find("{")
    if start < 0:
        return {}
    depth = 0
    in_str = False
    esc = False
    for idx in range(start, len(stripped)):
        ch = stripped[idx]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                try:
                    obj = json.loads(stripped[start: idx + 1])
                    return obj if isinstance(obj, dict) else {}
                except json.JSONDecodeError:
                    return {}
    return {}


def _triage(inference_api: str | None, records: list[dict[str, Any]]) -> tuple[list[str], list[dict[str, Any]]]:
    prompt = (
        "Repository map follows. Choose the highest-value audit targets and report any "
        "obvious high/critical bugs you can already justify from names, signatures, "
        "state, and risk lines.\n"
        "Return strict JSON: "
        '{"target_files":["path"],"findings":[{"title":"specific bug","file":"path",'
        '"contract":"Contract","function":"fn","line":1,"severity":"high|critical",'
        '"mechanism":"preconditions -> attacker action -> effect",'
        '"impact":"fund loss, insolvency, permanent lock, or privilege takeover",'
        '"description":"2-4 precise sentences"}]}\n'
        "Use this checklist: missing access control on privileged state/fund moves; "
        "reentrancy before accounting; oracle or share-price manipulation; bad "
        "rounding/accounting in deposit/withdraw/borrow/liquidate; unsafe upgrades or "
        "initializers; signature replay/domain mistakes; unchecked external-call results; "
        "delegatecall storage confusion; flash-loan amplified paths; cross-contract trust "
        "assumptions. Prefer concrete exploit paths over volume.\n\n"
        + _digest(records)
    )
    try:
        obj = _parse_json(_request(
            inference_api,
            [{"role": "system", "content": AUDITOR}, {"role": "user", "content": prompt}],
            6000,
        ))
    except Exception:
        return [], []
    targets = obj.get("target_files")
    findings = obj.get("findings") or obj.get("vulnerabilities") or []
    return (
        [str(x) for x in targets if isinstance(x, str)] if isinstance(targets, list) else [],
        [x for x in findings if isinstance(x, dict)] if isinstance(findings, list) else [],
    )


def _ordered_targets(targets: list[str], records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ordered: list[dict[str, Any]] = []
    for target in targets:
        cleaned = target.strip().lstrip("./")
        for rec in records:
            rel = str(rec["rel"])
            if cleaned == rel or rel.endswith(cleaned) or cleaned.endswith(rel) or Path(rel).name == Path(cleaned).name:
                if rec not in ordered:
                    ordered.append(rec)
                break
    for rec in records:
        if rec not in ordered:
            ordered.append(rec)
    return ordered


def _related(rec: dict[str, Any], by_name: dict[str, dict[str, Any]]) -> str:
    parts: list[str] = []
    for imp in IMPORT.findall(str(rec["text"])):
        base = imp.rsplit("/", 1)[-1]
        other = by_name.get(base)
        if other and other["rel"] != rec["rel"]:
            snippet = _compact_source(str(other["text"]), RELATED_CHARS // 2)
            parts.append(f"// import {other['rel']}\n{snippet}")
        if len(parts) >= 3:
            break
    return "\n\n".join(parts)[:RELATED_CHARS]


def _audit_full(
    inference_api: str | None,
    batch: list[dict[str, Any]],
    by_name: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    if not batch:
        return []
    prompt = _full_prompt(batch, by_name)
    try:
        obj = _parse_json(_request(
            inference_api,
            [{"role": "system", "content": AUDITOR}, {"role": "user", "content": prompt}],
            9000,
        ))
    except Exception:
        return []
    findings = obj.get("findings") or obj.get("vulnerabilities") or []
    return [x for x in findings if isinstance(x, dict)] if isinstance(findings, list) else []


def _full_prompt(batch: list[dict[str, Any]], by_name: dict[str, dict[str, Any]]) -> str:
    header = (
        "Deep-audit these full sources for high/critical exploitable vulnerabilities. "
        "Inspect attacker-controlled call order and cross-contract assumptions. "
        "Return strict JSON only: "
        '{"findings":[{"title":"Contract.function - specific exploit","file":"exact/path",'
        '"contract":"Contract","function":"functionName","line":123,"severity":"high|critical",'
        '"mechanism":"preconditions -> attacker transaction(s) -> violated invariant",'
        '"impact":"specific material impact","description":"2-5 sentences with exact path"}]}\n'
        "Report up to 12 distinct real issues. Include line/function when possible. "
        "Reject missing events, centralization complaints without an unauthorized path, and guesses.\n"
    )
    parts = [header]
    remaining = FULL_BATCH_CHARS - len(header)
    for rec in batch:
        text = str(rec["text"])
        if len(text) > 17_000:
            text = _compact_source(text, 17_000)
        block = (
            f"\n\n===== FILE: {rec['rel']} =====\n"
            f"Contracts: {', '.join(rec['contracts'][:8])}\n"
            f"Risk: {', '.join(_risk_kinds(str(rec['text'])))}\n{text}\n"
        )
        related = _related(rec, by_name)
        if related:
            block += f"\n===== IMPORT CONTEXT =====\n{related}\n"
        if remaining <= 0:
            break
        if len(block) > remaining:
            block = block[:remaining] + "\n/* truncated */\n"
        parts.append(block)
        remaining -= len(block)
    return "".join(parts)


def _audit_focused(
    inference_api: str | None,
    ordered: list[dict[str, Any]],
    by_name: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    if not ordered:
        return []
    prompt = _focused_prompt(ordered, by_name)
    try:
        obj = _parse_json(_request(
            inference_api,
            [{"role": "system", "content": AUDITOR}, {"role": "user", "content": prompt}],
            9000,
        ))
    except Exception:
        return []
    findings = obj.get("findings") or obj.get("vulnerabilities") or []
    return [x for x in findings if isinstance(x, dict)] if isinstance(findings, list) else []


def _focused_prompt(ordered: list[dict[str, Any]], by_name: dict[str, dict[str, Any]]) -> str:
    header = (
        "Second-pass audit with a different lens. Focus on files not fully covered, "
        "large functions, and interactions among vaults/pools/oracles/tokens/admin modules. "
        "For every proposed bug, spell out why existing modifiers/checks do not stop it. "
        "Return strict JSON only: "
        '{"findings":[{"title":"specific exploit","file":"exact/path","contract":"Contract",'
        '"function":"functionName","line":123,"severity":"high|critical",'
        '"mechanism":"preconditions -> attacker action -> effect",'
        '"impact":"specific loss/lock/privilege impact","description":"2-5 sentences"}]}\n'
        "Hunt especially for: access control gaps; reentrancy and callbacks; stale/manipulable "
        "prices; share inflation/deflation and rounding theft; liquidation math; unsafe "
        "initialization/upgrades; signature replay; unchecked token behavior; delegatecall misuse; "
        "DoS that permanently blocks funds. Report up to 14 issues only if concrete.\n"
    )
    parts = [header, "\n===== REPOSITORY SUMMARY =====\n", _digest(ordered)[:18_000]]
    remaining = FOCUS_BATCH_CHARS - sum(len(p) for p in parts)
    selected = ordered[5:18] + ordered[:5]
    for rec in selected:
        text = _compact_source(str(rec["text"]), 8_500)
        block = (
            f"\n\n===== FOCUSED FILE: {rec['rel']} =====\n"
            f"Contracts: {', '.join(rec['contracts'][:8])}\n"
            f"Risk: {', '.join(_risk_kinds(str(rec['text'])))}\n{text}\n"
        )
        related = _related(rec, by_name)
        if related:
            block += f"\n===== RELATED IMPORTS =====\n{related[:2500]}\n"
        if remaining <= 0:
            break
        if len(block) > remaining:
            block = block[:remaining] + "\n/* truncated */\n"
        parts.append(block)
        remaining -= len(block)
    return "".join(parts)


def _compact_source(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    lines = text.splitlines()
    keep: list[tuple[int, str]] = []
    important: set[int] = set()
    for idx, line in enumerate(lines):
        if RISK_RE.search(line) or re.search(r"\bfunction\b|\bdef\b|\bmodifier\b|\bconstructor\b", line):
            for j in range(max(0, idx - 5), min(len(lines), idx + 18)):
                important.add(j)
    for idx in sorted(important):
        keep.append((idx + 1, lines[idx]))
    out: list[str] = []
    last = -10
    for line_no, line in keep:
        if line_no > last + 1:
            out.append(f"\n// ... lines before {line_no} omitted ...")
        out.append(f"{line_no}: {line}")
        last = line_no
        if sum(len(x) + 1 for x in out) >= limit:
            break
    compact = "\n".join(out)
    if len(compact) < limit // 2:
        compact += "\n\n// file prefix\n" + text[: max(0, limit - len(compact) - 20)]
    return compact[:limit]


def _line_for(text: str, function: str) -> int | None:
    if not function:
        return None
    for needle in (f"function {function}", f"def {function}"):
        idx = text.find(needle)
        if idx >= 0:
            return text.count("\n", 0, idx) + 1
    return None


def _normalize(raw: dict[str, Any], rel_map: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    file_value = str(raw.get("file") or raw.get("path") or "").strip().lstrip("./")
    chosen = None
    for rel, rec in rel_map.items():
        if file_value == rel or rel.endswith(file_value) or file_value.endswith(rel) or Path(rel).name == Path(file_value).name:
            chosen = rec
            file_value = rel
            break
    if chosen is None:
        return None

    severity = str(raw.get("severity") or "").lower().strip()
    if severity not in {"high", "critical"}:
        return None

    function = str(raw.get("function") or "").strip().strip("`() ")
    if "." in function:
        function = function.split(".")[-1]
    valid_funcs = {str(f["name"]) for f in chosen["functions"]}
    if function and function not in valid_funcs:
        function = ""

    contract = str(raw.get("contract") or "").strip().strip("`")
    valid_contracts = {str(c) for c in chosen["contracts"]}
    if contract and valid_contracts and contract not in valid_contracts:
        if len(valid_contracts) == 1:
            contract = next(iter(valid_contracts))
    if not contract and chosen["contracts"]:
        contract = str(chosen["contracts"][0])

    mechanism = str(raw.get("mechanism") or "").strip()
    impact = str(raw.get("impact") or "").strip()
    description = str(raw.get("description") or "").strip()
    title = str(raw.get("title") or "").strip()
    if len(mechanism) < 25 and len(description) < 110:
        return None
    if not any(word in (impact + " " + description).lower() for word in (
        "loss", "steal", "drain", "insolv", "liquidat", "lock", "freeze", "privilege",
        "mint", "collateral", "withdraw", "borrow", "fund", "token", "dos",
    )):
        return None

    loc = ".".join(x for x in (contract, function) if x)
    if not title:
        title = f"{loc or file_value} - exploitable high-impact bug"
    elif loc and loc.lower() not in title.lower():
        title = f"{loc} - {title}"

    where = f"In `{file_value}`"
    if contract:
        where += f", contract `{contract}`"
    if function:
        where += f", function `{function}()`"
    rebuilt = where + ". "
    if mechanism:
        rebuilt += "Mechanism: " + mechanism.rstrip(".") + ". "
    if impact:
        rebuilt += "Impact: " + impact.rstrip(".") + ". "
    if description:
        rebuilt += description
    description = " ".join(rebuilt.split())
    if len(description) < 120:
        return None

    line = raw.get("line")
    if not isinstance(line, int) and function:
        line = _line_for(str(chosen["text"]), function)
    return {
        "title": title[:220],
        "description": description[:3500],
        "severity": severity,
        "file": file_value,
        "contract": contract,
        "function": function,
        "line": line if isinstance(line, int) else None,
        "type": str(raw.get("type") or "logic"),
        "confidence": 0.92 if severity == "critical" else 0.86,
    }


def _dedupe(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str]] = set()
    out: list[dict[str, Any]] = []
    ordered = sorted(
        items,
        key=lambda f: (
            f.get("severity") == "critical",
            float(f.get("confidence") or 0),
            len(str(f.get("description") or "")),
        ),
        reverse=True,
    )
    for item in ordered:
        words = re.findall(r"[a-z0-9]+", str(item.get("title") or "").lower())
        key_title = " ".join(words[:10])
        key = (
            str(item.get("file") or "").lower(),
            str(item.get("function") or "").lower(),
            key_title,
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
        if len(out) >= MAX_FINDINGS:
            break
    return out


if __name__ == "__main__":
    import sys

    print(json.dumps(agent_main(sys.argv[1] if len(sys.argv) > 1 else None), indent=2))
