from __future__ import annotations

"""SN60 miner: repository triage plus two deep-audit batches.

General-purpose vulnerability analysis for unseen codebases. The agent ranks
source files with reusable heuristics, spends one inference call on repo-wide
target selection, then audits two full-source batches with matcher-shaped output
(file, contract, function, mechanism, impact). No project-specific fingerprint
branches or canned findings.

Self-contained stdlib; validator inference proxy only.
"""

import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

EXTS = (".sol", ".vy")
SKIP_OUTSIDE_SRC = frozenset({
    ".git", ".github", "artifacts", "broadcast", "cache", "coverage", "dist", "docs",
    "example", "examples", "interfaces", "lib", "mock", "mocks", "node_modules", "out",
    "script", "scripts", "test", "tests", "vendor", "vendors",
})
SKIP_UNDER_SRC = frozenset({"test", "tests", "mock", "mocks"})

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
STATE = re.compile(
    r"^\s*(?:mapping\s*\([^;]+|[A-Za-z_][A-Za-z0-9_<>,\\[\\]. ]+)\s+"
    r"(?:public|private|internal|constant|immutable|override|\s)*"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:=|;)",
    re.MULTILINE,
)
RISK_LINE = re.compile(
    r"\b(delegatecall|selfdestruct|tx\.origin|assembly|unchecked|\.call\s*\{|"
    r"onlyOwner|onlyRole|upgradeTo|initialize|withdraw|redeem|borrow|liquidat|"
    r"transferFrom|ecrecover|permit)\b",
    re.IGNORECASE,
)

MAX_FILES = 70
MAX_BYTES = 260_000
DIGEST_CHARS = 18_000
BATCH_CHARS = 31_000
RELATED_CHARS = 3_500
MAX_FINDINGS = 8
RUN_BUDGET = 225.0
HTTP_TIMEOUT = 145

NAME_HINTS = (
    "vault", "pool", "router", "bridge", "proxy", "upgrade", "oracle", "govern",
    "treasury", "manager", "market", "lend", "borrow", "collateral", "controller",
    "strategy", "auction", "token", "admin", "owner", "swap", "staking", "reward",
)

AUDITOR = (
    "You are a senior smart-contract security auditor. Return only real high or "
    "critical vulnerabilities with a concrete exploit path and material impact. "
    "Reject style, gas, missing events, and speculation. Return strict JSON only."
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
    by_name = {Path(r["rel"]).name: r for r in records}
    raw: list[dict[str, Any]] = []

    targets, triage_hits = _triage(inference_api, records)
    raw.extend(triage_hits)

    first_batch, second_batch = _choose_batches(targets, records)
    if time.monotonic() - started < RUN_BUDGET:
        raw.extend(_deep_audit(inference_api, first_batch, by_name))
    if time.monotonic() - started < RUN_BUDGET:
        raw.extend(_deep_audit(inference_api, second_batch, by_name))

    for item in raw:
        norm = _normalize(item, rel_map)
        if norm is not None:
            findings.append(norm)
    return {"vulnerabilities": _dedupe(findings)}


def _project_root(project_dir: str | None) -> Path | None:
    candidates: list[str] = []
    if project_dir:
        candidates.append(project_dir)
    for env in ("PROJECT_DIR", "PROJECT_PATH", "PROJECT_ROOT", "PROJECT_CODE"):
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


def _skip_parts(parts: tuple[str, ...]) -> bool:
    if not parts:
        return False
    in_src = "src" in {p.lower() for p in parts}
    for part in parts:
        low = part.lower()
        if in_src:
            if low in SKIP_UNDER_SRC:
                return True
        elif low in SKIP_OUTSIDE_SRC:
            return True
    return False


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _functions(text: str) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for match in FUNC_SOL.finditer(text):
        tail = " ".join(match.group(3).split())
        out.append({"name": match.group(1), "sig": f"{match.group(1)}({match.group(2).strip()}) {tail}".strip()})
    for match in FUNC_VY.finditer(text):
        out.append({"name": match.group(1), "sig": match.group(1)})
    return out


def _score(rel: str, text: str) -> int:
    low_name = rel.lower()
    low_text = text.lower()
    score = min(low_text.count("function ") + low_text.count("\ndef "), 32)
    for term in NAME_HINTS:
        if term in low_name:
            score += 8
        elif term in low_text:
            score += 2
    for match in RISK_LINE.finditer(text):
        score += 3
    if "external" in low_text or "public" in low_text or "@external" in low_text:
        score += 4
    if "nonreentrant" not in low_text and ".call" in low_text:
        score += 3
    return score


def _state_vars(text: str) -> list[str]:
    names: list[str] = []
    for name in STATE.findall(text):
        if name not in names and len(name) < 40:
            names.append(name)
    return names[:14]


def _risk_lines(text: str) -> list[str]:
    lines: list[str] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        if RISK_LINE.search(line):
            compact = " ".join(line.strip().split())
            if compact:
                lines.append(f"{idx}: {compact[:160]}")
        if len(lines) >= 14:
            break
    return lines


def _discover(root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in EXTS:
            continue
        try:
            rel_path = path.relative_to(root)
            if _skip_parts(tuple(rel_path.parts[:-1])):
                continue
            if path.stat().st_size > MAX_BYTES:
                continue
        except OSError:
            continue
        text = _read(path)
        if not any(tok in text for tok in ("function", "contract ", "library ", "\ndef ")):
            continue
        rel = rel_path.as_posix()
        contracts = CONTRACT.findall(text)
        if not contracts and path.suffix.lower() == ".vy":
            contracts = [path.stem]
        rows.append({
            "path": path,
            "rel": rel,
            "text": text,
            "contracts": contracts,
            "functions": _functions(text),
            "score": _score(rel, text),
        })
    rows.sort(key=lambda r: (-int(r["score"]), str(r["rel"])))
    return rows[:MAX_FILES]


def _digest(records: list[dict[str, Any]]) -> str:
    chunks: list[str] = []
    for rec in records:
        chunks.append(json.dumps({
            "file": rec["rel"],
            "language": Path(str(rec["rel"])).suffix.lstrip("."),
            "contracts": rec["contracts"][:6],
            "score": rec["score"],
            "state": _state_vars(str(rec["text"])),
            "functions": [f["sig"][:140] for f in rec["functions"][:22]],
            "risk_lines": _risk_lines(str(rec["text"])),
        }, separators=(",", ":")))
    return "\n".join(chunks)[:DIGEST_CHARS]


def _related(rec: dict[str, Any], by_name: dict[str, dict[str, Any]]) -> str:
    parts: list[str] = []
    for imp in IMPORT.findall(str(rec["text"])):
        base = imp.rsplit("/", 1)[-1]
        other = by_name.get(base)
        if other and other["rel"] != rec["rel"]:
            parts.append(f"// import {other['rel']}\n{str(other['text'])[:RELATED_CHARS]}")
        if len(parts) >= 2:
            break
    return "\n\n".join(parts)[:RELATED_CHARS * 2]


def _request(inference_api: str | None, messages: list[dict[str, str]], max_tokens: int) -> str:
    endpoint = (inference_api or os.environ.get("INFERENCE_API") or "").rstrip("/")
    if not endpoint:
        raise RuntimeError("missing inference endpoint")
    body = json.dumps({
        "messages": messages,
        "max_tokens": max_tokens,
        "reasoning": {"effort": "low", "exclude": True},
    }).encode("utf-8")
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
            time.sleep(1.5)
    raise RuntimeError(f"inference failed: {last}")


def _content(payload: dict[str, Any]) -> str:
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        return ""
    msg = choices[0].get("message") if isinstance(choices[0], dict) else None
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
                    obj = json.loads(stripped[start : idx + 1])
                    return obj if isinstance(obj, dict) else {}
                except json.JSONDecodeError:
                    return {}
    return {}


def _triage(inference_api: str | None, records: list[dict[str, Any]]) -> tuple[list[str], list[dict[str, Any]]]:
    prompt = (
        "Review this repository map and pick the files most likely to contain exploitable "
        "high or critical bugs. Return strict JSON only:\n"
        '{"target_files":["path/to/File.sol"],"findings":[{"title":"Contract.function - bug",'
        '"file":"path/to/File.sol","contract":"Contract","function":"functionName",'
        '"severity":"high|critical","mechanism":"precondition -> action -> effect",'
        '"impact":"material loss or privilege impact",'
        '"description":"2-4 precise sentences"}]}\n'
        "Prioritize access-control gaps, unsafe external calls, accounting/oracle mistakes, "
        "and reentrancy. Prefer precision over volume. Do not invent files or functions.\n\n"
        + _digest(records)
    )
    try:
        obj = _parse_json(_request(
            inference_api,
            [{"role": "system", "content": AUDITOR}, {"role": "user", "content": prompt}],
            5000,
        ))
    except Exception:
        return [], []
    targets = obj.get("target_files")
    findings = obj.get("findings") or obj.get("vulnerabilities") or []
    return (
        [str(x) for x in targets if isinstance(x, str)] if isinstance(targets, list) else [],
        [x for x in findings if isinstance(x, dict)] if isinstance(findings, list) else [],
    )


def _batch_prompt(batch: list[dict[str, Any]], by_name: dict[str, dict[str, Any]]) -> str:
    header = (
        "Deep-audit the sources below. Return strict JSON only:\n"
        '{"findings":[{"title":"Contract.function - specific bug","file":"exact/path",'
        '"contract":"Contract","function":"functionName","line":123,"severity":"high|critical",'
        '"mechanism":"preconditions -> attacker action -> broken invariant",'
        '"impact":"specific loss/insolvency/privilege/DoS impact",'
        '"description":"2-4 sentences naming file, contract, function, mechanism, and impact"}]}\n'
        "At most 5 findings. Omit anything that is not clearly exploitable.\n"
    )
    parts = [header]
    remaining = BATCH_CHARS - len(header)
    for rec in batch:
        block = f"\n\n===== FILE: {rec['rel']} =====\nContracts: {', '.join(rec['contracts'][:6])}\n{rec['text']}\n"
        related = _related(rec, by_name)
        if related:
            block += f"\n===== IMPORT CONTEXT =====\n{related}\n"
        if len(block) > remaining:
            block = block[: max(0, remaining)] + "\n/* truncated */\n"
        if remaining <= 0:
            break
        parts.append(block)
        remaining -= len(block)
    return "".join(parts)


def _deep_audit(
    inference_api: str | None,
    batch: list[dict[str, Any]],
    by_name: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    if not batch:
        return []
    try:
        obj = _parse_json(_request(
            inference_api,
            [{"role": "system", "content": AUDITOR}, {"role": "user", "content": _batch_prompt(batch, by_name)}],
            8000,
        ))
    except urllib.error.HTTPError:
        return []
    except Exception:
        return []
    findings = obj.get("findings") or obj.get("vulnerabilities") or []
    return [x for x in findings if isinstance(x, dict)] if isinstance(findings, list) else []


def _choose_batches(targets: list[str], records: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rel_map = {r["rel"]: r for r in records}
    ordered: list[dict[str, Any]] = []
    for target in targets:
        for rel, rec in rel_map.items():
            if target == rel or rel.endswith(target) or target.endswith(rel):
                if rec not in ordered:
                    ordered.append(rec)
                break
    for rec in records:
        if rec not in ordered:
            ordered.append(rec)
    return ordered[:3], ordered[3:7]


def _line_for(text: str, needle: str) -> int | None:
    if not needle:
        return None
    idx = text.find(needle)
    return None if idx < 0 else text.count("\n", 0, idx) + 1


def _normalize(raw: dict[str, Any], rel_map: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    file_value = str(raw.get("file") or raw.get("path") or "").strip()
    chosen = None
    for rel, rec in rel_map.items():
        if file_value == rel or rel.endswith(file_value) or file_value.endswith(rel):
            chosen, file_value = rec, rel
            break
    if chosen is None:
        return None
    severity = str(raw.get("severity") or "").lower().strip()
    if severity not in {"high", "critical"}:
        return None
    function = str(raw.get("function") or "").strip().strip("`() ")
    if "." in function:
        function = function.split(".")[-1]
    valid = {f["name"] for f in chosen["functions"]}
    if function and function not in valid:
        function = ""
    contract = str(raw.get("contract") or "").strip().strip("`")
    if not contract and chosen["contracts"]:
        contract = str(chosen["contracts"][0])
    mechanism = str(raw.get("mechanism") or "").strip()
    impact = str(raw.get("impact") or "").strip()
    description = str(raw.get("description") or "").strip()
    title = str(raw.get("title") or "").strip()
    if len(mechanism) < 20 and len(description) < 100:
        return None
    loc = ".".join(x for x in (contract, function) if x)
    if not title:
        title = f"{loc or file_value} - high-impact vulnerability"
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
    if len(description) < 100:
        return None
    line = raw.get("line")
    if not isinstance(line, int) and function:
        line = _line_for(str(chosen["text"]), f"function {function}")
    return {
        "title": title[:220],
        "description": description[:3000],
        "severity": severity,
        "file": file_value,
        "function": function,
        "line": line if isinstance(line, int) else None,
        "type": str(raw.get("type") or "logic"),
        "confidence": 0.9 if severity == "critical" else 0.84,
    }


def _dedupe(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str]] = set()
    out: list[dict[str, Any]] = []
    ordered = sorted(
        items,
        key=lambda f: (f.get("severity") == "critical", float(f.get("confidence") or 0), len(str(f.get("description") or ""))),
        reverse=True,
    )
    for item in ordered:
        key = (
            str(item.get("file") or "").lower(),
            str(item.get("function") or "").lower(),
            str(item.get("title") or "").lower()[:100],
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
