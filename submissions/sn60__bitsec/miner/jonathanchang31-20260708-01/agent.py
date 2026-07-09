from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


SOURCE_EXTS = {".sol", ".vy", ".rs", ".move"}
SKIP_PARTS = {
    ".git",
    ".github",
    "artifacts",
    "broadcast",
    "cache",
    "coverage",
    "docs",
    "example",
    "examples",
    "lib",
    "mocks",
    "node_modules",
    "out",
    "script",
    "scripts",
    "test",
    "tests",
    "vendor",
}

MAX_FILES = 80
MAX_BYTES_PER_FILE = 240_000
MAX_MAP_CHARS = 17_000
MAX_SOURCE_CHARS = 38_000
MAX_RESULTS = 8
MAX_SECONDS = 245
TIMEOUT_SECONDS = 155

SOL_CONTRACT_RE = re.compile(r"\b(?:abstract\s+contract|contract|library|interface)\s+([A-Za-z_][A-Za-z0-9_]*)")
SOL_FUNCTION_RE = re.compile(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*([^{};]*)(?:\{|;)")
VY_FUNCTION_RE = re.compile(r"(?m)^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*(?:->\s*([^:]+))?:")
RS_FUNCTION_RE = re.compile(r"(?m)^\s*(?:pub\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
MOVE_FUNCTION_RE = re.compile(r"(?m)^\s*(?:public\s+)?(?:entry\s+)?fun\s+([A-Za-z_][A-Za-z0-9_]*)\s*<*")
IMPORT_RE = re.compile(r"(?m)^\s*import\b[^;]*?[\"']([^\"']+)[\"']")

RISK_WORDS = (
    "swap",
    "exchange",
    "liquidity",
    "withdraw",
    "redeem",
    "deposit",
    "borrow",
    "repay",
    "liquidat",
    "oracle",
    "price",
    "reward",
    "claim",
    "mint",
    "burn",
    "shares",
    "vault",
    "pool",
    "router",
    "market",
    "escrow",
    "auction",
    "vesting",
    "signature",
    "permit",
    "nonce",
    "delegatecall",
    "raw_call",
    ".call{",
    ".call(",
    "selfdestruct",
    "tx.origin",
    "unchecked",
    "assembly",
    "initialize",
    "upgrade",
    "admin",
    "fee",
    "rate",
    "invariant",
)

SYSTEM_PROMPT = (
    "You are auditing smart-contract source for exploitable high or critical security bugs. "
    "Return only issues supported by the provided code. Ignore style, gas, missing events, "
    "centralization complaints, generic best practices, and low-confidence guesses. "
    "The final answer must be valid JSON only."
)


def agent_main(project_dir: str | None = None, inference_api: str | None = None) -> dict:
    started = time.monotonic()
    root = _find_root(project_dir)
    if root is None:
        return _empty_report()

    files = _collect_files(root)
    if not files:
        return _empty_report()

    by_rel = {item["rel"]: item for item in files}
    by_name = {Path(item["rel"]).name: item for item in files}
    raw: list[dict[str, Any]] = []

    raw.extend(_local_patterns(files))

    selected, first = _map_pass(inference_api, files)
    raw.extend(first)

    batch_a, batch_b = _split_batches(selected, files)
    if time.monotonic() - started < MAX_SECONDS:
        raw.extend(_source_pass(inference_api, batch_a, by_name, "primary"))
    if time.monotonic() - started < MAX_SECONDS:
        raw.extend(_source_pass(inference_api, batch_b, by_name, "secondary"))

    normalized = []
    for item in raw:
        finding = _normalize(item, by_rel)
        if finding is not None:
            normalized.append(finding)
    return {"vulnerabilities": _dedupe(normalized)}


def _empty_report() -> dict:
    findings: list[dict[str, Any]] = []
    return {"vulnerabilities": findings}


def _find_root(project_dir: str | None) -> Path | None:
    candidates = []
    if project_dir:
        candidates.append(project_dir)
    for key in ("PROJECT_DIR", "PROJECT_PATH", "PROJECT_ROOT", "PROJECT_CODE"):
        value = os.environ.get(key)
        if value:
            candidates.append(value)
    candidates.extend(("/app/project_code", "/app/project", "/project", "/code", "."))
    for raw in candidates:
        try:
            root = Path(raw).expanduser().resolve()
        except OSError:
            continue
        if not root.is_dir():
            continue
        try:
            if any(path.is_file() and path.suffix.lower() in SOURCE_EXTS for path in root.rglob("*")):
                return root
        except OSError:
            continue
    return None


def _collect_files(root: Path) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in SOURCE_EXTS:
            continue
        try:
            rel_path = path.relative_to(root)
            if any(part.lower() in SKIP_PARTS for part in rel_path.parts[:-1]):
                continue
            if path.stat().st_size > MAX_BYTES_PER_FILE:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if not _looks_like_source(text, path.suffix.lower()):
            continue
        rel = rel_path.as_posix()
        funcs = _functions(path.suffix.lower(), text)
        contracts = SOL_CONTRACT_RE.findall(text)
        if not contracts and path.suffix.lower() in {".vy", ".rs", ".move"}:
            contracts = [path.stem]
        items.append(
            {
                "path": path,
                "rel": rel,
                "text": text,
                "suffix": path.suffix.lower(),
                "contracts": contracts[:10],
                "functions": funcs[:80],
                "score": _risk_score(rel, text, funcs),
            }
        )
    items.sort(key=lambda item: (-int(item["score"]), str(item["rel"])))
    return items[:MAX_FILES]


def _looks_like_source(text: str, suffix: str) -> bool:
    if suffix == ".sol":
        return "contract " in text or "library " in text or "function " in text
    if suffix == ".vy":
        return "def " in text or "@external" in text
    if suffix == ".rs":
        return "fn " in text or "pub " in text
    if suffix == ".move":
        return "module " in text or "fun " in text
    return False


def _functions(suffix: str, text: str) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    if suffix == ".sol":
        for match in SOL_FUNCTION_RE.finditer(text):
            name = match.group(1)
            tail = " ".join(match.group(3).split())
            out.append({"name": name, "sig": f"{name}({match.group(2).strip()}) {tail}".strip()})
    elif suffix == ".vy":
        for match in VY_FUNCTION_RE.finditer(text):
            name = match.group(1)
            ret = f" -> {match.group(3).strip()}" if match.group(3) else ""
            out.append({"name": name, "sig": f"{name}({match.group(2).strip()}){ret}"})
    elif suffix == ".rs":
        out.extend({"name": m.group(1), "sig": m.group(0).strip()} for m in RS_FUNCTION_RE.finditer(text))
    elif suffix == ".move":
        out.extend({"name": m.group(1), "sig": m.group(0).strip()} for m in MOVE_FUNCTION_RE.finditer(text))
    return out


def _risk_score(rel: str, text: str, funcs: list[dict[str, str]]) -> int:
    low_rel = rel.lower()
    low = text.lower()
    score = min(len(funcs), 40)
    for word in RISK_WORDS:
        hits = low.count(word)
        score += min(hits, 7) * 3
        if word in low_rel:
            score += 8
    if "external" in low or "public" in low or "@external" in low:
        score += 8
    if any(x in low for x in ("balances", "totalsupply", "total_supply", "reserve", "invariant")):
        score += 8
    if any(x in low for x in ("onlyowner", "onlyrole", "accesscontrol", "auth", "permission")):
        score += 4
    return score


def _line_of(text: str, needle: str) -> int | None:
    if not needle:
        return None
    idx = text.find(needle)
    if idx < 0:
        return None
    return text.count("\n", 0, idx) + 1


def _risk_lines(text: str) -> list[str]:
    lowered_words = [x.lower() for x in RISK_WORDS]
    lines = []
    for number, line in enumerate(text.splitlines(), 1):
        low = line.lower()
        if any(word in low for word in lowered_words):
            compact = " ".join(line.strip().split())
            if compact:
                lines.append(f"{number}: {compact[:170]}")
        if len(lines) >= 16:
            break
    return lines


def _repo_map(files: list[dict[str, Any]]) -> str:
    rows = []
    for item in files:
        rows.append(
            json.dumps(
                {
                    "file": item["rel"],
                    "contracts": item["contracts"],
                    "functions": [fn["sig"][:170] for fn in item["functions"][:32]],
                    "risk_lines": _risk_lines(item["text"]),
                },
                separators=(",", ":"),
            )
        )
    return "\n".join(rows)[:MAX_MAP_CHARS]


def _call_model(inference_api: str | None, prompt: str, max_tokens: int) -> str:
    endpoint = (inference_api or os.environ.get("INFERENCE_API") or "").rstrip("/")
    if not endpoint:
        raise RuntimeError("missing inference endpoint")
    body = json.dumps(
        {
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "max_tokens": max_tokens,
        }
    ).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "x-inference-api-key": os.environ.get("INFERENCE_API_KEY", ""),
    }
    last: Exception | None = None
    for attempt in range(2):
        try:
            req = urllib.request.Request(endpoint + "/inference", data=body, method="POST", headers=headers)
            with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as response:
                data = json.loads(response.read().decode("utf-8", "replace"))
            return _message_content(data)
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                raise
            last = exc
        except (OSError, TimeoutError, ValueError) as exc:
            last = exc
        if attempt == 0:
            time.sleep(1.0)
    raise RuntimeError(f"inference failed: {last}")


def _message_content(data: dict[str, Any]) -> str:
    choices = data.get("choices")
    if not isinstance(choices, list) or not choices:
        return ""
    choice = choices[0]
    if not isinstance(choice, dict):
        return ""
    message = choice.get("message")
    if not isinstance(message, dict):
        return ""
    content = message.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(str(part.get("text") or "") for part in content if isinstance(part, dict))
    return ""


def _json_object(text: str) -> dict[str, Any]:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```[A-Za-z]*\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    try:
        value = json.loads(text)
        return value if isinstance(value, dict) else {}
    except json.JSONDecodeError:
        pass
    start = text.find("{")
    if start < 0:
        return {}
    depth = 0
    inside = False
    escaped = False
    for idx, ch in enumerate(text[start:], start):
        if inside:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                inside = False
            continue
        if ch == '"':
            inside = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                try:
                    value = json.loads(text[start : idx + 1])
                    return value if isinstance(value, dict) else {}
                except json.JSONDecodeError:
                    return {}
    return {}


def _map_pass(inference_api: str | None, files: list[dict[str, Any]]) -> tuple[list[str], list[dict[str, Any]]]:
    prompt = (
        "Review this repository map and choose the highest-risk files for a deeper audit. "
        "Also include any high-confidence bugs that are already clear from signatures and risk lines. "
        "Return exactly this JSON shape:\n"
        '{"target_files":["path"],"findings":[{"title":"short specific title","file":"path",'
        '"contract":"name","function":"name","line":1,"severity":"high|critical",'
        '"mechanism":"precondition -> attacker action -> broken state transition",'
        '"impact":"specific material loss or denial of critical action",'
        '"description":"2-4 precise sentences"}]}\n'
        "Focus on exploitable accounting, authorization, oracle, invariant, slippage, replay, liquidation, "
        "vesting, reward, and upgrade bugs. Do not invent files or functions.\n\n"
        + _repo_map(files)
    )
    try:
        obj = _json_object(_call_model(inference_api, prompt, 4200))
    except Exception:
        return [], []
    targets = obj.get("target_files")
    findings = obj.get("findings") or obj.get("vulnerabilities")
    return (
        [str(x) for x in targets if isinstance(x, str)] if isinstance(targets, list) else [],
        [x for x in findings if isinstance(x, dict)] if isinstance(findings, list) else [],
    )


def _split_batches(targets: list[str], files: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    ordered: list[dict[str, Any]] = []
    for target in targets:
        for item in files:
            rel = item["rel"]
            if target == rel or rel.endswith(target) or target.endswith(rel):
                if item not in ordered:
                    ordered.append(item)
                break
    for item in files:
        if item not in ordered:
            ordered.append(item)
    return ordered[:4], ordered[4:9]


def _import_context(item: dict[str, Any], by_name: dict[str, dict[str, Any]]) -> str:
    chunks = []
    for match in IMPORT_RE.finditer(item["text"]):
        name = match.group(1).rsplit("/", 1)[-1]
        other = by_name.get(name)
        if other and other["rel"] != item["rel"]:
            chunks.append(f"\n// Imported context: {other['rel']}\n{other['text'][:2600]}")
        if len(chunks) >= 2:
            break
    return "".join(chunks)


def _source_pass(
    inference_api: str | None,
    batch: list[dict[str, Any]],
    by_name: dict[str, dict[str, Any]],
    label: str,
) -> list[dict[str, Any]]:
    if not batch:
        return []
    header = (
        f"Deep audit the {label} source batch below. Return only concrete high or critical bugs. "
        "A valid issue must name the exact file/function, the exploitable state transition, and material impact. "
        "Return this JSON only:\n"
        '{"findings":[{"title":"Contract.function - specific bug","file":"exact/path",'
        '"contract":"Contract","function":"functionName","line":1,"severity":"high|critical",'
        '"mechanism":"precondition -> attacker transaction(s) -> broken state",'
        '"impact":"specific material impact",'
        '"description":"2-4 precise sentences using code details"}]}\n'
        "Prioritize value-moving math, reserve/share accounting, stale or manipulable prices, missing authority on "
        "privileged state changes, bad signature/nonce handling, unsafe external calls, liquidation edge cases, "
        "and critical user-action denial. Omit anything that is merely best practice or not exploitable.\n"
    )
    parts = [header]
    remaining = MAX_SOURCE_CHARS - len(header)
    for item in batch:
        block = (
            f"\n\n===== FILE: {item['rel']} =====\n"
            f"Contracts/modules: {', '.join(item['contracts'])}\n"
            f"{item['text']}"
            f"{_import_context(item, by_name)}\n"
        )
        if len(block) > remaining:
            block = block[: max(0, remaining)] + "\n/* truncated */\n"
        if remaining <= 0:
            break
        parts.append(block)
        remaining -= len(block)
    try:
        obj = _json_object(_call_model(inference_api, "".join(parts), 6200))
    except urllib.error.HTTPError:
        return []
    except Exception:
        return []
    findings = obj.get("findings") or obj.get("vulnerabilities")
    return [x for x in findings if isinstance(x, dict)] if isinstance(findings, list) else []


def _mk(
    *,
    title: str,
    file: str,
    contract: str,
    function: str,
    line: int | None,
    mechanism: str,
    impact: str,
) -> dict[str, Any]:
    return {
        "title": title,
        "file": file,
        "contract": contract,
        "function": function,
        "line": line,
        "severity": "high",
        "mechanism": mechanism,
        "impact": impact,
        "description": f"{mechanism} {impact}",
    }


def _local_patterns(files: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for item in files:
        rel = item["rel"]
        text = item["text"]
        low = text.lower()
        contract = item["contracts"][0] if item["contracts"] else Path(rel).stem
        if "tx.origin" in low:
            out.append(
                _mk(
                    title=f"{contract} - authorization depends on tx.origin",
                    file=rel,
                    contract=contract,
                    function=_nearest_function(item, "tx.origin"),
                    line=_line_of(low, "tx.origin"),
                    mechanism="The contract uses tx.origin in an authorization path, so a privileged user can be tricked through an intermediate contract into executing a protected action.",
                    impact="If the guarded action moves funds or changes protocol configuration, phishing a privileged account can lead to unauthorized state changes or asset loss.",
                )
            )
        if "delegatecall" in low and not any(x in low for x in ("onlyowner", "onlyrole", "requiresauth", "auth(")):
            out.append(
                _mk(
                    title=f"{contract} - delegatecall path lacks clear access control",
                    file=rel,
                    contract=contract,
                    function=_nearest_function(item, "delegatecall"),
                    line=_line_of(low, "delegatecall"),
                    mechanism="A delegatecall-capable path is reachable without an obvious owner or role guard in the same source, letting caller-controlled code execute in this contract's storage context.",
                    impact="An attacker can corrupt storage, change ownership, drain approved assets, or permanently break accounting if the delegated target is attacker controlled.",
                )
            )
        if ("function initialize" in low or "def initialize" in low) and not any(
            x in low for x in ("initializer", "onlyowner", "onlyrole", "assert self.owner", "require(msg.sender")
        ):
            out.append(
                _mk(
                    title=f"{contract}.initialize - initializer has no clear single-use authority guard",
                    file=rel,
                    contract=contract,
                    function="initialize",
                    line=_line_of(low, "initialize"),
                    mechanism="The initializer appears externally reachable without a clear one-time initializer modifier or caller authorization check.",
                    impact="A caller can initialize or reinitialize ownership and critical configuration before legitimate setup, taking control of privileged protocol actions.",
                )
            )
        for block in _solidity_blocks(text):
            body_low = block["body"].lower()
            name = block["name"]
            if (".call{" in body_low or ".call(" in body_low) and not any(
                guard in body_low for guard in ("nonreentrant", "reentrancyguard")
            ):
                call_pos = min(pos for pos in (body_low.find(".call{"), body_low.find(".call(")) if pos >= 0)
                after_call = body_low[call_pos:]
                if any(x in after_call for x in ("balances[", "balanceof[", "-=", "= 0", "total_supply", "totalsupply")):
                    out.append(
                        _mk(
                            title=f"{contract}.{name} - external call before accounting update",
                            file=rel,
                            contract=contract,
                            function=name,
                            line=block["line"],
                            mechanism="The function performs an external call before completing balance or supply accounting, and there is no visible non-reentrancy guard in the function body.",
                            impact="A malicious receiver can reenter while the old balance is still recorded, allowing repeated withdrawals or inconsistent accounting that can drain protocol funds.",
                        )
                    )
            if ("transferfrom(" in body_low or ".transfer(" in body_low) and any(
                x in body_low for x in ("shares", "amount", "balance", "reserve")
            ):
                if "safe" not in body_low and "require(" not in body_low.split("transfer", 1)[0][-120:]:
                    out.append(
                        _mk(
                            title=f"{contract}.{name} - token transfer result is not enforced",
                            file=rel,
                            contract=contract,
                            function=name,
                            line=block["line"],
                            mechanism="The function continues accounting around an ERC20 transfer call without clearly enforcing the returned success value or using a safe-transfer wrapper.",
                            impact="A non-standard token can make internal accounting advance without the expected asset movement, creating undercollateralized shares, unpaid purchases, or incorrect reserves.",
                        )
                    )
    return out[:4]


def _solidity_blocks(text: str) -> list[dict[str, Any]]:
    blocks: list[dict[str, Any]] = []
    for match in SOL_FUNCTION_RE.finditer(text):
        header_tail = match.group(3).lower()
        if "public" not in header_tail and "external" not in header_tail:
            continue
        start = text.find("{", match.end() - 1)
        if start < 0:
            continue
        depth = 0
        end = start
        for pos in range(start, len(text)):
            char = text[pos]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    end = pos + 1
                    break
        body = text[start:end]
        blocks.append(
            {
                "name": match.group(1),
                "body": body,
                "line": text.count("\n", 0, match.start()) + 1,
            }
        )
    return blocks


def _nearest_function(item: dict[str, Any], needle: str) -> str:
    text = item["text"]
    idx = text.lower().find(needle.lower())
    if idx < 0:
        return ""
    best = ""
    best_pos = -1
    for fn in item["functions"]:
        name = fn.get("name", "")
        pos = text.find(name)
        if 0 <= pos <= idx and pos > best_pos:
            best = name
            best_pos = pos
    return best


def _normalize(raw: dict[str, Any], by_rel: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    file_value = str(raw.get("file") or raw.get("path") or raw.get("location") or "").strip()
    if not file_value:
        return None
    chosen = None
    for rel, item in by_rel.items():
        if file_value == rel or rel.endswith(file_value) or file_value.endswith(rel) or Path(file_value).name == Path(rel).name:
            chosen = item
            file_value = rel
            break
    if chosen is None:
        return None

    severity = str(raw.get("severity") or "").strip().lower()
    if severity not in {"high", "critical"}:
        return None

    title = _clean(str(raw.get("title") or ""))
    description = _clean(str(raw.get("description") or ""))
    mechanism = _clean(str(raw.get("mechanism") or ""))
    impact = _clean(str(raw.get("impact") or ""))
    contract = _clean(str(raw.get("contract") or ""))
    function = _clean(str(raw.get("function") or "")).strip("`()")
    if "." in function:
        function = function.rsplit(".", 1)[-1]
    valid_functions = {fn["name"] for fn in chosen["functions"]}
    if function and valid_functions and function not in valid_functions:
        function = ""
    if not contract and chosen["contracts"]:
        contract = chosen["contracts"][0]
    if not title:
        title = f"{contract or Path(file_value).stem}.{function or 'logic'} - exploitable state inconsistency"
    if _looks_low_value(title + " " + description):
        return None

    parts = []
    where = f"In `{file_value}`"
    if contract:
        where += f", `{contract}`"
    if function:
        where += f".`{function}()`"
    parts.append(where + ".")
    if mechanism:
        parts.append("Mechanism: " + mechanism.rstrip(".") + ".")
    if impact:
        parts.append("Impact: " + impact.rstrip(".") + ".")
    if description:
        parts.append(description)
    full_description = " ".join(parts)
    if len(full_description) < 100:
        return None

    line = raw.get("line")
    if not isinstance(line, int):
        token = f"function {function}" if chosen["suffix"] == ".sol" and function else function
        line = _line_of(chosen["text"], token) if token else None

    return {
        "title": title[:220],
        "description": full_description[:2800],
        "severity": severity,
        "file": file_value,
        "function": function,
        "line": line if isinstance(line, int) else None,
        "confidence": 0.88 if severity == "high" else 0.92,
    }


def _clean(value: str) -> str:
    return " ".join(value.replace("\x00", " ").split())


def _looks_low_value(text: str) -> bool:
    low = text.lower()
    blocked = (
        "missing event",
        "emit event",
        "gas optimization",
        "pragma",
        "floating pragma",
        "centralization",
        "owner can",
        "best practice",
        "code style",
        "naming",
        "comment",
    )
    return any(word in low for word in blocked)


def _dedupe(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    ordered = sorted(
        items,
        key=lambda item: (
            str(item.get("severity")) == "critical",
            float(item.get("confidence") or 0),
            len(str(item.get("description") or "")),
        ),
        reverse=True,
    )
    result = []
    for item in ordered:
        key = (
            str(item.get("file") or "").lower(),
            str(item.get("function") or "").lower(),
            re.sub(r"[^a-z0-9]+", " ", str(item.get("title") or "").lower())[:120],
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
        if len(result) >= MAX_RESULTS:
            break
    return result


if __name__ == "__main__":
    import sys

    print(json.dumps(agent_main(sys.argv[1] if len(sys.argv) > 1 else None), indent=2))