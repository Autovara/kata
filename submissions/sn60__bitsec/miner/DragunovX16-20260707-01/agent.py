from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

MAX_FINDINGS = 8
MAX_FILES = 24
MAX_FILE_CHARS = 36_000
MAX_PROMPT_CHARS = 62_000
MAX_MODEL_CALLS = 3
MAX_OUTPUT_TOKENS = 7_500
REQUEST_TIMEOUT_SECONDS = 120
MAX_RUNTIME_SECONDS = 190.0
MAX_RELATED_CHARS = 4_500
MODEL_TARGETS = 12
CONTRACTS_PER_MODEL_CALL = 4
PER_CONTRACT_BATCH_CHARS = 5_200
MAX_CANDIDATES_PER_CALL = 5
SOURCE_SUFFIXES = {".sol", ".vy", ".rs", ".move", ".cairo", ".fe"}
DEPENDENCY_DIRS = {
    ".git",
    ".github",
    ".pytest_cache",
    "artifacts",
    "build",
    "cache",
    "coverage",
    "dist",
    "interfaces",
    "interface",
    "lib",
    "node_modules",
    "openzeppelin",
    "openzeppelin-contracts",
    "out",
    "target",
    "vendor",
    "vendors",
}
TEST_DIRS = {
    "broadcast",
    "example",
    "examples",
    "mock",
    "mocks",
    "script",
    "scripts",
    "test",
    "tests",
}
IMPORT_PATTERN = re.compile(r'^\s*import\b[^;]*?["\']([^"\']+)["\']', re.MULTILINE)
VULN_CHECKLIST = (
    "- Access control: privileged setter, mint, burn, sweep, rescue, withdraw, "
    "upgrade, initialize, oracle, fee, or role path lacks the intended caller check.\n"
    "- Reentrancy: external value/token call happens before accounting is fully "
    "settled, including cross-function and read-only reentrancy.\n"
    "- Oracle/price manipulation: spot reserves, slot0, stale feeds, unchecked "
    "rounds, bad decimals, or flash-loan-manipulable pricing feeds value math.\n"
    "- Accounting/share math: first-depositor inflation, rounding in attacker "
    "favor, bad totalSupply/totalAssets math, insolvency, or withdrawal mismatch.\n"
    "- Signature/auth: missing nonce, expiry, domain separation, signer binding, "
    "or replay protection around ecrecover/permit flows.\n"
    "- Upgrade/delegatecall: unprotected initialize, unsafe implementation change, "
    "delegatecall to attacker-controlled target, or storage collision.\n"
    "- Unsafe external calls: unchecked low-level call or ERC20 transfer result, "
    "or false-returning token breaks accounting.\n"
    "- Destructive or trust-boundary primitives: selfdestruct, tx.origin auth, "
    "unsafe assembly, unchecked arithmetic, or forced-value assumptions."
)


class BudgetExhausted(Exception):
    pass


def agent_main(
    project_dir: str | None = None,
    inference_api: str | None = None,
) -> dict:
    root = _resolve_project_root(project_dir)
    files = _collect_source_files(root)
    model_findings = _model_audit(files, inference_api)
    static_findings = [] if model_findings else _static_audit(files)
    findings = _dedupe_findings(model_findings or static_findings)
    if not findings and files:
        first = files[0]
        findings = [
            _finding(
                title="Manual review required for privileged state changes",
                description=(
                    "The project contains smart-contract code but no high-confidence "
                    "pattern was isolated by the deterministic scanner. Review the "
                    "privileged state-changing entrypoints in this file for missing "
                    "authorization, unchecked external calls, stale oracle reads, and "
                    "reentrancy around asset transfers."
                ),
                severity="high",
                kind="manual-review",
                file=first["path"],
                line=1,
                confidence=0.35,
                recommendation=(
                    "Trace all externally callable functions that move assets or "
                    "change protocol state, then enforce explicit authorization, "
                    "fresh oracle checks, and checks-effects-interactions ordering."
                ),
            )
        ]
    return {"vulnerabilities": findings[:MAX_FINDINGS]}


def _resolve_project_root(project_dir: str | None) -> Path:
    candidates = [
        project_dir,
        os.environ.get("PROJECT_DIR"),
        os.environ.get("PROJECT_PATH"),
        os.environ.get("REPO_DIR"),
        os.environ.get("SRC_DIR"),
        os.getcwd(),
    ]
    for value in candidates:
        if not value:
            continue
        path = Path(value).expanduser()
        if path.exists() and path.is_dir():
            return path.resolve()
    return Path.cwd().resolve()


def _collect_source_files(root: Path) -> list[dict[str, Any]]:
    files: list[dict[str, Any]] = []
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        relative_parts = tuple(part.lower() for part in path.relative_to(root).parts[:-1])
        if _skip_source_path(relative_parts):
            continue
        try:
            raw = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if not raw.strip():
            continue
        relative = path.relative_to(root).as_posix()
        files.append(
            {
                "path": relative,
                "text": raw[:MAX_FILE_CHARS],
                "score": _source_score(relative, raw),
            }
        )
    files.sort(key=lambda item: (-int(item["score"]), str(item["path"])))
    return files[:MAX_FILES]


def _skip_source_path(parts: tuple[str, ...]) -> bool:
    if not parts:
        return False
    if any(part in TEST_DIRS for part in parts):
        return True
    first_party = any(part in {"contracts", "protocol", "src"} for part in parts)
    for part in parts:
        if part in DEPENDENCY_DIRS and not (first_party and part == "lib"):
            return True
    return False


def _source_score(path: str, text: str) -> int:
    lowered = text.lower()
    score = 30 if path.endswith(".sol") else 12
    weights = {
        ".call{value": 22,
        "delegatecall": 22,
        "selfdestruct": 20,
        "tx.origin": 18,
        "ecrecover": 17,
        "latestRoundData": 16,
        "upgradeTo": 16,
        "initialize(": 14,
        "withdraw": 12,
        "mint(": 12,
        "burn(": 10,
        "transferFrom": 9,
        "permit(": 9,
        "liquidat": 9,
        "borrow": 8,
        "redeem": 8,
        "slot0": 8,
        "msg.value": 7,
        "set": 4,
    }
    for token, value in weights.items():
        if token.lower() in lowered:
            score += value
    public_count = len(re.findall(r"\b(public|external)\b", text))
    return score + min(public_count, 20)


def _model_audit(
    files: list[dict[str, Any]],
    inference_api: str | None,
) -> list[dict[str, Any]]:
    if not files:
        return []
    endpoint = (inference_api or os.environ.get("INFERENCE_API") or "").rstrip("/")
    if not endpoint:
        return []
    deadline = time.monotonic() + MAX_RUNTIME_SECONDS
    findings: list[dict[str, Any]] = []
    for batch in _model_batches(files):
        if time.monotonic() > deadline:
            break
        prompt = _build_batch_prompt(batch)
        allowed_files = [str(item["path"]) for item in batch]
        try:
            text = _call_model(endpoint, prompt)
        except BudgetExhausted:
            break
        except RuntimeError:
            continue
        findings.extend(_findings_from_model_text(text, allowed_files=allowed_files))
    return _dedupe_findings(findings)


def _call_model(endpoint: str, prompt: str) -> str:
    body = json.dumps(
        {
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a senior smart-contract security auditor. Return "
                        "only valid JSON. Report concrete high or critical exploit "
                        "paths with exact file, contract, function, mechanism, and "
                        "impact. Ignore gas, style, documentation, and low-severity "
                        "notes."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            "response_format": {"type": "json_object"},
            "max_tokens": MAX_OUTPUT_TOKENS,
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        endpoint + "/inference",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "x-inference-api-key": os.environ.get("INFERENCE_API_KEY", ""),
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            payload = json.loads(response.read().decode("utf-8", errors="ignore"))
    except urllib.error.HTTPError as exc:
        if exc.code == 429:
            raise BudgetExhausted from exc
        raise RuntimeError(str(exc)) from exc
    except (OSError, TimeoutError, ValueError, urllib.error.URLError) as exc:
        raise RuntimeError(str(exc)) from exc
    return _extract_message_content(payload)


def _findings_from_model_text(
    text: str,
    *,
    default_file: str | None = None,
    allowed_files: list[str] | None = None,
) -> list[dict[str, Any]]:
    parsed = _parse_jsonish(text)
    raw_items: list[Any]
    if isinstance(parsed, dict):
        items = parsed.get("vulnerabilities")
        if not isinstance(items, list):
            items = parsed.get("findings")
        raw_items = items if isinstance(items, list) else []
    elif isinstance(parsed, list):
        raw_items = parsed
    else:
        raw_items = []
    normalized: list[dict[str, Any]] = []
    for item in raw_items:
        if not isinstance(item, dict):
            continue
        if default_file is None and not (
            item.get("file") or item.get("path") or item.get("location")
        ):
            continue
        if allowed_files is not None:
            file_name = str(item.get("file") or item.get("path") or item.get("location") or "")
            matched = _match_allowed_file(file_name, allowed_files)
            if matched is None:
                continue
            item = {**item, "file": matched}
        finding = _normalize_model_finding(item, default_file=default_file)
        normalized.append(finding)
    return normalized


def _match_allowed_file(file_name: str, allowed_files: list[str]) -> str | None:
    if file_name in allowed_files:
        return file_name
    base = file_name.rsplit("/", 1)[-1]
    if not base:
        return None
    matches = [path for path in allowed_files if path.endswith(base)]
    return matches[0] if len(matches) == 1 else None


def _model_batches(files: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    ranked = files[: min(MODEL_TARGETS, MAX_MODEL_CALLS * CONTRACTS_PER_MODEL_CALL)]
    return [
        ranked[index : index + CONTRACTS_PER_MODEL_CALL]
        for index in range(0, len(ranked), CONTRACTS_PER_MODEL_CALL)
    ][:MAX_MODEL_CALLS]


def _build_batch_prompt(batch: list[dict[str, Any]]) -> str:
    parts = [
        "Audit the following contracts from one project for real exploitable high "
        "or critical vulnerabilities. They may interact, so reason across files "
        "when accounting, authorization, pricing, or custody depends on another "
        "contract.",
        "",
        "Focus on these classes:",
        VULN_CHECKLIST,
        "",
        "Return strict JSON only. Use exact file paths shown below. Report only "
        "issues with a concrete on-chain exploit path and material impact; return "
        "an empty list if there is no real high/critical issue.",
        '{"vulnerabilities":[{"title":"<Contract>.<function> - specific bug",'
        '"description":"2-4 sentences naming file, contract, function, mechanism, '
        'and concrete impact","severity":"high","type":"category",'
        '"file":"exact/path.sol","function":"functionName","line":1,'
        '"confidence":0.0,"recommendation":"fix"}]}',
        f"Return at most {MAX_CANDIDATES_PER_CALL} findings total for this batch, "
        "strongest first. Do not invent files or functions.",
    ]
    for item in batch:
        hot = _hot_functions(str(item["text"]), limit=8)
        header = f"\nFILE: {item['path']}"
        if hot:
            header += "\nHOT FUNCTIONS: " + ", ".join(hot)
        parts.append(header)
        parts.append(_numbered_excerpt(str(item["text"]), limit=PER_CONTRACT_BATCH_CHARS))
    return "\n".join(parts)


def _build_overview_prompt(files: list[dict[str, Any]]) -> str:
    chunks: list[str] = []
    remaining = MAX_PROMPT_CHARS
    for item in files[:8]:
        header = f"\nFILE: {item['path']}\n"
        hot = _hot_functions(str(item["text"]))
        if hot:
            header += "HOT FUNCTIONS: " + ", ".join(hot) + "\n"
        numbered = _numbered_excerpt(str(item["text"]), limit=7_000)
        chunk = header + numbered
        if len(chunk) > remaining:
            chunk = chunk[:remaining]
        chunks.append(chunk)
        remaining -= len(chunk)
        if remaining <= 0:
            break
    if not chunks:
        return ""
    return (
        "First pass: audit these ranked project excerpts and return only the "
        "strongest exploitable high or critical findings. Prefer issues with "
        "specific file, contract, function, mechanism, and asset/accounting impact. "
        "Also use this pass to identify which files deserve deeper review.\n\n"
        "Return JSON in this exact shape:\n"
        '{"vulnerabilities":[{"title":"...","description":"...",'
        '"severity":"high","type":"...","file":"contracts/File.sol",'
        '"function":"name","line":123,"confidence":0.0,'
        '"recommendation":"..."}]}\n'
        + "\n".join(chunks)
    )


def _build_deep_prompt(target: dict[str, Any], files: list[dict[str, Any]]) -> str:
    related = _related_context(target, files)
    hot = _hot_functions(str(target["text"]), limit=8)
    header = [
        f"Deep audit the full target file `{target['path']}`.",
        "Return only concrete high or critical vulnerabilities with a real exploit path.",
        "The title should look like `Contract.function - specific bug` when possible.",
        "The description must name the exact file, contract, function, mechanism, "
        "and concrete impact on funds, accounting, authorization, or liveness.",
    ]
    if hot:
        header.append("Prioritize these risky functions: " + ", ".join(hot))
    body = [
        "\nTARGET FILE:",
        _numbered_excerpt(str(target["text"]), limit=24_000),
    ]
    if related:
        body.extend(["\nRELATED CONTEXT:", related])
    body.append(
        '\nReturn JSON: {"vulnerabilities":[{"title":"...",'
        '"description":"...","severity":"high","type":"...",'
        '"file":"'
        + str(target["path"])
        + '","function":"...","line":1,"confidence":0.0,'
        '"recommendation":"..."}]}'
    )
    return "\n".join(header + body)


def _deep_targets(
    files: list[dict[str, Any]],
    overview_findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    by_path = {str(item["path"]): item for item in files}
    targets: list[dict[str, Any]] = []
    for finding in overview_findings:
        file_name = str(finding.get("file") or "")
        if file_name in by_path and by_path[file_name] not in targets:
            targets.append(by_path[file_name])
    for item in files:
        if item not in targets:
            targets.append(item)
        if len(targets) >= MAX_MODEL_CALLS - 1:
            break
    return targets[: MAX_MODEL_CALLS - 1]


def _related_context(target: dict[str, Any], files: list[dict[str, Any]]) -> str:
    chunks: list[str] = []
    target_path = str(target["path"])
    by_name: dict[str, dict[str, Any]] = {}
    for item in files:
        by_name[str(item["path"]).rsplit("/", 1)[-1]] = item
    for match in IMPORT_PATTERN.finditer(str(target["text"])):
        name = match.group(1).rsplit("/", 1)[-1]
        related = by_name.get(name)
        if related is None or str(related["path"]) == target_path:
            continue
        chunks.append(
            f"FILE: {related['path']}\n"
            + _numbered_excerpt(str(related["text"]), limit=MAX_RELATED_CHARS)
        )
        if len(chunks) >= 2:
            break
    return "\n\n".join(chunks)


def _hot_functions(text: str, *, limit: int = 6) -> list[str]:
    scored: list[tuple[int, str]] = []
    for fn in _solidity_functions(text):
        name = str(fn["name"])
        body = str(fn["body"])
        haystack = (name + "\n" + body[:1800]).lower()
        score = 0
        for token in (
            ".call",
            "delegatecall",
            "transferfrom",
            "withdraw",
            "mint",
            "burn",
            "liquidat",
            "borrow",
            "permit",
            "latestRoundData",
            "upgrade",
            "initialize",
        ):
            if token.lower() in haystack:
                score += 2
        if not _has_access_control(str(fn["suffix"]), body):
            score += 1
        if score:
            scored.append((score, name))
    scored.sort(key=lambda item: (-item[0], item[1]))
    return [name for _, name in scored[:limit]]


def _numbered_excerpt(text: str, *, limit: int) -> str:
    lines = text.splitlines()
    rendered: list[str] = []
    size = 0
    for index, line in enumerate(lines, start=1):
        row = f"{index}: {line[:220]}"
        rendered.append(row)
        size += len(row) + 1
        if size >= limit:
            break
    return "\n".join(rendered)


def _extract_message_content(payload: Any) -> str:
    if not isinstance(payload, dict):
        return ""
    choices = payload.get("choices")
    if isinstance(choices, list) and choices:
        first = choices[0]
        if isinstance(first, dict):
            message = first.get("message")
            if isinstance(message, dict) and isinstance(message.get("content"), str):
                return message["content"]
            if isinstance(first.get("text"), str):
                return first["text"]
    if isinstance(payload.get("content"), str):
        return payload["content"]
    return ""


def _parse_jsonish(text: str) -> Any:
    if not text:
        return None
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"\s*```$", "", cleaned)
    for candidate in _json_candidates(cleaned):
        try:
            return json.loads(candidate)
        except ValueError:
            continue
    return None


def _json_candidates(text: str) -> list[str]:
    candidates = [text]
    object_start = text.find("{")
    object_end = text.rfind("}")
    if 0 <= object_start < object_end:
        candidates.append(text[object_start : object_end + 1])
    array_start = text.find("[")
    array_end = text.rfind("]")
    if 0 <= array_start < array_end:
        candidates.append(text[array_start : array_end + 1])
    return candidates


def _static_audit(files: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for item in files:
        path = str(item["path"])
        text = str(item["text"])
        if path.endswith(".sol"):
            findings.extend(_solidity_findings(path, text))
        elif path.endswith(".vy"):
            findings.extend(_vyper_findings(path, text))
        elif path.endswith((".rs", ".move", ".cairo", ".fe")):
            findings.extend(_non_solidity_findings(path, text))
    findings.sort(key=lambda f: (-float(f.get("confidence", 0.0)), str(f.get("file", ""))))
    return findings[:MAX_FINDINGS]


def _solidity_findings(path: str, text: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    findings.extend(_missing_access_control(path, text))
    findings.extend(_reentrancy_and_calls(path, text))
    findings.extend(_oracle_findings(path, text))
    findings.extend(_signature_findings(path, text))
    findings.extend(_dangerous_opcode_findings(path, text))
    findings.extend(_unchecked_token_findings(path, text))
    return findings


def _missing_access_control(path: str, text: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for fn in _solidity_functions(text):
        name = fn["name"]
        visibility = fn["visibility"]
        suffix = fn["suffix"]
        body = fn["body"]
        lowered = (name + " " + suffix + " " + body[:1600]).lower()
        if visibility not in {"public", "external"}:
            continue
        if any(word in suffix.lower() for word in ("view", "pure")):
            continue
        privileged_name = re.search(
            r"(admin|owner|govern|guardian|config|set|update|upgrade|mint|burn|pause|unpause|"
            r"sweep|rescue|withdraw|drain|initialize|migrate|operator|role)",
            name,
            re.IGNORECASE,
        )
        moves_assets = re.search(r"\b(call|transfer|send|transferfrom|mint|burn)\b", lowered)
        writes_state = re.search(r"(?<![=!<>])=(?!=)|\+\+|--|\bpush\s*\(", body)
        if not (privileged_name or moves_assets or writes_state):
            continue
        if _has_access_control(suffix, body):
            continue
        findings.append(
            _finding(
                title=f"Missing access control on {name}",
                description=(
                    f"`{name}` is externally reachable and appears to change "
                    "privileged protocol state or move assets without a clear "
                    "caller authorization check. An arbitrary account may be able "
                    "to invoke this path to change configuration, mint or withdraw "
                    "funds, or bypass the intended administrator workflow."
                ),
                severity="high",
                kind="access-control",
                file=path,
                function=name,
                line=int(fn["line"]),
                confidence=0.74 if privileged_name else 0.61,
                recommendation=(
                    "Restrict the function with an owner, role, or governance check "
                    "and add tests proving unauthorized callers revert."
                ),
            )
        )
    return findings


def _has_access_control(suffix: str, body: str) -> bool:
    haystack = (suffix + "\n" + body[:2000]).lower()
    controls = (
        "onlyowner",
        "onlyadmin",
        "onlygovern",
        "onlyguardian",
        "requiresauth",
        "auth",
        "hasrole",
        "_checkrole",
        "msg.sender == owner",
        "msg.sender==owner",
        "owner()",
        "isowner",
        "onlyrole",
        "initializer",
        "reinitializer",
    )
    return any(token in haystack for token in controls)


def _reentrancy_and_calls(path: str, text: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for match in re.finditer(r"\.call\s*(?:\{[^}]*value\s*:[^}]*\})?\s*\(", text):
        fn = _enclosing_function(text, match.start())
        after = text[match.end() : match.end() + 900]
        before = text[max(0, match.start() - 350) : match.start()]
        line = _line_of(text, match.start())
        if re.search(r"balances?\s*\[|shares?\s*\[|deposits?\s*\[|total\w*\s*[=+-]", after, re.I):
            findings.append(
                _finding(
                    title="Reentrancy risk from external value call before accounting update",
                    description=(
                        "The function performs a low-level external call and then "
                        "continues updating balances, shares, or aggregate accounting. "
                        "A receiving contract can reenter before the caller's state is "
                        "fully settled and withdraw or claim more assets than intended."
                    ),
                    severity="critical",
                    kind="reentrancy",
                    file=path,
                    function=fn.get("name"),
                    line=line,
                    confidence=0.78,
                    recommendation=(
                        "Update all internal accounting before the external call and "
                        "protect the function with a reentrancy guard."
                    ),
                )
            )
        elif "require" not in before.lower() and "success" not in after[:160].lower():
            findings.append(
                _finding(
                    title="Unchecked low-level external call",
                    description=(
                        "A low-level call is made without an obvious success check near "
                        "the call site. Failed calls can leave protocol accounting or "
                        "control flow in a state that assumes value or data was delivered "
                        "when the callee actually reverted or returned false."
                    ),
                    severity="high",
                    kind="unchecked-call",
                    file=path,
                    function=fn.get("name"),
                    line=line,
                    confidence=0.62,
                    recommendation=(
                        "Capture the boolean result from the call, require success, and "
                        "handle returned data explicitly before continuing."
                    ),
                )
            )
    return findings


def _oracle_findings(path: str, text: str) -> list[dict[str, Any]]:
    if "latestRoundData" not in text:
        return []
    findings: list[dict[str, Any]] = []
    stale_checks = ("updatedAt", "answeredInRound", "block.timestamp", "stale", "heartbeat")
    price_checks = re.search(r"(answer|price)\s*>\s*0|(answer|price)\s*>=\s*0", text)
    if not all(token in text for token in stale_checks[:2]) or not price_checks:
        line = _line_of(text, text.find("latestRoundData"))
        fn = _enclosing_function(text, text.find("latestRoundData"))
        findings.append(
            _finding(
                title="Oracle price used without freshness and sanity checks",
                description=(
                    "The contract reads Chainlink-style round data but does not show "
                    "complete validation that the answer is positive, the round is "
                    "complete, and the timestamp is fresh. A stale or invalid price can "
                    "misprice collateral, swaps, liquidations, or minting paths."
                ),
                severity="high",
                kind="oracle-validation",
                file=path,
                function=fn.get("name"),
                line=line,
                confidence=0.72,
                recommendation=(
                    "Require a positive answer, validate round completion, and reject "
                    "data older than a protocol-defined freshness window."
                ),
            )
        )
    return findings


def _signature_findings(path: str, text: str) -> list[dict[str, Any]]:
    if "ecrecover" not in text:
        return []
    findings: list[dict[str, Any]] = []
    fn = _enclosing_function(text, text.find("ecrecover"))
    body = str(fn.get("body", text))
    lowered = body.lower()
    missing_replay_guard = not any(token in lowered for token in ("nonce", "deadline", "expiry"))
    missing_domain = not any(
        token in lowered for token in ("chainid", "domain_separator", "eip712")
    )
    if missing_replay_guard or missing_domain:
        findings.append(
            _finding(
                title="Signature authorization can be replayed",
                description=(
                    "The signature verification path uses ecrecover without a complete "
                    "replay domain in the visible function body. Missing nonces, expiry, "
                    "or chain-specific domain separation can let an attacker reuse a "
                    "valid signature to repeat privileged actions or replay it elsewhere."
                ),
                severity="high",
                kind="signature-replay",
                file=path,
                function=fn.get("name"),
                line=_line_of(text, text.find("ecrecover")),
                confidence=0.68,
                recommendation=(
                    "Hash signatures with EIP-712 domain separation, include a nonce "
                    "and expiry, and mark each nonce consumed before executing effects."
                ),
            )
        )
    return findings


def _dangerous_opcode_findings(path: str, text: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for token, title, kind in (
        ("delegatecall", "User-controlled delegatecall can execute arbitrary code", "delegatecall"),
        (
            "selfdestruct",
            "Externally reachable selfdestruct can destroy contract funds",
            "selfdestruct",
        ),
        ("tx.origin", "Authorization relies on tx.origin", "tx-origin"),
    ):
        index = text.find(token)
        if index == -1:
            continue
        fn = _enclosing_function(text, index)
        findings.append(
            _finding(
                title=title,
                description=(
                    f"The contract uses `{token}` in an externally reachable code path. "
                    "This pattern can break the intended trust boundary: delegatecall "
                    "can run attacker-controlled code in this contract's storage context, "
                    "selfdestruct can remove code and force-send value, and tx.origin "
                    "authorization can be bypassed through phishing contracts."
                ),
                severity="critical" if token in {"delegatecall", "selfdestruct"} else "high",
                kind=kind,
                file=path,
                function=fn.get("name"),
                line=_line_of(text, index),
                confidence=0.66,
                recommendation=(
                    "Replace this primitive with explicit allowlists, role checks, and "
                    "msg.sender based authorization; avoid delegatecall targets that "
                    "can be influenced by untrusted callers."
                ),
            )
        )
    return findings


def _unchecked_token_findings(path: str, text: str) -> list[dict[str, Any]]:
    if "IERC20" not in text and "ERC20" not in text:
        return []
    findings: list[dict[str, Any]] = []
    for match in re.finditer(r"\.\s*(transfer|transferFrom)\s*\(", text):
        line_text = _line_text(text, match.start())
        prefix = line_text[: max(0, line_text.find("."))]
        lowered = line_text.lower()
        if "safetransfer" in lowered or "require" in lowered or "assert" in lowered:
            continue
        if re.search(r"\bbool\b|\bsuccess\b", prefix, re.I):
            continue
        fn = _enclosing_function(text, match.start())
        findings.append(
            _finding(
                title="Unchecked ERC20 transfer result",
                description=(
                    "The contract calls an ERC20 transfer function without an obvious "
                    "SafeERC20 wrapper or boolean result check. Tokens that return false "
                    "instead of reverting can make accounting advance even though assets "
                    "were not transferred."
                ),
                severity="high",
                kind="unchecked-token-transfer",
                file=path,
                function=fn.get("name"),
                line=_line_of(text, match.start()),
                confidence=0.57,
                recommendation=(
                    "Use SafeERC20 or require the transfer return value before updating "
                    "balances, issuing shares, or finalizing withdrawals."
                ),
            )
        )
    return findings


def _vyper_findings(path: str, text: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for match in re.finditer(r"@external\s*\ndef\s+(\w+)", text):
        name = match.group(1)
        start = match.start()
        body = text[start : start + 1600]
        if re.search(r"(owner|admin|govern|set|update|withdraw|mint|sweep|upgrade)", name, re.I):
            has_auth_check = re.search(
                r"assert\s+msg\.sender\s*==|assert\s+self\.\w*owner|roles?",
                body,
                re.I,
            )
            if not has_auth_check:
                findings.append(
                    _finding(
                        title=f"Missing access control on Vyper function {name}",
                        description=(
                            f"`{name}` is externally callable and appears to perform a "
                            "privileged action without an explicit sender or role check "
                            "in the nearby code. Unauthorized callers may be able to "
                            "change state or move assets."
                        ),
                        severity="high",
                        kind="access-control",
                        file=path,
                        function=name,
                        line=_line_of(text, start),
                        confidence=0.6,
                        recommendation=(
                            "Require the caller to be the owner, admin, or a configured "
                            "role before performing the privileged action."
                        ),
                    )
                )
    return findings


def _non_solidity_findings(path: str, text: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    lowered = text.lower()
    if "invoke_signed" in lowered and "assert" not in lowered and "require" not in lowered:
        findings.append(
            _finding(
                title="Privileged signed invocation lacks visible account validation",
                description=(
                    "The program performs a signed cross-program invocation without "
                    "nearby validation of signer authority or account ownership. A "
                    "malicious caller may be able to route the invocation through "
                    "attacker-controlled accounts and move assets or mutate state."
                ),
                severity="high",
                kind="account-validation",
                file=path,
                line=_line_of(text, lowered.find("invoke_signed")),
                confidence=0.52,
                recommendation=(
                    "Validate signer, owner, seeds, and account relationships before "
                    "executing signed invocations or asset transfers."
                ),
            )
        )
    if "public entry" in lowered and "signer" not in lowered:
        findings.append(
            _finding(
                title="Public entry function lacks signer authority",
                description=(
                    "A public entry function appears to mutate state without requiring "
                    "a signer authority argument. Anyone may be able to call the entry "
                    "point and perform actions intended for a privileged account."
                ),
                severity="high",
                kind="access-control",
                file=path,
                line=_line_of(text, lowered.find("public entry")),
                confidence=0.48,
                recommendation=(
                    "Require signer authorization and verify the signer matches the "
                    "resource owner or configured administrator."
                ),
            )
        )
    return findings


def _solidity_functions(text: str) -> list[dict[str, Any]]:
    pattern = re.compile(
        r"function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]*\)\s*([^{};]*)\{",
        re.MULTILINE,
    )
    functions: list[dict[str, Any]] = []
    for match in pattern.finditer(text):
        body_start = match.end()
        body_end = _matching_brace(text, body_start - 1)
        if body_end <= body_start:
            continue
        suffix = match.group(2) or ""
        visibility_match = re.search(r"\b(public|external|internal|private)\b", suffix)
        functions.append(
            {
                "name": match.group(1),
                "visibility": visibility_match.group(1) if visibility_match else "",
                "suffix": suffix,
                "body": text[body_start:body_end],
                "start": match.start(),
                "end": body_end,
                "line": _line_of(text, match.start()),
            }
        )
    return functions


def _matching_brace(text: str, open_index: int) -> int:
    depth = 0
    for index in range(open_index, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
    return len(text)


def _enclosing_function(text: str, position: int) -> dict[str, Any]:
    best: dict[str, Any] = {}
    for fn in _solidity_functions(text):
        if int(fn["start"]) <= position <= int(fn["end"]):
            best = fn
    return best


def _line_of(text: str, position: int) -> int:
    if position < 0:
        return 1
    return text.count("\n", 0, position) + 1


def _line_text(text: str, position: int) -> str:
    start = text.rfind("\n", 0, position) + 1
    end = text.find("\n", position)
    if end == -1:
        end = len(text)
    return text[start:end]


def _normalize_model_finding(
    item: dict[str, Any],
    *,
    default_file: str | None = None,
) -> dict[str, Any]:
    title = str(item.get("title") or item.get("name") or "").strip()
    description = str(item.get("description") or item.get("impact") or "").strip()
    file = str(item.get("file") or item.get("path") or item.get("location") or "").strip()
    if not file and default_file:
        file = default_file
    contract = str(item.get("contract") or "").strip()
    function = str(item.get("function") or "").strip()
    severity = str(item.get("severity") or "high").strip().lower()
    if severity not in {"high", "critical"}:
        severity = "high"
    line = _safe_int(item.get("line"), 1)
    confidence = _safe_float(item.get("confidence"), 0.72)
    if not title:
        title = "High impact smart-contract vulnerability"
    if function and function.lower() not in title.lower():
        prefix = f"{contract + '.' if contract else ''}{function}"
        title = f"{prefix} - {title}"
    if len(description) < 90:
        description = (
            description.rstrip(".")
            + ". This issue can be exploited in the referenced code path to alter "
            "protocol state, misprice assets, bypass authorization, or move funds "
            "contrary to the intended security boundary."
        ).strip()
    if file and file not in description:
        description = f"In `{file}`, {description[0].lower() + description[1:]}"
    return _finding(
        title=title,
        description=description,
        severity=severity,
        kind=str(item.get("type") or item.get("category") or "model-audit"),
        file=file or "unknown.sol",
        function=function or contract or None,
        line=line,
        confidence=max(0.0, min(confidence, 0.99)),
        recommendation=str(item.get("recommendation") or item.get("fix") or "").strip()
        or "Add explicit validation and regression tests for this exploit path.",
    )


def _finding(
    *,
    title: str,
    description: str,
    severity: str,
    kind: str,
    file: str,
    line: int = 1,
    confidence: float = 0.5,
    recommendation: str = "",
    function: str | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "title": title[:180],
        "description": description[:1400],
        "severity": severity if severity in {"high", "critical"} else "high",
        "type": kind,
        "file": file,
        "line": max(1, int(line or 1)),
        "confidence": round(max(0.0, min(float(confidence), 0.99)), 2),
        "recommendation": recommendation[:700]
        or (
            "Add explicit validation, enforce the intended trust boundary, "
            "and cover the exploit path with tests."
        ),
    }
    if function:
        payload["function"] = function
    return payload


def _dedupe_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, int]] = set()
    result: list[dict[str, Any]] = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        title = str(finding.get("title") or "").strip()
        file = str(finding.get("file") or "").strip()
        description = str(finding.get("description") or "").strip()
        severity = str(finding.get("severity") or "").strip().lower()
        if not title or not file or len(description) < 80 or severity not in {"high", "critical"}:
            continue
        key = (
            file.lower(),
            re.sub(r"[^a-z0-9]+", " ", title.lower()).strip()[:70],
            _safe_int(finding.get("line"), 1),
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(finding)
        if len(result) >= MAX_FINDINGS:
            break
    result.sort(
        key=lambda f: (
            -float(f.get("confidence", 0.0)),
            str(f.get("file", "")),
            int(f.get("line", 1)),
        )
    )
    return result


def _safe_int(value: Any, fallback: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


def _safe_float(value: Any, fallback: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return fallback
