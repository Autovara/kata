from __future__ import annotations

"""SN60 / Bitsec miner agent — depth-first, matcher-tuned, round-budget capped.

v2 of the king agent. Same winning idea as v1 (it scored this lane's first-ever
matched true-positive): the pinned semantic scorer only counts a match when a
finding correctly identifies the *contract/file*, the *function*, the *core
mechanism*, and the *impact* of a real high/critical issue — and it extracts
`.sol` filenames + function names out of the title/description as hints. So the
agent emits findings shaped exactly like that.

What's new in v2 — it respects the competition-round budget of **at most 3 model
calls and ~24,000 tokens per problem**:

  * hard cap of 3 model calls (``MAX_MODEL_CALLS``), one per contract;
  * the 3 calls go to the highest-suspicion contracts first, so the budget is
    spent where a real high is most likely;
  * lean prompts — a trimmed single-contract context, no extra related file — so
    input stays small and leaves token headroom for the reasoning model.

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
SOL_SUFFIXES = (".sol", ".vy")
EXCLUDED_DIR_NAMES = {
    "test", "tests", "mock", "mocks", "example", "examples", "script",
    "scripts", "broadcast", "node_modules", "vendor", "vendors", "lib",
    "out", "artifacts", "cache", "interfaces", "interface",
}
SUSPICIOUS_NAME_TERMS = (
    "vault", "router", "bridge", "proxy", "upgrade", "oracle", "govern",
    "treasury", "manager", "pool", "reward", "staking", "market", "reserve",
    "lend", "borrow", "collateral", "controller", "strategy", "auction",
    "token", "admin", "owner",
)
SUSPICIOUS_CONTENT_PATTERNS = (
    r"\bdelegatecall\b", r"\.call\s*\{", r"\bcall\.value\b", r"\bselfdestruct\b",
    r"\btx\.origin\b", r"\bassembly\b", r"\becrecover\b", r"\bpermit\b",
    r"\bonlyOwner\b", r"\bonlyRole\b", r"\bupgradeTo\b", r"\b_mint\b", r"\b_burn\b",
    r"\bwithdraw\b", r"\bredeem\b", r"\bliquidat", r"\bborrow\b", r"\brepay\b",
    r"\btransferFrom\b", r"\bsafeTransfer", r"\bunchecked\b", r"\breentran",
    r"\bflash", r"\bgetPrice\b", r"\blatestAnswer\b", r"\bslot0\b", r"\bnonce\b",
    r"\bsignature\b", r"\btotalSupply\b", r"\bbalanceOf\b",
)
CONTRACT_NAME_PATTERN = re.compile(
    r"\b(?:contract|library|abstract\s+contract)\s+([A-Za-z_][A-Za-z0-9_]*)"
)
FUNCTION_DEF_PATTERN = re.compile(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")

# --- budgets (round: <=3 model calls / ~24k tokens per problem; container is
# 512MB / 0.25 CPU, agent self-limited) -------------------------------------
MAX_MODEL_CALLS = 3          # hard cap — never exceed the per-problem call budget
MAX_FILE_BYTES = 200_000
MAX_CONTRACT_CHARS = 10_000  # lean single-contract context (leaves token headroom)
MAX_FINDINGS = 6
MAX_RUNTIME_SECONDS = 200.0
REQUEST_TIMEOUT_SECONDS = 150
MAX_RETRIES = 1              # one retry keeps us inside the call budget on a flake

SYSTEM_PROMPT = (
    "You are a senior smart-contract security auditor. You find only REAL, "
    "exploitable HIGH or CRITICAL vulnerabilities — logic flaws that let an "
    "attacker steal funds, escalate privilege, brick the protocol, or corrupt "
    "accounting. You ignore gas, style, missing events, and speculative issues "
    "with no concrete exploit path. You are precise about WHERE the bug is."
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
    score += min(content.count("function "), 20)
    if "constructor" in content:
        score += 2
    return score


def _discover(project_root: Path) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for path in sorted(project_root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in SOL_SUFFIXES:
            continue
        if any(part.lower() in EXCLUDED_DIR_NAMES for part in path.relative_to(project_root).parts[:-1]):
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


# ---------------------------------------------------------------------------
# inference
# ---------------------------------------------------------------------------
def _post_inference(inference_api: str | None, messages: list[dict[str, str]]) -> str:
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
            with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as resp:
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
def _build_prompt(target: dict[str, object]) -> str:
    rel = target["rel"]
    contracts = ", ".join(target["contracts"][:6]) or "(unnamed)"
    full = str(target["content"])
    content = full[:MAX_CONTRACT_CHARS]
    truncated = " (truncated)" if len(full) > MAX_CONTRACT_CHARS else ""
    return "\n".join(
        [
            "Audit this Solidity file for real HIGH/CRITICAL vulnerabilities.\n",
            f"File path (use EXACTLY this as `file`): {rel}",
            f"Contracts defined here: {contracts}\n",
            "Think through the protocol logic, access control, external calls, "
            "accounting/oracle math, and upgrade/init paths. Report ONLY issues "
            "with a concrete exploit path and material impact.\n",
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
            "Rules: at most 2 findings; each MUST name the real function it lives "
            'in; if nothing is genuinely exploitable, return {"findings": []}. Do '
            "not invent functions or files not present in the source below.\n",
            f"----- SOURCE{truncated} -----",
            content,
        ]
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

    collected: list[dict[str, object]] = []
    calls = 0
    # Spend the <=3-call budget on the highest-suspicion contracts first.
    for target in records:
        if calls >= MAX_MODEL_CALLS or time.monotonic() > deadline:
            break
        calls += 1
        prompt = _build_prompt(target)
        try:
            content = _post_inference(
                inference_api,
                [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
            )
        except (RuntimeError, ValueError):
            continue
        valid_fns = _valid_functions(str(target["content"]))
        for raw in _parse_findings(content):
            norm = _normalize(raw, target, valid_fns)
            if norm is not None:
                collected.append(norm)

    findings = _dedupe(collected)[:MAX_FINDINGS]
    return {"vulnerabilities": findings}


if __name__ == "__main__":  # local smoke check only (no network)
    import sys

    print(json.dumps(agent_main(sys.argv[1] if len(sys.argv) > 1 else None), indent=2))
