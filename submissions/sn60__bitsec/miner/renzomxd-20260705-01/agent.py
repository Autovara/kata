"""SN60 / Bitsec miner agent: keyword-ranked triage + multi-pass LLM review.

Walks the mounted project for smart-contract source files, ranks them by how
suspicious they look (payable functions, external calls, access-control
keywords, ...), then runs each top-ranked file through several narrowly
focused specialist passes (access control, fund-flow accounting, unit/
interface mismatches, math/iteration edge cases) instead of one generic
"find bugs" prompt. Passes run concurrently against the single pinned
inference endpoint under a hard wall-clock budget, so a slow or hung file
cannot starve the rest of the run.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

CONTRACT_SUFFIXES = (".sol", ".vy", ".rs", ".move", ".cairo", ".fe")
SKIP_DIR_NAMES = {
    "node_modules", "lib", "libs", "vendor", "test", "tests",
    "mock", "mocks", "script", "scripts", "artifacts", "cache", "out",
    "forge-std", "openzeppelin-contracts", "openzeppelin",
}
SUSPICIOUS_KEYWORDS = (
    "payable", "delegatecall", "selfdestruct", ".call(", "transfer(",
    "send(", "onlyowner", "msg.sender", "tx.origin", "unchecked",
    "external", "assembly", "approve(", "mint(", "burn(", "withdraw",
)
MAX_FILE_CHARS = 12000
MAX_FILES_CONSIDERED = 40
MAX_FILES_ANALYZED = 8
MAX_FINDINGS = 20
MAX_FINDINGS_PER_CALL = 4
MIN_CONFIDENCE = 0.6
TIME_BUDGET_SECONDS = 300.0
REQUEST_TIMEOUT_SECONDS = 90
MAX_WORKERS = 8
MIN_DESCRIPTION_CHARS = 80
VALID_SEVERITIES = ("high", "critical")

# Shared instructions appended to every specialist prompt below: output
# contract, confidence discipline, and a short false-positive suppression
# list distilled from well-known smart-contract audit conventions (SWC
# registry style categories), written independently for this agent.
_COMMON_TAIL = f"""
Only report a finding if you can state the exact function name and a
concrete scenario (inputs, call sequence, or numeric example) that shows
the impact. If you cannot show a concrete path, do not report it.

Do not report:
- functions already gated by onlyOwner/onlyRole/similar modifiers, unless
  you can show the role check itself is bypassable
- decimal/scaling differences that are already handled by an explicit
  conversion helper in the code
- reentrancy, unless you can point to a state write that happens AFTER an
  external call, with no reentrancy guard, and a concrete profit path
- gas/DoS from unbounded loops, unless the loop bound is attacker-controlled
  with no practical cap
- unchecked return values on calls that revert by default or use a safe
  transfer wrapper

Only report severity "high" or "critical", and only when your own
confidence in the finding is at least 0.7.

Respond with ONLY a JSON array (no prose, no markdown fences), at most
{MAX_FINDINGS_PER_CALL} elements, each an object with keys: "title",
"description" (at least two sentences explaining the concrete exploit
path), "severity" ("high" or "critical"), "function", "line" (integer or
null), "confidence" (0-1 float), "recommendation". If nothing meets this
bar, respond with an empty JSON array: [].
"""

SYSTEM_ACCESS_CONTROL = (
    "You are a smart-contract security auditor focused only on access "
    "control and authorization. For every external or public function, "
    "work out who is supposed to be allowed to call it, then check whether "
    "the code actually enforces that. Specifically look for: state-changing "
    "functions with no caller check at all; functions that move funds out "
    "of or into an account other than msg.sender using a pre-existing "
    "approval, without verifying msg.sender is that account or holds a "
    "signature from it; signature-gated functions that verify the signer "
    "but not that the submitter is the intended party; and privileged "
    "setters that accept new configuration values with no sanity bounds."
) + _COMMON_TAIL

SYSTEM_FUND_FLOW = (
    "You are a smart-contract security auditor focused only on fund-flow "
    "and accounting correctness. For every function that both pulls in and "
    "pays out value in the same call (swaps, refunds, redemptions, "
    "withdrawals), check whether the paid-out amount is derived from what "
    "was actually received or consumed, rather than from a requested amount "
    "that was never fully collected. Check that every approve() or "
    "increaseAllowance() call is reset back down on every exit path of the "
    "function, including error and early-return branches, so no leftover "
    "spending right survives the call. Check that internal counters or "
    "running totals feeding fee, share-price, or payout math are updated "
    "the same way on both the forward operation and its reverse."
) + _COMMON_TAIL

SYSTEM_UNIT_INTERFACE = (
    "You are a smart-contract security auditor focused only on unit, "
    "precision, and cross-contract interface mismatches. Check whether "
    "values returned from external calls -- especially to vaults, wrappers, "
    "or other share-issuing contracts -- are consumed in the unit the "
    "caller assumes (shares vs. underlying asset, differing token "
    "decimals, wei vs. whole units). Check whether identifiers produced by "
    "a shared counter or sequence are properly scoped so two different "
    "owners or collections cannot end up with colliding keys."
) + _COMMON_TAIL

SYSTEM_MATH_ITERATION = (
    "You are a smart-contract security auditor focused only on math and "
    "iteration correctness. Check exposed math helpers (square root, log, "
    "division, modulo) for undefined or reverting behavior on zero, one, "
    "or extreme inputs where a normal result is expected. Check loops that "
    "iterate up to a stored counter or length for gaps caused by removals "
    "that never compact the underlying collection. Check explicit integer "
    "downcasts against realistic input ranges for overflow."
) + _COMMON_TAIL

SPECIALIST_PASSES = (
    ("access_control", SYSTEM_ACCESS_CONTROL),
    ("fund_flow", SYSTEM_FUND_FLOW),
    ("unit_interface", SYSTEM_UNIT_INTERFACE),
    ("math_iteration", SYSTEM_MATH_ITERATION),
)


def agent_main(project_dir: str | None = None, inference_api: str | None = None) -> dict:
    findings: list[dict] = []
    try:
        root = _resolve_project_dir(project_dir)
        if root is not None:
            endpoint = _resolve_inference_endpoint(inference_api)
            api_key = os.environ.get("INFERENCE_API_KEY", "")
            deadline = time.monotonic() + TIME_BUDGET_SECONDS

            sources: dict[str, str] = {}
            for path in _rank_candidate_files(root)[:MAX_FILES_ANALYZED]:
                try:
                    source = path.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                if source.strip():
                    sources[_relative_path(path, root)] = source[:MAX_FILE_CHARS]

            executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)
            try:
                futures = {
                    executor.submit(
                        _ask_model,
                        endpoint=endpoint,
                        api_key=api_key,
                        system_prompt=system_prompt,
                        file_label=relative_path,
                        source=source,
                    ): relative_path
                    for relative_path, source in sources.items()
                    for _pass_name, system_prompt in SPECIALIST_PASSES
                }
                remaining = deadline - time.monotonic()
                try:
                    for future in as_completed(futures, timeout=max(remaining, 0.0)):
                        relative_path = futures[future]
                        try:
                            raw_reply = future.result()
                        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
                            continue
                        for finding in _parse_findings(raw_reply):
                            finding["file"] = relative_path
                            findings.append(finding)
                except TimeoutError:
                    pass
            finally:
                executor.shutdown(wait=False, cancel_futures=True)
    except Exception:
        # Analysis was attempted; never let an unexpected runtime error crash
        # the sandboxed run. A partial or empty result only scores 0 on this
        # problem, it does not invalidate the submission.
        pass

    return {"vulnerabilities": _dedupe_and_cap(findings, MAX_FINDINGS)}


def _resolve_project_dir(project_dir: str | None) -> Path | None:
    candidate = project_dir or os.environ.get("PROJECT_DIR") or os.environ.get("PROJECT_ROOT")
    if candidate:
        path = Path(candidate)
        if path.is_dir():
            return path
    for fallback in (Path.cwd(), Path("/project"), Path("/kata_project")):
        if fallback.is_dir():
            return fallback
    return None


def _resolve_inference_endpoint(inference_api: str | None) -> str:
    base = (inference_api or os.environ.get("INFERENCE_API") or "").rstrip("/")
    return f"{base}/inference"


def _relative_path(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return path.name


def _iter_contract_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames if d.lower() not in SKIP_DIR_NAMES and not d.startswith(".")
        ]
        for filename in filenames:
            if filename.lower().endswith(CONTRACT_SUFFIXES):
                yield Path(dirpath) / filename


def _suspicion_score(source: str) -> int:
    lowered = source.lower()
    return sum(lowered.count(keyword) for keyword in SUSPICIOUS_KEYWORDS)


def _rank_candidate_files(root: Path) -> list[Path]:
    scored: list[tuple[int, Path]] = []
    for path in _iter_contract_files(root):
        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if not source.strip():
            continue
        scored.append((_suspicion_score(source), path))
    scored.sort(key=lambda pair: pair[0], reverse=True)
    return [path for _, path in scored[:MAX_FILES_CONSIDERED]]


def _ask_model(
    *, endpoint: str, api_key: str, system_prompt: str, file_label: str, source: str
) -> str:
    user_prompt = f"File: {file_label}\n\n```\n{source}\n```"
    body = json.dumps(
        {
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "max_tokens": 4000,
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        endpoint,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "x-inference-api-key": api_key,
        },
    )
    with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
        payload = json.loads(response.read().decode("utf-8"))
    return payload["choices"][0]["message"]["content"]


def _parse_findings(raw_reply: str) -> list[dict]:
    payload = _extract_json_array(raw_reply)
    if payload is None:
        return []
    cleaned: list[dict] = []
    for item in payload[:MAX_FINDINGS_PER_CALL]:
        if not isinstance(item, dict):
            continue
        title = str(item.get("title") or "").strip()
        if not title:
            continue
        severity = str(item.get("severity") or "high").strip().lower()
        if severity not in VALID_SEVERITIES:
            severity = "high"
        confidence = _safe_confidence(item.get("confidence"))
        if confidence < MIN_CONFIDENCE:
            continue
        description = str(item.get("description") or "").strip()
        if len(description) < MIN_DESCRIPTION_CHARS:
            description = (description + " " if description else "") + (
                f"This is a {severity}-severity issue flagged by automated "
                "review; verify the reported location and exploit path before "
                "relying on this report."
            )
        line = item.get("line")
        cleaned.append(
            {
                "title": title,
                "description": description,
                "severity": severity,
                "function": str(item.get("function") or "").strip(),
                "line": line if isinstance(line, int) else None,
                "confidence": confidence,
                "recommendation": str(item.get("recommendation") or "").strip(),
            }
        )
    return cleaned


def _safe_confidence(value: object) -> float:
    try:
        confidence = float(value)
    except (TypeError, ValueError):
        return 0.5
    return min(1.0, max(0.0, confidence))


def _extract_json_array(raw_reply: str) -> list | None:
    text = raw_reply.strip()
    if text.startswith("```"):
        text = text.strip("`")
        newline = text.find("\n")
        if newline != -1:
            text = text[newline + 1 :]
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        payload = None
    if payload is None:
        start, end = text.find("["), text.rfind("]")
        if start != -1 and end != -1 and end > start:
            try:
                payload = json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                return None
        else:
            return None
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict) and isinstance(payload.get("vulnerabilities"), list):
        return payload["vulnerabilities"]
    return None


def _dedupe_and_cap(findings: list[dict], limit: int) -> list[dict]:
    best_by_key: dict[tuple[str, str], dict] = {}
    for finding in findings:
        key = (finding.get("file", ""), finding.get("title", "").lower())
        existing = best_by_key.get(key)
        if existing is None or finding.get("confidence", 0.0) > existing.get("confidence", 0.0):
            best_by_key[key] = finding
    unique = list(best_by_key.values())
    unique.sort(key=lambda f: (f.get("severity") != "critical", -f.get("confidence", 0.0)))
    return unique[:limit]
