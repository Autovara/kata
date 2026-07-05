"""SN60 / Bitsec miner agent.

A self-contained smart-contract security auditor. It runs several complementary
passes and merges their findings:

  1. Broad pass       — every security-relevant file audited individually (recall).
  2. Deep pass        — core entry-point contract(s) audited together with the
                        real source of the files they call, so the model can
                        trace a full call chain (execute -> _dispatch -> _execute).
  3. Gas specialist   — a focused pass on the entry contracts for gas-griefing /
                        out-of-gas denial of service (the 63/64 rule, starved
                        inner calls, unbounded loops).
  4. Signature spec.  — a focused pass on the entry contracts for signature and
                        replay flaws (cross-chain replay, user-supplied domain
                        separator, missing deadline, nonce/executor binding).

Findings are merged and returned in the SN60 report shape:

    {"vulnerabilities": [ {title, description, severity, file, ...}, ... ]}
"""

import concurrent.futures
import json
import os
import re
import time
import urllib.request
from pathlib import Path

# --- runtime contract -------------------------------------------------------

DEFAULT_PROJECT_DIR = "/app/project_code"
DEFAULT_INFERENCE_API = "http://bitsec_proxy:8000"

# --- tuning (kept modest for the 512MB / 0.25 CPU / ~5min sandbox) ---

SOURCE_SUFFIXES = (".sol", ".vy", ".rs", ".move", ".cairo", ".fe")
EXCLUDE_DIR_PARTS = {
    "test", "tests", "mock", "mocks", "interface", "interfaces",
    "script", "scripts", "lib", "libs", "node_modules", "example",
    "examples", "broadcast", "out", "cache", ".git",
}
# A library/support dir is not a user-facing entry point.
SUPPORT_DIR_PARTS = {"libraries", "lib", "utils", "base", "mixins", "abstract", "common"}
# Filenames/paths that usually hold the money logic get analyzed first.
PRIORITY_HINTS = (
    "vault", "pool", "staking", "stake", "router", "oracle", "auth", "admin",
    "owner", "governance", "gov", "bridge", "lend", "borrow", "collateral",
    "reward", "vesting", "manager", "controller", "treasury", "swap",
    "liquidat", "token", "market", "escrow", "farm", "strategy", "distributor",
    "minter", "bank", "loan", "debt", "flash", "auction", "position",
    "account", "delegation", "execute", "settlement", "entry", "core", "main",
)

MAX_FILES = 16             # broad-pass file cap to leave budget for specialists
ENTRY_FILES = 4            # core contracts that get the deep call-chain pass
SPECIALIST_ENTRIES = 4     # entry contracts that also get gas + signature passes
MAX_FILE_BYTES = 40_000    # truncate very large files to protect memory/time
NEIGHBOR_BYTES = 12_000    # per related file included in an entry pass
NEIGHBOR_BUDGET = 34_000   # total related-file bytes per entry pass
MAX_NEIGHBORS = 5
MAX_WORKERS = 6            # inference is IO-bound; keep CPU/memory pressure low
MAX_RUNTIME_SECONDS = 250  # soft deadline; leaves margin to write the report
PER_FILE_FINDINGS = 6
DEEP_FINDINGS = 8
MAX_TOTAL_FINDINGS = 60
REQUEST_TIMEOUT = 90
KEEP_SEVERITIES = {"high", "critical"}

IMPORT_RE = re.compile(r"""import\s+(?:[^;"']*\bfrom\s+)?["']([^"']+)["']""")

CLASS_GUIDANCE = (
    "Pay special attention to classes that are easy to miss: front-running, "
    "transaction-ordering and MEV (a signed or authorized call that does not "
    "bind the caller/executor and can be submitted or replayed by anyone); "
    "griefing and gas-based denial of service (the 63/64 gas rule, insufficient "
    "gas forwarded to an inner call so a subcall fails while the outer call "
    "succeeds, forced reverts, unbounded loops); signature replay, malleability, "
    "missing domain separation, and nonce misuse (a nonce consumed before the "
    "signature is verified); reentrancy and unsafe external calls or callbacks; "
    "broken or missing access control and privilege escalation; accounting, "
    "rounding, and share-price manipulation; oracle and price manipulation; and "
    "initialization or upgrade flaws."
)

JSON_SHAPE = (
    "Respond with ONLY a JSON object: "
    '{"vulnerabilities": [{"title": "...", "description": "...", '
    '"vulnerability_type": "...", "severity": "high|critical", '
    '"confidence": 0.0, "location": "function or line range", "file": "..."}]}. '
    "Report an empty list only if there is truly no high/critical issue."
)

SYSTEM_BROAD = (
    "You are a world-class smart-contract security auditor competing to find the "
    "exact high- and critical-severity vulnerabilities a professional audit of "
    "this codebase reported. Be exhaustive: enumerate EVERY distinct, "
    "exploitable high/critical issue in the target file. For each external or "
    "public function, reason about who can call it, in what order, and how a "
    "malicious actor can abuse it. " + CLASS_GUIDANCE + " Ignore gas "
    "optimizations, style, and purely theoretical issues without a concrete "
    "exploit path. Give each finding a precise title that names the affected "
    "function and mechanism, and a description covering the root cause, a "
    "concrete exploit path, and the impact. " + JSON_SHAPE
)

SYSTEM_DEEP = (
    "You are a world-class smart-contract security auditor. You are given a MAIN "
    "entry-point contract plus the real source of the contracts and libraries it "
    "calls. Trace EVERY externally callable (public/external) function of the "
    "entry contract through its FULL call chain into the related files. For each "
    "entry function, determine precisely who can call it, in what order it can "
    "be called, and how a malicious actor (including a front-runner, or a caller "
    "who crafts msg.value or the gas limit) can abuse it. " + CLASS_GUIDANCE
    + " Name the exact entry function and the mechanism in every finding. Ignore "
    "gas optimizations and style. " + JSON_SHAPE
)

SYSTEM_GAS = (
    "You are a smart-contract security auditor specializing in GAS-BASED DENIAL "
    "OF SERVICE and GRIEFING. You are given a MAIN entry contract plus the real "
    "source of the contracts and libraries it calls. For every externally "
    "callable function, determine whether a malicious caller can make the call "
    "fail or misbehave by controlling the GAS or msg.value. Look specifically "
    "for: the EIP-150 63/64 rule — only 63/64 of the remaining gas is forwarded "
    "to a subcall, so a caller can pick an overall gas limit that lets the outer "
    "call succeed but starves an inner low-level call and forces it to fail; a "
    "swallowed subcall failure (e.g. a batched call with shouldRevert=false) so "
    "the batch partially completes while still consuming the nonce; unbounded "
    "loops or external calls inside loops; return-data bombs; and forced reverts "
    "that grief other users. Report only high/critical gas-griefing, "
    "out-of-gas, or denial-of-service findings, naming the exact entry function "
    "and the inner call that can be starved or forced to fail. " + JSON_SHAPE
)

SYSTEM_SIG = (
    "You are a smart-contract security auditor specializing in SIGNATURE and "
    "REPLAY vulnerabilities. You are given a MAIN entry contract plus the real "
    "source of the contracts and libraries it calls. For every function that "
    "verifies a signature or consumes a nonce, check for: replay across chains "
    "(the signed digest or EIP-712 domain separator omits block.chainid, or the "
    "domainSeparator is user-supplied instead of bound to this contract and "
    "chain); a MISSING DEADLINE or expiry so a signature is valid forever; "
    "signature malleability; missing binding of the intended executor or caller "
    "so anyone can submit the signed call (front-running); a nonce consumed "
    "before the signature is verified, or nonces that fail to prevent replay; "
    "and missing domain separation between different operations. Report only "
    "high/critical signature or replay findings, naming the exact function and "
    "the missing check. " + JSON_SHAPE
)

INSTRUCT_DEEP = (
    "Trace every externally callable function of this contract through its full "
    "call chain into the related files, and report all high/critical bugs."
)
INSTRUCT_GAS = (
    "Find every way a malicious caller can grief or force an out-of-gas failure "
    "via the 63/64 gas rule, a starved inner/low-level call, msg.value, an "
    "unbounded loop, or a swallowed subcall failure."
)
INSTRUCT_SIG = (
    "Find every signature-replay, cross-chain replay, user-supplied or unbound "
    "domain-separator, missing-deadline, malleability, nonce-binding, and "
    "executor-binding flaw."
)


# --- inference --------------------------------------------------------------

def _endpoint(inference_api):
    base = (
        inference_api
        or os.environ.get("INFERENCE_API")
        or DEFAULT_INFERENCE_API
    ).rstrip("/")
    return base + "/inference"


def _headers():
    return {
        "Content-Type": "application/json",
        "x-inference-api-key": os.environ.get("INFERENCE_API_KEY", ""),
        "x-agent-id": os.environ.get("AGENT_ID", "unknown"),
        "x-job-run-id": os.environ.get("JOB_RUN_ID", "unknown"),
        "x-request-phase": "execution",
    }


def _call_model(endpoint, headers, system, user, attempts=3):
    body = json.dumps({
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "response_format": {"type": "json_object"},
        "max_tokens": 8000,
    }).encode("utf-8")
    for attempt in range(attempts):
        try:
            request = urllib.request.Request(
                endpoint, data=body, method="POST", headers=headers
            )
            with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            return data["choices"][0]["message"].get("content") or ""
        except Exception:  # noqa: BLE001 - resilience: skip on any failure
            if attempt < attempts - 1:
                time.sleep(2 * (attempt + 1))
    return ""


# --- parsing ----------------------------------------------------------------

def _parse_findings(content):
    if not content:
        return []
    text = content.strip()
    if text.startswith("```"):
        text = text.strip("`").strip()
        newline = text.find("\n")
        if newline != -1 and " " not in text[:newline]:
            text = text[newline + 1:]
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return []
    try:
        payload = json.loads(text[start:end + 1])
    except ValueError:
        return []
    items = payload.get("vulnerabilities")
    return items if isinstance(items, list) else []


def _normalize(item, fallback_file):
    if not isinstance(item, dict):
        return None
    title = str(item.get("title") or "").strip()
    description = str(item.get("description") or "").strip()
    severity = str(item.get("severity") or "").strip().lower()
    if not title or len(description) < 20:
        return None
    if severity not in KEEP_SEVERITIES:
        return None
    try:
        confidence = float(item.get("confidence", 0.6))
    except (TypeError, ValueError):
        confidence = 0.6
    return {
        "title": title,
        "description": description,
        "vulnerability_type": str(
            item.get("vulnerability_type") or item.get("type") or "security"
        ).strip(),
        "severity": severity,
        "confidence": max(0.0, min(1.0, confidence)),
        "location": str(item.get("location") or item.get("function") or "").strip(),
        "file": str(item.get("file") or "").strip() or fallback_file,
    }


# --- project walk -----------------------------------------------------------

def _discover(root):
    found = []
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        lowered_parts = {part.lower() for part in path.parts}
        if lowered_parts & EXCLUDE_DIR_PARTS:
            continue
        name = path.name.lower()
        if "test" in name or "mock" in name:
            continue
        found.append(path)

    def rank(path):
        low = str(path).lower()
        hits = sum(1 for hint in PRIORITY_HINTS if hint in low)
        return (-hits, len(low))

    found.sort(key=rank)
    return found


def _entry_files(files, root, limit=ENTRY_FILES):
    def is_support(path):
        parts = [p.lower() for p in path.relative_to(root).parts[:-1]]
        return any(p in SUPPORT_DIR_PARTS for p in parts)

    candidates = [p for p in files if not is_support(p)] or list(files)

    def rank(path):
        low = str(path).lower()
        hits = sum(1 for hint in PRIORITY_HINTS if hint in low)
        depth = len(path.relative_to(root).parts)
        return (-hits, depth)

    candidates.sort(key=rank)
    return candidates[:limit]


def _neighbors(entry_path, root, files):
    try:
        text = entry_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    by_name = {p.name: p for p in files}
    root_resolved = root.resolve()
    picked, used, seen = [], 0, set()
    for imported in IMPORT_RE.findall(text):
        target = (entry_path.parent / imported).resolve()
        if not target.exists():
            target = by_name.get(Path(imported).name)
        if not target or not target.exists() or target == entry_path:
            continue
        try:
            rel = target.resolve().relative_to(root_resolved)
        except ValueError:
            continue
        if str(rel) in seen:
            continue
        try:
            content = target.read_text(encoding="utf-8", errors="ignore")[:NEIGHBOR_BYTES]
        except OSError:
            continue
        if used + len(content) > NEIGHBOR_BUDGET:
            break
        seen.add(str(rel))
        picked.append((str(rel), content))
        used += len(content)
        if len(picked) >= MAX_NEIGHBORS:
            break
    return picked


# --- analysis passes --------------------------------------------------------

def _analyze_file(endpoint, headers, root, path, index):
    try:
        raw = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    if not raw.strip():
        return []
    relative = str(path.relative_to(root))
    user = (
        "Project contract files (for cross-contract context):\n" + index
        + "\n\nAudit the TARGET file below and report ALL high/critical "
        "vulnerabilities you can justify with a concrete exploit path.\n\n"
        "TARGET FILE: " + relative + "\n\n```\n" + raw[:MAX_FILE_BYTES] + "\n```"
    )
    content = _call_model(endpoint, headers, SYSTEM_BROAD, user)
    findings = []
    for item in _parse_findings(content)[:PER_FILE_FINDINGS]:
        normalized = _normalize(item, relative)
        if normalized:
            findings.append(normalized)
    return findings


def _entry_pass(endpoint, headers, root, path, files, system, instruction):
    """A focused pass over one entry contract plus its call-chain neighbours."""
    try:
        entry_src = path.read_text(encoding="utf-8", errors="ignore")[:MAX_FILE_BYTES]
    except OSError:
        return []
    if not entry_src.strip():
        return []
    relative = str(path.relative_to(root))
    related = _neighbors(path, root, files)
    context = "".join(
        f"\n\n--- RELATED FILE: {name}\n```\n{code}\n```" for name, code in related
    )
    user = (
        f"MAIN ENTRY CONTRACT: {relative}\n\n" + instruction
        + "\n\n```\n" + entry_src + "\n```" + context
    )
    content = _call_model(endpoint, headers, system, user)
    findings = []
    for item in _parse_findings(content)[:DEEP_FINDINGS]:
        normalized = _normalize(item, relative)
        if normalized:
            findings.append(normalized)
    return findings


def _dedupe(findings):
    seen = set()
    unique = []
    for finding in findings:
        key = (finding["file"].lower(), finding["title"].lower())
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    unique.sort(key=lambda f: (f["severity"] != "critical", -f["confidence"]))
    return unique[:MAX_TOTAL_FINDINGS]


# --- entrypoint -------------------------------------------------------------

def agent_main(project_dir=None, inference_api=None):
    root = Path(
        project_dir or os.environ.get("PROJECT_DIR") or DEFAULT_PROJECT_DIR
    )
    collected = []
    if root.exists() and root.is_dir():
        endpoint = _endpoint(inference_api)
        headers = _headers()
        all_files = _discover(root)
        entries = _entry_files(all_files, root)
        specialists = entries[:SPECIALIST_ENTRIES]
        entry_set = set(entries)
        broad = [f for f in all_files if f not in entry_set][:MAX_FILES]
        index = "\n".join(str(p.relative_to(root)) for p in all_files[:60])

        pool = concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS)
        futures = []
        # High-value entry passes first so they start before the broad sweep.
        for path in entries:
            futures.append(pool.submit(
                _entry_pass, endpoint, headers, root, path, all_files,
                SYSTEM_DEEP, INSTRUCT_DEEP))
        for path in specialists:
            futures.append(pool.submit(
                _entry_pass, endpoint, headers, root, path, all_files,
                SYSTEM_GAS, INSTRUCT_GAS))
        for path in specialists:
            futures.append(pool.submit(
                _entry_pass, endpoint, headers, root, path, all_files,
                SYSTEM_SIG, INSTRUCT_SIG))
        # Broad coverage of the rest.
        for path in broad:
            futures.append(pool.submit(
                _analyze_file, endpoint, headers, root, path, index))

        try:
            for future in concurrent.futures.as_completed(
                futures, timeout=MAX_RUNTIME_SECONDS
            ):
                try:
                    collected.extend(future.result())
                except Exception:  # noqa: BLE001 - one bad task never aborts
                    continue
        except concurrent.futures.TimeoutError:
            pass
        finally:
            pool.shutdown(wait=False, cancel_futures=True)

    results = _dedupe(collected)
    return {"vulnerabilities": results}


if __name__ == "__main__":
    print(json.dumps(agent_main(), indent=2))
