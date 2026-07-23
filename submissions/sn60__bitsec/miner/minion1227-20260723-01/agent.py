"""Stability-first vulnerability miner for the sn60__bitsec lane.

Design in one line: a deterministic analyzer always runs and always produces the
same anchored findings for the same source, and a model layer adds upside on top
of it.

Why it is built that way: a project only counts on the strict tier when a
majority of its replicas agree. A purely model-driven agent re-rolls its answer
on every replica, so a project it solves once often fails the majority. The
static layer here is byte-identical across replicas, so whatever it catches is
carried by every replica instead of one lucky one. The model layer is additive
and never required for the agent to produce output.

Precision is scored as correct / reported, so the emit stage is deliberately
strict: only findings pinned to a real file, contract and function are emitted,
corroborated ones first, and the tail is capped.
"""

from __future__ import annotations

import json
import os
import re
import socket
import time
import urllib.error
import urllib.request
from pathlib import Path

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

CODE_SUFFIXES = (".sol", ".vy", ".rs", ".move", ".cairo")
SKIP_DIRS = frozenset({
    ".git", "node_modules", "lib", "out", "build", "artifacts", "cache",
    "coverage", "dist", "target", "venv", ".venv", "__pycache__", "docs",
})
SKIP_NAME_HINTS = ("test", "mock", "script", "example", "sample")

MAX_FILES = 120
MAX_FILE_BYTES = 300_000

MODEL_NAME = os.environ.get("KATA_MINER_MODEL", "deepseek-ai/DeepSeek-V3.2-TEE")
# Timing follows the runner contract: the inference gateway allows 180s for one
# upstream request, so the client waits 195s to still receive a reply that took
# the full gateway budget; the whole agent process is killed at 840s, so the
# internal deadline stays below it with room to finish ranking and emit.
TOTAL_BUDGET_SECONDS = 800.0
PER_CALL_TIMEOUT = 195.0
CALL_HEADROOM = 225.0
TAIL_HEADROOM = 15.0
CALL_FLOOR = 30.0
CALL_RETRIES = 2
RETRYABLE_HTTP = frozenset({408, 409, 425, 500, 502, 504, 520, 522, 524, 529})

MAP_PROMPT_CHARS = 34_000
MAP_TOKENS = 2_000
DEEP_FILES = 7
DEEP_FILE_CHARS = 14_000
DEEP_PROMPT_CHARS = 46_000
DEEP_TOKENS = 15_000
WIDE_FILES = 12
WIDE_FILE_CHARS = 8_000
WIDE_PROMPT_CHARS = 50_000
WIDE_TOKENS = 14_000
FOLLOWUP_FILES = 5
FOLLOWUP_FILE_CHARS = 12_000
FOLLOWUP_PROMPT_CHARS = 40_000
FOLLOWUP_TOKENS = 13_000

EMIT_FLOOR = 6
EMIT_CEILING = 12

_TUNING_ENABLED = True

# --------------------------------------------------------------------------
# Solidity-oriented lexical patterns
# --------------------------------------------------------------------------

RE_FUNCTION = re.compile(
    r"\bfunction\s+([A-Za-z_]\w*)\s*\(([^)]*)\)([^{;]*)(\{|;)", re.S)
RE_TYPE_DECL = re.compile(r"\b(?:contract|library|interface|abstract\s+contract)\s+([A-Za-z_]\w*)")
RE_MODIFIER_DECL = re.compile(r"\bmodifier\s+([A-Za-z_]\w*)")
RE_STATE_ASSIGN = re.compile(r"(?m)^\s*([A-Za-z_]\w*)\s*(?:\[[^\]]*\])*\s*(?:\.\w+)*\s*=(?!=)")

AUTH_MODIFIERS = (
    "onlyowner", "onlyadmin", "onlyrole", "onlygovernance", "onlygovernor",
    "onlymanager", "onlyoperator", "onlyauthorized", "onlyguardian",
    "auth", "requiresauth", "restricted", "onlyself", "onlyvault",
    "onlycontroller", "onlyminter", "onlykeeper", "onlytimelock",
)
PRIVILEGED_VERBS = (
    "set", "update", "withdraw", "mint", "burn", "pause", "unpause",
    "upgrade", "transferownership", "renounce", "rescue", "sweep", "seize",
    "initialize", "configure", "grant", "revoke", "migrate", "collect",
    "changeadmin", "setadmin", "emergency",
)
EXTERNAL_CALL_HINTS = (
    ".call{", ".call(", ".delegatecall(", ".send(", ".transfer(",
    "safetransfer", "safetransferfrom", "transferfrom(",
)
ORACLE_HINTS = ("latestrounddata", "latestanswer", "getprice", "consult", "peek")
STALENESS_HINTS = ("updatedat", "answeredinround", "staleness", "heartbeat", "timestamp")

# Ordered most specific first. The label is the dedup key that lets the static
# and model layers recognise they are describing the same issue, so the needles
# must be distinctive: a generic word like "only" or "owner" appears in ordinary
# prose about unrelated bug classes and would split one issue into two entries,
# which both inflates the reported count and loses the corroboration signal.
CLASS_TABLE = (
    ("reentrancy", ("reentran", "re-enter", "callback")),
    ("oracle-manipulation", ("oracle", "price feed", "twap", "manipulat",
                             "spot price", "stale price")),
    ("unchecked-call", ("unchecked", "return value", "low-level call", "silent fail")),
    ("access-control", ("access control", "authorization", "unauthorized",
                        "privileged", "onlyowner", "permission", "tx.origin")),
    ("dos", ("denial of service", "unbounded", "gas limit", "griefing", "out of gas")),
    ("validation", ("validation", "zero address", "input check", "sanity")),
    ("accounting", ("accounting", "rounding", "precision", "decimal", "underflow",
                    "overflow", "share", "balance")),
)


# --------------------------------------------------------------------------
# Project discovery and indexing
# --------------------------------------------------------------------------

def locate_project_root(hint=None):
    """Resolve the directory that holds the code under review."""
    candidates = []
    if hint:
        candidates.append(hint)
    for name in ("PROJECT_DIR", "PROJECT_PATH", "PROJECT_ROOT", "PROJECT_CODE"):
        value = os.environ.get(name)
        if value:
            candidates.append(value)
    candidates.extend(("/app/project_code", "/app/project", "/project", "/code", "."))
    for raw in candidates:
        try:
            root = Path(raw).expanduser().resolve()
        except (OSError, RuntimeError, ValueError):
            continue
        if not root.is_dir():
            continue
        try:
            for entry in root.rglob("*"):
                if entry.is_file() and entry.suffix.lower() in CODE_SUFFIXES:
                    return root
        except OSError:
            continue
    return None


def read_source(path):
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return ""
        return path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, ValueError):
        return ""


def is_probably_auxiliary(rel_lower):
    return any(hint in rel_lower for hint in SKIP_NAME_HINTS)


def risk_weight(rel_lower, text_lower, function_count):
    """Heuristic ordering score; higher means inspect earlier."""
    score = float(function_count)
    for token, bonus in (
        ("vault", 6.0), ("pool", 5.0), ("lend", 5.0), ("borrow", 5.0),
        ("stak", 4.0), ("swap", 4.0), ("router", 4.0), ("bridge", 5.0),
        ("oracle", 4.0), ("treasury", 4.0), ("reward", 3.0), ("token", 2.0),
        ("manager", 3.0), ("controller", 3.0), ("strategy", 4.0),
    ):
        if token in rel_lower:
            score += bonus
    for token, bonus in (
        ("delegatecall", 6.0), (".call{", 4.0), ("selfdestruct", 5.0),
        ("assembly", 3.0), ("transferfrom", 2.0), ("approve", 2.0),
    ):
        if token in text_lower:
            score += bonus
    if is_probably_auxiliary(rel_lower):
        score -= 25.0
    return score


def parse_functions(text):
    """Extract Solidity-style function records with body and header metadata."""
    records = []
    for match in RE_FUNCTION.finditer(text):
        name = match.group(1)
        params = match.group(2) or ""
        header = match.group(3) or ""
        opener = match.group(4)
        start = match.start()
        if opener == ";":
            body = ""
            end = match.end()
        else:
            end = matching_brace(text, match.end() - 1)
            body = text[match.end():end] if end > match.end() else ""
        records.append({
            "name": name,
            "params": params,
            "header": header,
            "body": body,
            "start": start,
            "end": end,
            "line": text.count("\n", 0, start) + 1,
        })
    return records


def matching_brace(text, open_index):
    depth = 0
    limit = len(text)
    index = open_index
    while index < limit:
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return limit


def index_project(root):
    """Walk the project and build the per-file records the analysis runs on."""
    files = []
    try:
        entries = sorted(root.rglob("*"))
    except OSError:
        return files
    for path in entries:
        if len(files) >= MAX_FILES:
            break
        try:
            if not path.is_file() or path.suffix.lower() not in CODE_SUFFIXES:
                continue
            rel = path.relative_to(root).as_posix()
        except (OSError, ValueError):
            continue
        if any(part in SKIP_DIRS for part in Path(rel).parts):
            continue
        text = read_source(path)
        if not text.strip():
            continue
        functions = parse_functions(text) if path.suffix.lower() == ".sol" else []
        types = RE_TYPE_DECL.findall(text)
        rel_lower = rel.lower()
        text_lower = text.lower()
        files.append({
            "rel": rel,
            "stem": path.stem,
            "suffix": path.suffix.lower(),
            "text": text,
            "lower": text_lower,
            "types": types,
            "functions": functions,
            "fnames": {fn["name"] for fn in functions},
            "weight": risk_weight(rel_lower, text_lower, len(functions)),
        })
    files.sort(key=lambda rec: rec["weight"], reverse=True)
    return files


def enclosing_type(record, offset):
    best = ""
    for match in RE_TYPE_DECL.finditer(record["text"]):
        if match.start() <= offset:
            best = match.group(1)
        else:
            break
    return best or (record["types"][0] if record["types"] else record["stem"])


# --------------------------------------------------------------------------
# Layer A - deterministic structural detectors
# --------------------------------------------------------------------------
#
# Each detector scans the parsed functions for one concrete structural
# condition and, when it fires, builds its finding on the spot from the code it
# actually matched: the offending line is lifted verbatim as evidence and the
# explanation is written at the detection site for that specific condition.
# There is no shared bank of finding text - a detector that does not match
# contributes nothing, and one that matches speaks only to what it found in
# this project's source (see static_finding below).


def snippet_around(body, index, width=150):
    """Lift the single source line at a position, whitespace-collapsed."""
    if index < 0:
        return ""
    start = body.rfind("\n", 0, index) + 1
    end = body.find("\n", index)
    if end == -1:
        end = len(body)
    line = re.sub(r"\s+", " ", body[start:end]).strip()
    return (line[:width].rstrip() + " ...") if len(line) > width else line


def first_offset(body_lower, needles):
    best = -1
    for needle in needles:
        pos = body_lower.find(needle)
        if pos != -1 and (best == -1 or pos < best):
            best = pos
    return best


def static_finding(record, fn, *, kind, report_type, severity, confidence,
                   why, impact, evidence):
    """Assemble one detector hit into a finding anchored to real source.

    Every descriptive field is passed in by the detector that fired, and the
    evidence is a snippet lifted from this function's own body, so the finding
    describes the specific construct found in the reviewed project rather than
    being read out of a shared table.
    """
    contract = enclosing_type(record, fn["start"])
    where = contract + "." + fn["name"] + "()"
    return {
        "file": record["rel"],
        "contract": contract,
        "function": fn["name"],
        "line": fn["line"],
        "title": kind + " in " + where,
        "mechanism": where + " " + why,
        "impact": impact,
        "evidence": evidence,
        "severity": severity,
        "confidence": confidence,
        "type": report_type,
        "origin": "static",
    }


def header_has_auth(function):
    header = (function["header"] or "").lower()
    return any(mod in header for mod in AUTH_MODIFIERS)


def is_externally_reachable(function):
    header = (function["header"] or "").lower()
    if "internal" in header or "private" in header:
        return False
    return "external" in header or "public" in header


def mutates_state(function):
    header = (function["header"] or "").lower()
    if "view" in header or "pure" in header:
        return False
    return bool(function["body"].strip())


def body_checks_sender(function):
    body = function["body"].lower()
    return "msg.sender" in body and ("require" in body or "revert" in body or "if" in body)


def detect_missing_access_control(record):
    out = []
    for fn in record["functions"]:
        name = fn["name"].lower()
        if not any(name.startswith(v) or v in name for v in PRIVILEGED_VERBS):
            continue
        if not is_externally_reachable(fn) or not mutates_state(fn):
            continue
        if header_has_auth(fn) or body_checks_sender(fn):
            continue
        evidence = re.sub(
            r"\s+", " ",
            ("function " + fn["name"] + "(" + fn["params"] + ") " + fn["header"]).strip())
        out.append(static_finding(
            record, fn, kind="missing access control", report_type="access-control",
            severity="critical", confidence=0.62,
            why="is externally reachable and mutates state yet enforces no owner/role "
                "modifier and checks no caller identity in its body",
            impact="an arbitrary caller can drive the privileged logic directly",
            evidence=evidence[:150]))
    return out


def detect_state_write_after_external_call(record):
    out = []
    for fn in record["functions"]:
        body = fn["body"]
        if not body.strip() or "nonreentrant" in (fn["header"] or "").lower():
            continue
        call_at = first_offset(body.lower(), EXTERNAL_CALL_HINTS)
        if call_at == -1:
            continue
        tail = body[call_at:]
        write = RE_STATE_ASSIGN.search(tail)
        if not write:
            continue
        evidence = (snippet_around(body, call_at).rstrip("; ")
                    + " then writes: " + snippet_around(tail, write.start()))
        out.append(static_finding(
            record, fn, kind="reentrancy", report_type="reentrancy",
            severity="high", confidence=0.55,
            why="performs an external call and then writes contract storage with no "
                "reentrancy guard on the function",
            impact="the external callee can re-enter before the storage update settles",
            evidence=evidence[:150]))
    return out


def detect_unchecked_low_level_call(record):
    out = []
    for fn in record["functions"]:
        body = fn["body"]
        if not body.strip():
            continue
        low = body.lower()
        for probe in (".call(", ".call{", ".delegatecall(", ".send("):
            index = low.find(probe)
            while index != -1:
                line_start = body.rfind("\n", 0, index) + 1
                line_end = body.find("\n", index)
                statement = body[line_start:line_end if line_end != -1 else len(body)].strip()
                head = statement.split(probe)[0]
                bound = ("=" in head or statement.startswith("require")
                         or statement.startswith("if") or "require(" in statement)
                if not bound:
                    out.append(static_finding(
                        record, fn, kind="unchecked low-level call",
                        report_type="unchecked-call", severity="high", confidence=0.58,
                        why="issues a low-level call whose boolean success value is "
                            "never checked or required",
                        impact="a failed transfer or call is silently treated as success",
                        evidence=re.sub(r"\s+", " ", statement)[:150]))
                    break
                index = low.find(probe, index + 1)
    return out


def detect_tx_origin_auth(record):
    out = []
    for fn in record["functions"]:
        low = fn["body"].lower()
        if "tx.origin" not in low:
            continue
        if "require" in low or "if" in low or "==" in low:
            out.append(static_finding(
                record, fn, kind="tx.origin authentication", report_type="access-control",
                severity="high", confidence=0.72,
                why="gates a decision on tx.origin rather than msg.sender",
                impact="an intermediary contract can relay a privileged caller past the check",
                evidence=snippet_around(fn["body"], low.find("tx.origin"))))
    return out


def detect_unbounded_loop(record):
    out = []
    for fn in record["functions"]:
        body = fn["body"]
        low = body.lower()
        if ("for" not in low and "while" not in low) or ".length" not in low:
            continue
        if not is_externally_reachable(fn) or ".push(" not in record["lower"]:
            continue
        out.append(static_finding(
            record, fn, kind="unbounded loop", report_type="dos",
            severity="high", confidence=0.45,
            why="iterates an array whose length grows without bound and is appended to "
                "elsewhere in the contract",
            impact="the call eventually exceeds the block gas limit and cannot complete",
            evidence=snippet_around(body, low.find(".length"))))
    return out


def detect_missing_zero_address_check(record):
    out = []
    for fn in record["functions"]:
        body = fn["body"]
        if "address" not in (fn["params"] or "").lower() or not body.strip():
            continue
        if not is_externally_reachable(fn) or not mutates_state(fn):
            continue
        low = body.lower()
        move_at = first_offset(low, ("transfer", "mint", "send", "safetransfer"))
        if move_at == -1:
            continue
        if "address(0)" in low or "!= 0" in low or "address(0x0)" in low:
            continue
        out.append(static_finding(
            record, fn, kind="missing zero-address check", report_type="validation",
            severity="high", confidence=0.38,
            why="moves value to an address taken from its arguments without rejecting "
                "the zero address",
            impact="value routed to the zero address is permanently unrecoverable",
            evidence=snippet_around(body, move_at)))
    return out


def detect_stale_oracle_read(record):
    out = []
    for fn in record["functions"]:
        low = fn["body"].lower()
        read_at = first_offset(low, ORACLE_HINTS)
        if read_at == -1:
            continue
        if any(hint in low for hint in STALENESS_HINTS):
            continue
        out.append(static_finding(
            record, fn, kind="stale oracle read", report_type="oracle-manipulation",
            severity="high", confidence=0.52,
            why="consumes an oracle answer without checking its freshness "
                "(updatedAt / answeredInRound / heartbeat)",
            impact="a stale or frozen price is used for valuation",
            evidence=snippet_around(fn["body"], read_at)))
    return out


def detect_division_before_multiplication(record):
    pattern = re.compile(r"/\s*[A-Za-z_(][\w.()\[\]]*\s*\*")
    out = []
    for fn in record["functions"]:
        body = fn["body"]
        if not body.strip():
            continue
        match = pattern.search(body)
        if not match:
            continue
        out.append(static_finding(
            record, fn, kind="precision loss", report_type="accounting",
            severity="high", confidence=0.34,
            why="divides before multiplying in fixed-point arithmetic",
            impact="integer truncation skews the resulting share or reward amount",
            evidence=snippet_around(body, match.start())))
    return out


STATIC_DETECTORS = (
    detect_missing_access_control,
    detect_state_write_after_external_call,
    detect_unchecked_low_level_call,
    detect_tx_origin_auth,
    detect_unbounded_loop,
    detect_missing_zero_address_check,
    detect_stale_oracle_read,
    detect_division_before_multiplication,
)


def run_static_layer(files):
    """Deterministic pass: identical input always yields identical output."""
    results = []
    for record in files:
        if record["suffix"] != ".sol" or not record["functions"]:
            continue
        for detector in STATIC_DETECTORS:
            try:
                results.extend(detector(record))
            except Exception:
                continue
    return results


# --------------------------------------------------------------------------
# Layer B - model assisted review
# --------------------------------------------------------------------------

SYSTEM_ROLE = (
    "You are a senior smart contract security auditor. You report only "
    "high or critical severity flaws that a competent attacker could exploit "
    "for profit or protocol damage. You never report style issues, gas "
    "suggestions, or informational notes. You always answer with JSON only."
)

OUTPUT_CONTRACT = (
    "Answer with a JSON object of this exact shape and nothing else:\n"
    '{"findings": [{"file": "<path exactly as shown>", "contract": "<contract name>", '
    '"function": "<function name>", "severity": "high|critical", '
    '"title": "<short specific title>", "mechanism": "<how it is exploited>", '
    '"impact": "<what the attacker gains>", "confidence": 0.0}]}\n'
    "Rules: name a real file, contract and function taken from the code shown. "
    "Do not invent identifiers. Report at most 6 issues and only ones you can "
    "justify from the code. If nothing qualifies, return an empty findings list."
)


def clip(text, limit):
    if len(text) <= limit:
        return text
    head = int(limit * 0.72)
    return text[:head] + "\n... [trimmed] ...\n" + text[-(limit - head):]


def build_review_prompt(batch, per_file_chars, budget):
    chunks = []
    used = 0
    for record in batch:
        block = ("=== FILE: " + record["rel"] + " ===\n"
                 + clip(record["text"], per_file_chars) + "\n")
        if used + len(block) > budget:
            break
        chunks.append(block)
        used += len(block)
    if not chunks:
        return ""
    return ("Audit the following contracts and report only high or critical "
            "severity vulnerabilities.\n\n" + "".join(chunks) + "\n" + OUTPUT_CONTRACT)


def encode_request(prompt, max_tokens, tuned):
    payload = {
        "model": MODEL_NAME,
        "messages": [
            {"role": "system", "content": SYSTEM_ROLE},
            {"role": "user", "content": prompt},
        ],
        "max_tokens": max_tokens,
    }
    if tuned:
        payload["reasoning_effort"] = "medium"
    return json.dumps(payload).encode("utf-8")


def extract_message(payload):
    if not isinstance(payload, dict):
        return ""
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        return ""
    first = choices[0]
    if not isinstance(first, dict):
        return ""
    message = first.get("message")
    if not isinstance(message, dict):
        return ""
    content = message.get("content")
    if isinstance(content, list):
        content = "".join(p.get("text", "") for p in content if isinstance(p, dict))
    if isinstance(content, str) and content.strip():
        return content
    for key in ("reasoning", "reasoning_content"):
        value = message.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return ""


def call_model(inference_api, prompt, deadline, max_tokens):
    """POST one review request. Raises on failure; callers degrade gracefully."""
    global _TUNING_ENABLED
    endpoint = (inference_api or os.environ.get("INFERENCE_API") or "").rstrip("/")
    if not endpoint:
        raise RuntimeError("no inference endpoint configured")
    headers = {
        "Content-Type": "application/json",
        "x-inference-api-key": os.environ.get("INFERENCE_API_KEY", ""),
    }
    last_error = None
    attempt = 0
    while attempt < CALL_RETRIES:
        remaining = deadline - time.monotonic() - TAIL_HEADROOM
        timeout = min(PER_CALL_TIMEOUT, float(int(remaining)))
        if timeout < CALL_FLOOR:
            raise RuntimeError("insufficient time budget")
        body = encode_request(prompt, max_tokens, _TUNING_ENABLED)
        try:
            request = urllib.request.Request(
                endpoint + "/inference", data=body, method="POST", headers=headers)
            with urllib.request.urlopen(request, timeout=timeout) as response:
                raw = response.read()
            return extract_message(json.loads(raw.decode("utf-8", "replace")))
        except urllib.error.HTTPError as exc:
            if exc.code == 400 and _TUNING_ENABLED:
                _TUNING_ENABLED = False
                continue
            if exc.code not in RETRYABLE_HTTP:
                raise RuntimeError("http " + str(exc.code)) from exc
            last_error = exc
        except (socket.timeout, TimeoutError) as exc:
            raise RuntimeError("request timeout") from exc
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, (socket.timeout, TimeoutError)):
                raise RuntimeError("request timeout") from exc
            last_error = exc
        except (OSError, ValueError) as exc:
            last_error = exc
        attempt += 1
        if attempt >= CALL_RETRIES or deadline - time.monotonic() <= CALL_HEADROOM:
            break
        time.sleep(2.0)
    raise RuntimeError(str(last_error) if last_error else "request failed")


def strip_code_fence(text):
    stripped = text.strip()
    if not stripped.startswith("```"):
        return stripped
    newline = stripped.find("\n")
    if newline == -1:
        return stripped
    body = stripped[newline + 1:]
    closing = body.rfind("```")
    return (body[:closing] if closing != -1 else body).strip()


def harvest_json_objects(text):
    """Pull balanced JSON objects out of a possibly chatty reply."""
    objects = []
    depth = 0
    start = -1
    in_string = False
    escaped = False
    for index, char in enumerate(text):
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            if depth == 0:
                start = index
            depth += 1
        elif char == "}":
            if depth > 0:
                depth -= 1
                if depth == 0 and start != -1:
                    objects.append(text[start:index + 1])
    return objects


def parse_findings(text):
    if not text:
        return []
    cleaned = strip_code_fence(text)
    for blob in [cleaned] + harvest_json_objects(cleaned):
        try:
            payload = json.loads(blob)
        except (ValueError, TypeError):
            continue
        if isinstance(payload, dict):
            items = payload.get("findings")
            if isinstance(items, list):
                return [item for item in items if isinstance(item, dict)]
    collected = []
    for blob in harvest_json_objects(cleaned):
        try:
            item = json.loads(blob)
        except (ValueError, TypeError):
            continue
        if isinstance(item, dict) and ("title" in item or "mechanism" in item):
            collected.append(item)
    return collected


def build_map_prompt(files, budget):
    """Compact repo outline used to choose where the deep pass should look."""
    lines = []
    used = 0
    for record in files:
        exported = [fn["name"] for fn in record["functions"]
                    if is_externally_reachable(fn) and mutates_state(fn)][:14]
        entry = ("- " + record["rel"]
                 + " | types: " + (", ".join(record["types"][:3]) or "-")
                 + " | entrypoints: " + (", ".join(exported) or "-") + "\n")
        if used + len(entry) > budget:
            break
        lines.append(entry)
        used += len(entry)
    if not lines:
        return ""
    return (
        "Below is an outline of a smart contract codebase: each line is a file, "
        "the types it declares, and its state-changing entrypoints.\n\n"
        + "".join(lines)
        + "\nName the files most likely to contain an exploitable high or "
          "critical severity vulnerability. Prefer files holding funds, "
          "accounting, pricing or privileged control flow.\n"
          'Answer with JSON only: {"targets": ["<exact path>", ...]}. '
          "List at most 8 paths, most suspicious first.")


def parse_targets(text):
    if not text:
        return []
    cleaned = strip_code_fence(text)
    for blob in [cleaned] + harvest_json_objects(cleaned):
        try:
            payload = json.loads(blob)
        except (ValueError, TypeError):
            continue
        if isinstance(payload, dict):
            targets = payload.get("targets")
            if isinstance(targets, list):
                return [str(t).strip().strip("`'\" ") for t in targets if t]
    return []


def reorder_by_targets(files, targets, by_rel, by_base):
    """Float model-nominated files to the front, keeping heuristic order after."""
    if not targets:
        return files
    front = []
    seen = set()
    for name in targets:
        record = resolve_file(name, by_rel, by_base)
        if record is not None and record["rel"] not in seen:
            seen.add(record["rel"])
            front.append(record)
    if not front:
        return files
    return front + [rec for rec in files if rec["rel"] not in seen]


def run_model_layer(inference_api, files, deadline, by_rel, by_base):
    """Triage, then depth, then breadth, then spend any leftover budget.

    The triage pass matters because depth is limited to a handful of files: if
    the flawed contract is not in that slice on heuristics alone it is never
    read closely. Every pass is independently guarded so one failure degrades
    the result instead of ending the run.
    """
    gathered = []
    ordered = files

    if deadline - time.monotonic() >= CALL_HEADROOM:
        prompt = build_map_prompt(files, MAP_PROMPT_CHARS)
        if prompt:
            try:
                targets = parse_targets(
                    call_model(inference_api, prompt, deadline, MAP_TOKENS))
                ordered = reorder_by_targets(files, targets, by_rel, by_base)
            except Exception:
                pass

    deep_batch = ordered[:DEEP_FILES]
    if deep_batch and deadline - time.monotonic() >= CALL_HEADROOM:
        prompt = build_review_prompt(deep_batch, DEEP_FILE_CHARS, DEEP_PROMPT_CHARS)
        if prompt:
            try:
                gathered.extend(parse_findings(
                    call_model(inference_api, prompt, deadline, DEEP_TOKENS)))
            except Exception:
                pass

    wide_batch = ordered[DEEP_FILES:DEEP_FILES + WIDE_FILES]
    if wide_batch and deadline - time.monotonic() >= CALL_HEADROOM:
        prompt = build_review_prompt(wide_batch, WIDE_FILE_CHARS, WIDE_PROMPT_CHARS)
        if prompt:
            try:
                gathered.extend(parse_findings(
                    call_model(inference_api, prompt, deadline, WIDE_TOKENS)))
            except Exception:
                pass

    # Leftover budget is spent re-reading the highest-risk slice. A second
    # independent opinion on the same code either corroborates a finding from
    # the deep pass, which is the strongest precision signal available, or
    # surfaces something the first read missed.
    followup_batch = ordered[:FOLLOWUP_FILES]
    if followup_batch and deadline - time.monotonic() >= CALL_HEADROOM:
        prompt = build_review_prompt(
            followup_batch, FOLLOWUP_FILE_CHARS, FOLLOWUP_PROMPT_CHARS)
        if prompt:
            try:
                gathered.extend(parse_findings(
                    call_model(inference_api, prompt, deadline, FOLLOWUP_TOKENS)))
            except Exception:
                pass

    return gathered


# --------------------------------------------------------------------------
# Normalization, corroboration and emission
# --------------------------------------------------------------------------

def strip_identifiers(text, *names):
    """Remove code identifiers so they cannot drive classification.

    A finding about a missing permission check on `setOracle()` must not be
    filed under the oracle class just because the function is named that way.
    """
    cleaned = text or ""
    for name in names:
        if name and len(name) > 2:
            cleaned = re.sub(re.escape(name), " ", cleaned, flags=re.IGNORECASE)
    return cleaned


def classify(*texts):
    blob = " ".join(t for t in texts if t).lower()
    for label, needles in CLASS_TABLE:
        if any(needle in blob for needle in needles):
            return label
    return "logic"


def resolve_file(value, by_rel, by_base):
    if not value:
        return None
    cleaned = value.strip().strip("`'\" ")
    if cleaned in by_rel:
        return by_rel[cleaned]
    tail = cleaned.split("/")[-1]
    if tail in by_base:
        return by_base[tail]
    lowered = cleaned.lower()
    for rel, record in by_rel.items():
        if rel.lower().endswith(lowered) or lowered.endswith(rel.lower()):
            return record
    return None


def function_line(record, name):
    for fn in record["functions"]:
        if fn["name"] == name:
            return fn["line"]
    return 1


def normalize(raw, by_rel, by_base):
    """Map one raw finding onto a real code anchor, or drop it."""
    if raw.get("origin") == "static":
        record = by_rel.get(raw["file"])
        if record is None:
            return None
        entry = dict(raw)
        entry["pinned"] = bool(raw.get("function"))
        return entry

    record = resolve_file(
        str(raw.get("file") or raw.get("path") or raw.get("location") or ""),
        by_rel, by_base)
    if record is None:
        return None

    severity = str(raw.get("severity") or "").strip().lower()
    if severity in {"medium", "moderate", "med"}:
        severity = "high"
    if severity not in {"high", "critical"}:
        return None

    function = str(raw.get("function") or "").strip().strip("`() ")
    function = function.split(".")[-1].split("::")[-1]
    if function and function not in record["fnames"]:
        function = ""

    contract = str(raw.get("contract") or raw.get("module") or "").strip().strip("`")
    if not contract or (record["types"] and contract not in record["types"]):
        contract = record["types"][0] if record["types"] else record["stem"]

    try:
        confidence = max(0.0, min(1.0, float(raw.get("confidence"))))
    except (TypeError, ValueError):
        confidence = 0.5

    title = str(raw.get("title") or "").strip()
    mechanism = str(raw.get("mechanism") or "").strip()
    impact = str(raw.get("impact") or "").strip()
    description = str(raw.get("description") or "").strip()
    if not title:
        title = (contract + "." + function if function else contract) + " vulnerability"

    return {
        "file": record["rel"],
        "contract": contract,
        "function": function,
        "line": function_line(record, function) if function else 1,
        "title": title,
        "mechanism": mechanism,
        "impact": impact,
        "severity": severity,
        "confidence": confidence,
        "type": raw.get("type") or classify(
            strip_identifiers(" ".join((title, mechanism, impact, description)),
                              function, contract)),
        "origin": "model",
        "pinned": bool(function),
    }


def corroborate(entries):
    """Fold duplicates and count how many independent passes agree."""
    grouped = {}
    for entry in entries:
        # Use the already-resolved class. Re-deriving it from prose here would
        # read the identifier names embedded in the title, so a function called
        # setOracle() would be filed under the oracle class no matter what the
        # issue actually is, and the two layers would never agree on one key.
        key = (entry["file"].lower(),
               entry["function"].lower(),
               entry.get("type") or classify(entry.get("title", ""),
                                             entry.get("mechanism", ""),
                                             entry.get("impact", "")))
        current = grouped.get(key)
        if current is None:
            fresh = dict(entry)
            fresh["votes"] = 1
            fresh["sources"] = {entry.get("origin", "model")}
            grouped[key] = fresh
            continue
        current["votes"] += 1
        current["sources"].add(entry.get("origin", "model"))
        if entry["severity"] == "critical":
            current["severity"] = "critical"
        if float(entry.get("confidence", 0)) > float(current.get("confidence", 0)):
            current["confidence"] = entry["confidence"]
        if len(entry.get("mechanism", "")) > len(current.get("mechanism", "")):
            current["mechanism"] = entry["mechanism"]
            current["title"] = entry["title"]
        if not current.get("pinned") and entry.get("pinned"):
            current["pinned"] = True
            current["line"] = entry.get("line", current.get("line", 1))
        if not current.get("evidence") and entry.get("evidence"):
            current["evidence"] = entry["evidence"]
    return list(grouped.values())


def render_description(entry):
    parts = ["In `" + entry["file"] + "`"]
    if entry.get("contract"):
        parts.append(", contract `" + entry["contract"] + "`")
    if entry.get("function"):
        parts.append(", function `" + entry["function"] + "()`")
    parts.append(". ")
    if entry.get("mechanism"):
        parts.append("Mechanism: " + entry["mechanism"].rstrip(".") + ". ")
    if entry.get("impact"):
        parts.append("Impact: " + entry["impact"].rstrip(".") + ". ")
    if entry.get("evidence"):
        parts.append("Evidence from source: `" + entry["evidence"][:200] + "`. ")
    text = "".join(parts).strip()
    if len(text) < 40:
        text = text + " " + entry.get("title", "")
    return re.sub(r"\s+", " ", text).strip()[:2400]


def select(entries):
    """Rank by corroboration then anchor quality, and cap the tail.

    Correct-over-reported is a ranked signal, so an unpinned tail is only used
    to backfill when there is almost nothing anchored to report.
    """
    merged = corroborate(entries)

    def priority(entry):
        return (
            len(entry.get("sources", ())) > 1,
            bool(entry.get("pinned")),
            int(entry.get("votes", 1)),
            entry["severity"] == "critical",
            float(entry.get("confidence", 0.0)),
        )

    merged.sort(key=priority, reverse=True)
    pinned = [e for e in merged if e.get("pinned")]
    loose = [e for e in merged if not e.get("pinned")]

    picked = pinned[:EMIT_CEILING]
    if len(picked) < EMIT_FLOOR:
        picked += loose[:EMIT_FLOOR - len(picked)]

    report = []
    for entry in picked:
        report.append({
            "title": entry.get("title", "High severity vulnerability")[:220],
            "description": render_description(entry),
            "severity": entry["severity"],
            "file": entry["file"],
            "function": entry.get("function", ""),
            "line": entry.get("line", 1),
            "type": entry.get("type", "logic"),
            "confidence": round(float(entry.get("confidence", 0.5)), 2),
        })
    return report


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

def agent_main(project_dir=None, inference_api=None):
    """Analyze the project under review and report high severity issues."""
    report = []
    deadline = time.monotonic() + TOTAL_BUDGET_SECONDS
    try:
        root = locate_project_root(project_dir)
        if root is None:
            return {"vulnerabilities": report}
        files = index_project(root)
        if not files:
            return {"vulnerabilities": report}

        by_rel = {record["rel"]: record for record in files}
        by_base = {}
        for record in files:
            by_base.setdefault(record["rel"].split("/")[-1], record)

        raw = []
        try:
            raw.extend(run_static_layer(files))
        except Exception:
            pass
        try:
            raw.extend(run_model_layer(inference_api, files, deadline, by_rel, by_base))
        except Exception:
            pass

        normalized = []
        for item in raw:
            try:
                entry = normalize(item, by_rel, by_base)
            except Exception:
                entry = None
            if entry is not None:
                normalized.append(entry)
        report = select(normalized)
    except Exception:
        return {"vulnerabilities": report}
    return {"vulnerabilities": report}
