from __future__ import annotations

"""SN60 / Bitsec miner agent — pattern-pre-screened LLM vulnerability scanner.

Strategy (differs from Tet-9-20260706-01):
1. Walk *.sol files and run lightweight regex patterns to flag suspicious
   constructs (reentrancy, unchecked calls, tx.origin, etc.) BEFORE sending
   to the model. This pre-screening focuses the model on files that already
   show suspicious patterns, improving precision and reducing noise.
2. For each flagged file, send the model the full source + the specific
   patterns that triggered, asking it to confirm or reject each one and
   find additional issues.
3. Deduplicate and rank findings by severity.
"""

import json
import os
import pathlib
import re
import urllib.request

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_MAX_CHUNK = 5000

# Lightweight pre-screen patterns — each is a (label, regex) pair.
# These flag files worth deeper LLM inspection without running the model.
_PATTERNS = [
    ("reentrancy",        re.compile(r"\.call\{value:", re.I)),
    ("reentrancy",        re.compile(r"\.call\.value\(", re.I)),
    ("unchecked-call",    re.compile(r"\.call\(", re.I)),
    ("tx-origin",         re.compile(r"\btx\.origin\b")),
    ("delegatecall",      re.compile(r"\.delegatecall\(")),
    ("selfdestruct",      re.compile(r"\bselfdestruct\b|\bsuicide\b")),
    ("overflow",          re.compile(r"\bunchecked\s*\{", re.I)),
    ("access-control",    re.compile(r"function\s+\w+\s*\([^)]*\)\s*(?:external|public)\s*(?!.*(?:onlyOwner|require|modifier))", re.M)),
    ("timestamp",         re.compile(r"\bblock\.timestamp\b|\bnow\b")),
    ("assembly",          re.compile(r"\bassembly\b\s*\{")),
]

_PROMPT_TEMPLATE = (
    "You are an expert smart-contract security auditor.\n\n"
    "The following Solidity file triggered these suspicious pattern(s): {patterns}\n\n"
    "Carefully analyze the code and identify all HIGH and CRITICAL severity vulnerabilities.\n"
    "For each vulnerability, confirm whether the flagged pattern is a real issue, "
    "and identify any additional vulnerabilities you find.\n\n"
    "Respond ONLY with a JSON array (no prose outside the block):\n"
    "```json\n"
    "[\n"
    "  {{\n"
    '    "title": "Short descriptive title",\n'
    '    "description": "Explanation of the vulnerability and exploit scenario",\n'
    '    "severity": "high",\n'
    '    "type": "reentrancy",\n'
    '    "file": "{filename}",\n'
    '    "function": "affectedFunction",\n'
    '    "line": 0,\n'
    '    "confidence": 0.85,\n'
    '    "recommendation": "How to fix it"\n'
    "  }}\n"
    "]\n"
    "```\n\n"
    "If no real high/critical vulnerabilities: ```json\n[]\n```\n\n"
    "File: {filename}\n"
    "```solidity\n{source}\n```"
)

_JSON_RE = re.compile(r"```(?:json)?\s*([\s\S]*?)```", re.I)


def _ask(inference_api, prompt):
    endpoint = (inference_api or os.environ.get("INFERENCE_API", "")).rstrip("/")
    key = os.environ.get("INFERENCE_API_KEY", "")
    body = json.dumps({
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 3000,
    }).encode()
    req = urllib.request.Request(
        endpoint + "/inference",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "x-inference-api-key": key,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=90) as resp:
            data = json.loads(resp.read().decode())
        return data["choices"][0]["message"]["content"]
    except Exception:
        return ""


def _prescreen(source):
    """Return list of pattern labels that match in source."""
    triggered = []
    seen = set()
    for label, pattern in _PATTERNS:
        if label not in seen and pattern.search(source):
            triggered.append(label)
            seen.add(label)
    return triggered


def _parse(raw, filename):
    for m in _JSON_RE.finditer(raw):
        try:
            data = json.loads(m.group(1))
            if isinstance(data, list):
                return _normalize(data, filename)
        except json.JSONDecodeError:
            continue
    s, e = raw.find("["), raw.rfind("]")
    if s != -1 and e > s:
        try:
            data = json.loads(raw[s:e + 1])
            if isinstance(data, list):
                return _normalize(data, filename)
        except json.JSONDecodeError:
            pass
    return []


def _normalize(items, filename):
    out = []
    for item in items:
        if not isinstance(item, dict):
            continue
        sev = str(item.get("severity", "high")).lower()
        if sev not in _SEVERITY_RANK:
            sev = "high"
        out.append({
            "title": str(item.get("title", "Vulnerability")),
            "description": str(item.get("description", "")),
            "severity": sev,
            "type": str(item.get("type", "")),
            "file": str(item.get("file", filename)),
            "function": str(item.get("function", "")),
            "line": int(item.get("line", 0) or 0),
            "confidence": float(item.get("confidence", 0.85)),
            "recommendation": str(item.get("recommendation", "")),
        })
    return out


def _scan(filepath, root, inference_api):
    try:
        source = filepath.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    rel = str(filepath.relative_to(root))
    triggered = _prescreen(source)
    if not triggered:
        return []
    findings = []
    chunks = [source[i:i + _MAX_CHUNK] for i in range(0, len(source), _MAX_CHUNK)]
    for chunk in chunks[:3]:
        prompt = _PROMPT_TEMPLATE.format(
            patterns=", ".join(triggered),
            filename=rel,
            source=chunk,
        )
        raw = _ask(inference_api, prompt)
        if raw:
            findings.extend(_parse(raw, rel))
    return findings


def _dedup(findings):
    seen = set()
    out = []
    for f in findings:
        key = (f.get("file", ""), f.get("function", ""), f.get("title", "")[:60])
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


_PRIORITY = ("admin", "owner", "vault", "token", "wallet", "proxy",
             "upgrade", "bridge", "escrow", "dao", "govern")


def agent_main(project_dir=None, inference_api=None):
    root = pathlib.Path(project_dir or ".").resolve()
    api = inference_api or os.environ.get("INFERENCE_API", "")
    sol_files = sorted(root.rglob("*.sol"))

    def _pri(p):
        return 0 if any(k in p.name.lower() for k in _PRIORITY) else 1

    sol_files.sort(key=_pri)
    all_findings = []
    for sol in sol_files[:25]:
        all_findings.extend(_scan(sol, root, api))
    deduped = _dedup(all_findings)
    deduped.sort(key=lambda f: _SEVERITY_RANK.get(f.get("severity", "info"), 4))
    return {"vulnerabilities": deduped}
