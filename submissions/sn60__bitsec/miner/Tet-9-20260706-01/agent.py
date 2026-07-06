from __future__ import annotations

import json
import os
import pathlib
import re
import urllib.request

_JSON_BLOCK = re.compile(r"```(?:json)?\s*([\s\S]*?)```", re.IGNORECASE)
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_MAX_CHUNK = 6000
_PRIORITY = ("admin", "owner", "vault", "token", "wallet", "proxy",
              "upgrade", "bridge", "escrow", "dao", "govern")

_PROMPT = (
    "You are an expert smart-contract security auditor specializing in Solidity.\n\n"
    "Analyze the following Solidity source and identify all HIGH and CRITICAL severity "
    "security vulnerabilities.\n\n"
    "Focus on: reentrancy, integer overflow/underflow, missing access control, unchecked "
    "return values, front-running, timestamp dependence, delegatecall injection, "
    "selfdestruct abuse, flash loan vulnerabilities, tx.origin authentication.\n\n"
    "Respond ONLY with a JSON array:\n"
    "```json\n"
    "[\n"
    "  {\n"
    '    "title": "Short title",\n'
    '    "description": "Detailed explanation",\n'
    '    "severity": "high",\n'
    '    "type": "reentrancy",\n'
    '    "file": "{filename}",\n'
    '    "function": "functionName",\n'
    '    "line": 42,\n'
    '    "confidence": 0.9,\n'
    '    "recommendation": "Specific fix"\n'
    "  }\n"
    "]\n"
    "```\n\n"
    "If none found: ```json\n[]\n```\n\n"
    "File: {filename}\n"
    "```solidity\n{source}\n```"
)


def _ask(inference_api, prompt, max_tokens=3000):
    endpoint = (inference_api or os.environ.get("INFERENCE_API", "")).rstrip("/")
    key = os.environ.get("INFERENCE_API_KEY", "")
    body = json.dumps({
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": max_tokens,
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


def _parse_findings(raw, filename):
    for m in _JSON_BLOCK.finditer(raw):
        try:
            data = json.loads(m.group(1))
            if isinstance(data, list):
                return _normalize(data, filename)
            if isinstance(data, dict) and "vulnerabilities" in data:
                return _normalize(data["vulnerabilities"], filename)
        except json.JSONDecodeError:
            continue
    start, end = raw.find("["), raw.rfind("]")
    if start != -1 and end > start:
        try:
            data = json.loads(raw[start:end + 1])
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
        severity = str(item.get("severity", "high")).lower()
        if severity not in _SEVERITY_RANK:
            severity = "high"
        out.append({
            "title": str(item.get("title", "Untitled")),
            "description": str(item.get("description", item.get("details", ""))),
            "severity": severity,
            "type": str(item.get("type", item.get("vulnerability_type", ""))),
            "file": str(item.get("file", filename)),
            "function": str(item.get("function", item.get("function_name", ""))),
            "line": int(item.get("line", item.get("line_number", 0)) or 0),
            "confidence": float(item.get("confidence", 0.8)),
            "recommendation": str(item.get("recommendation", item.get("fix", ""))),
        })
    return out


def _scan_file(filepath, root, inference_api):
    try:
        source = filepath.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    rel = str(filepath.relative_to(root))
    findings = []
    chunks = [source[i:i + _MAX_CHUNK] for i in range(0, len(source), _MAX_CHUNK)]
    for chunk in chunks[:4]:
        prompt = _PROMPT.format(filename=rel, source=chunk)
        raw = _ask(inference_api, prompt)
        if raw:
            findings.extend(_parse_findings(raw, rel))
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


def agent_main(project_dir=None, inference_api=None):
    root = pathlib.Path(project_dir or ".").resolve()
    api = inference_api or os.environ.get("INFERENCE_API", "")
    sol_files = sorted(root.rglob("*.sol"))

    def _priority(p):
        name = p.name.lower()
        return 0 if any(k in name for k in _PRIORITY) else 1

    sol_files.sort(key=_priority)
    all_findings = []
    for sol in sol_files[:20]:
        all_findings.extend(_scan_file(sol, root, api))
    deduped = _dedup(all_findings)
    deduped.sort(key=lambda f: _SEVERITY_RANK.get(f.get("severity", "info"), 4))
    return {"vulnerabilities": deduped}
