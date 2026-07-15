"""Source-driven SN60 security-audit agent.

The agent ranks security-relevant source files, asks the miner-funded model to
audit each selected file, and returns only structured high-impact findings.
It contains no project-specific reports or embedded credentials.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from pathlib import Path


# This model identifier is sent to the miner-selected AkashML provider. It is
# miner-controlled agent configuration, not a validator policy.
MODEL = "zai-org/GLM-5.2"
MAX_TARGETS = 4
MAX_FILE_CHARS = 14_000
SOURCE_SUFFIXES = {".sol", ".vy", ".rs", ".cairo", ".move"}
RISK_MARKERS = (
    "delegatecall",
    "call{",
    "assembly",
    "transfer",
    "withdraw",
    "mint",
    "burn",
    "upgrade",
    "initialize",
    "signature",
    "permit",
    "nonce",
    "owner",
    "role",
    "oracle",
    "price",
    "liquidat",
    "swap",
)


def _project_root(project_dir: str | None) -> Path | None:
    for raw_path in (project_dir, os.environ.get("PROJECT_DIR"), "/app/project_code", "."):
        if raw_path and Path(raw_path).is_dir():
            return Path(raw_path).resolve()
    return None


def _source_files(root: Path) -> list[tuple[str, str]]:
    candidates: list[tuple[int, str, str]] = []
    ignored_parts = {".git", "node_modules", "vendor", "target", "lib", "test", "tests"}

    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        if any(part.lower() in ignored_parts for part in path.relative_to(root).parts):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if not text.strip():
            continue
        relative_path = path.relative_to(root).as_posix()
        lowered = text.lower()
        score = sum(lowered.count(marker) for marker in RISK_MARKERS)
        score += 3 if path.name.lower().startswith(("vault", "pool", "router", "manager")) else 0
        candidates.append((score, relative_path, text[:MAX_FILE_CHARS]))

    candidates.sort(key=lambda item: (-item[0], item[1]))
    return [(relative_path, text) for _, relative_path, text in candidates[:MAX_TARGETS]]


def _request_model(inference_api: str | None, prompt: str) -> str:
    endpoint = (inference_api or os.environ.get("INFERENCE_API") or "").rstrip("/")
    api_key = os.environ.get("INFERENCE_API_KEY", "")
    if not endpoint or not api_key:
        return ""

    body = json.dumps(
        {
            "model": MODEL,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a careful smart-contract security auditor. Analyze only the "
                        "provided source. Do not speculate or invent issues."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.1,
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        endpoint + "/inference",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "x-inference-api-key": api_key,
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=140) as response:
            payload = json.loads(response.read().decode("utf-8", "replace"))
        return str(payload["choices"][0]["message"]["content"])
    except (
        urllib.error.HTTPError,
        urllib.error.URLError,
        KeyError,
        IndexError,
        OSError,
        TypeError,
        ValueError,
    ):
        return ""


def _json_array(content: str) -> list[object]:
    fenced = re.search(r"```(?:json)?\s*(\[.*?\])\s*```", content, re.DOTALL)
    candidate = fenced.group(1) if fenced else content.strip()
    if not candidate.startswith("["):
        bracketed = re.search(r"\[.*\]", candidate, re.DOTALL)
        candidate = bracketed.group(0) if bracketed else ""
    try:
        parsed = json.loads(candidate)
    except (TypeError, ValueError):
        return []
    return parsed if isinstance(parsed, list) else []


def _normalize_findings(content: str, source_file: str, source: str) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    source_line_count = source.count("\n") + 1

    for item in _json_array(content):
        if not isinstance(item, dict):
            continue
        severity = str(item.get("severity") or "").strip().lower()
        title = str(item.get("title") or "").strip()
        description = str(item.get("description") or "").strip()
        if severity not in {"high", "critical"} or not title or len(description) < 80:
            continue
        try:
            line = int(item.get("line") or 0)
        except (TypeError, ValueError):
            line = 0
        if line < 1 or line > source_line_count:
            line = 0
        findings.append(
            {
                "title": title[:220],
                "severity": severity,
                "file": source_file,
                "line": line,
                "description": description[:1800],
            }
        )
    return findings


def _audit_file(inference_api: str | None, source_file: str, source: str) -> list[dict[str, object]]:
    prompt = (
        "Audit the following source file for exploitable security issues. Focus on "
        "authorization, state transitions, accounting, external calls, signatures, "
        "upgradeability, and asset movement. Return only a JSON array. Each item must "
        "have title, severity, line, and description. Include only high or critical "
        "issues with concrete code evidence.\n\n"
        f"FILE: {source_file}\n"
        f"```\n{source}\n```"
    )
    return _normalize_findings(_request_model(inference_api, prompt), source_file, source)


def _deduplicate(findings: list[dict[str, object]]) -> list[dict[str, object]]:
    unique: list[dict[str, object]] = []
    seen: set[tuple[str, str, int]] = set()
    for finding in findings:
        key = (
            str(finding["file"]),
            str(finding["title"]).lower(),
            int(finding.get("line") or 0),
        )
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return unique


def agent_main(project_dir: str | None = None, inference_api: str | None = None) -> dict:
    root = _project_root(project_dir)
    findings: list[dict[str, object]] = []
    if root is not None:
        for source_file, source in _source_files(root):
            findings.extend(_audit_file(inference_api, source_file, source))
    return {"vulnerabilities": _deduplicate(findings)}
