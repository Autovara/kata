from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from typing import Any

from helpers.collect import SourceFile

ACCESS_MODIFIERS = (
    "onlyowner",
    "onlyrole",
    "onlyadmin",
    "auth",
    "restricted",
    "requiresauth",
    "whennotpaused",
    "nonreentrant",
)

SENSITIVE_KEYWORDS = (
    "withdraw",
    "redeem",
    "mint",
    "burn",
    "transfer",
    "approve",
    "setowner",
    "setadmin",
    "upgrade",
    "initialize",
    "delegate",
    "liquidat",
    "borrow",
    "repay",
    "claim",
    "execute",
    "swap",
    "bridge",
    "oracle",
    "price",
)

FUNCTION_RE = re.compile(
    r"(?m)^\s*function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)\s*([^{;]*)",
)
JSON_BLOCK_RE = re.compile(r"\{[\s\S]*\}|\[[\s\S]*\]")


def rank_sources(files: list[SourceFile]) -> list[SourceFile]:
    scored = [(score_source(item), item) for item in files]
    scored.sort(key=lambda pair: pair[0], reverse=True)
    return [item for _, item in scored]


def score_source(item: SourceFile) -> int:
    text = item.text.lower()
    score = len(item.text) // 500
    for keyword in SENSITIVE_KEYWORDS:
        score += text.count(keyword) * 3
    if "delegatecall" in text:
        score += 8
    if "tx.origin" in text:
        score += 10
    if ".call{" in text or ".call(" in text:
        score += 5
    if "unchecked" in text:
        score += 4
    if "selfdestruct" in text:
        score += 6
    return score


def static_findings(files: list[SourceFile]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for item in files:
        findings.extend(_scan_file(item))
    return findings


def _pack_finding(
    title: str,
    description: str,
    severity: str,
    file: str,
    line: int | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = dict(
        title=title,
        description=description,
        severity=severity,
        file=file,
    )
    if line is not None:
        payload["line"] = line
    return payload


def _scan_file(item: SourceFile) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    lines = item.text.splitlines()
    for index, line in enumerate(lines, start=1):
        compact = " ".join(line.strip().split())
        if not compact:
            continue
        low = compact.lower()
        if "tx.origin" in low:
            findings.append(
                _pack_finding(
                    title="tx.origin check in " + item.rel,
                    description=(
                        "Line "
                        + str(index)
                        + " in "
                        + item.rel
                        + " references tx.origin: "
                        + compact[:180]
                    ),
                    severity="high",
                    file=item.rel,
                    line=index,
                )
            )
        if "delegatecall" in low and "only" not in low:
            findings.append(
                _pack_finding(
                    title="delegatecall in " + item.rel,
                    description=(
                        "Line "
                        + str(index)
                        + " in "
                        + item.rel
                        + " uses delegatecall: "
                        + compact[:180]
                    ),
                    severity="critical",
                    file=item.rel,
                    line=index,
                )
            )
        if "selfdestruct" in low:
            findings.append(
                _pack_finding(
                    title="selfdestruct in " + item.rel,
                    description=(
                        "Line "
                        + str(index)
                        + " in "
                        + item.rel
                        + " references selfdestruct: "
                        + compact[:180]
                    ),
                    severity="high",
                    file=item.rel,
                    line=index,
                )
            )

    for match in FUNCTION_RE.finditer(item.text):
        name = match.group(1)
        modifiers = match.group(2).lower()
        if not any(keyword in name.lower() for keyword in SENSITIVE_KEYWORDS):
            continue
        if any(token in modifiers for token in ACCESS_MODIFIERS):
            continue
        if "view" in modifiers or "pure" in modifiers:
            continue
        if "internal" in modifiers or "private" in modifiers:
            continue
        line = item.text.count("\n", 0, match.start()) + 1
        signature = " ".join(match.group(0).strip().split())[:180]
        findings.append(
            _pack_finding(
                title="Sensitive function without guard: " + name,
                description=(
                    "Function `"
                    + name
                    + "` at line "
                    + str(line)
                    + " in "
                    + item.rel
                    + " may lack access control. Signature: "
                    + signature
                ),
                severity="high",
                file=item.rel,
                line=line,
            )
        )
    return findings


def build_audit_prompt(item: SourceFile) -> str:
    excerpt = item.text[:28_000]
    return (
        "You are auditing smart contract source for exploitable vulnerabilities.\n"
        "File: "
        + item.rel
        + "\n"
        "Return ONLY a JSON array. Each item must include title, description, severity, "
        "and file fields. Severity must be one of: critical, high, medium, low.\n"
        "Focus on concrete, exploitable issues grounded in the excerpt.\n\n"
        "```\n"
        + excerpt
        + "\n```"
    )


def parse_model_findings(raw: str | None, default_file: str) -> list[dict[str, Any]]:
    if not raw:
        return []
    match = JSON_BLOCK_RE.search(raw)
    if match is None:
        return []
    try:
        payload = json.loads(match.group(0))
    except json.JSONDecodeError:
        return []
    if isinstance(payload, dict):
        payload = payload.get("vulnerabilities") or payload.get("findings") or []
    if not isinstance(payload, list):
        return []
    findings: list[dict[str, Any]] = []
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        normalized = _normalize_entry(entry, default_file)
        if normalized is not None:
            findings.append(normalized)
    return findings


def merge_findings(*groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for group in groups:
        for item in group:
            key = (
                str(item.get("title", "")).strip().lower(),
                str(item.get("file", "")).strip().lower(),
                str(item.get("severity", "")).strip().lower(),
            )
            if not key[0] or key in seen:
                continue
            seen.add(key)
            merged.append(item)
    return merged[:12]


def _normalize_entry(entry: dict[str, Any], default_file: str) -> dict[str, Any] | None:
    title = str(entry.get("title") or entry.get("name") or "").strip()
    description = str(entry.get("description") or entry.get("detail") or "").strip()
    if not title or not description:
        return None
    severity = str(entry.get("severity") or "medium").strip().lower()
    if severity not in {"critical", "high", "medium", "low"}:
        severity = "medium"
    file_path = str(entry.get("file") or entry.get("path") or default_file).strip()
    if not file_path:
        file_path = default_file
    line = entry.get("line")
    finding = dict(
        title=title[:200],
        description=description[:2000],
        severity=severity,
        file=file_path,
    )
    if isinstance(line, int) and line > 0:
        finding["line"] = line
    return finding
