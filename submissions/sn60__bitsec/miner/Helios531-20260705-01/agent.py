from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path

CONTRACT_SUFFIXES = (".sol", ".vy", ".rs", ".move", ".cairo", ".fe")
EXCLUDED_DIR_NAMES = {
    "test",
    "tests",
    "mock",
    "mocks",
    "example",
    "examples",
    "script",
    "scripts",
    "broadcast",
    "node_modules",
    "vendor",
    "vendors",
}
SUSPICIOUS_NAME_TERMS = (
    "admin",
    "owner",
    "vault",
    "router",
    "bridge",
    "proxy",
    "upgrade",
    "oracle",
    "govern",
    "treasury",
    "manager",
    "pool",
    "reward",
    "staking",
    "market",
    "reserve",
)
SUSPICIOUS_CONTENT_PATTERNS = (
    r"\bdelegatecall\b",
    r"\bcall\s*\{",
    r"\bcall\.value\b",
    r"\bselfdestruct\b",
    r"\btx\.origin\b",
    r"\bassembly\b",
    r"\becrecover\b",
    r"\bpermit\b",
    r"\bonlyOwner\b",
    r"\bonlyAdmin\b",
    r"\bonlyRole\b",
    r"\bupgradeTo\b",
    r"\bsetImplementation\b",
    r"\bwithdraw\b",
    r"\bredeem\b",
    r"\bliquidate\b",
    r"\bborrow\b",
    r"\brepay\b",
    r"\bmint\b",
    r"\bburn\b",
    r"\btransferFrom\b",
    r"\bapprove\b",
    r"\bunchecked\b",
    r"\breentran",
    r"\bflash",
    r"\boracle\b",
    r"\bnonce\b",
    r"\bsignature\b",
    r"\bfee\b",
    r"\bprice\b",
)
FUNCTION_START_PATTERN = re.compile(
    r"^\s*(?:function|fn|pub\s+fn|entry\s+fun|public\s+entry\s+fun)\b",
    re.IGNORECASE,
)
IMPORT_PATTERN = re.compile(
    r'^\s*import\s+(?:"([^"]+)"|\'([^\']+)\')',
    re.IGNORECASE | re.MULTILINE,
)
CONTRACT_NAME_PATTERN = re.compile(
    r"\b(?:contract|library|interface|struct|enum|trait|module)\s+([A-Za-z_][A-Za-z0-9_]*)"
)
INHERITANCE_PATTERN = re.compile(r"\bis\s+([A-Za-z0-9_,\s]+)")
TOP_FILE_COUNT = 24
TOP_TARGET_FILES = 14
TOP_SNIPPETS_PER_FILE = 2
TOP_VALIDATION_CANDIDATES = 8
SECONDARY_SWEEP_FILES = 8
MAX_FILE_BYTES = 220_000
MAX_EXCERPT_CHARS = 2_100
MAX_FOCUSED_CONTEXT_CHARS = 7_000
MAX_PRIMARY_PROMPT_CHARS = 25_000
MAX_VALIDATION_PROMPT_CHARS = 26_000
MAX_SECONDARY_PROMPT_CHARS = 24_000
MAX_AGENT_RUNTIME_SECONDS = 210
REQUEST_TIMEOUT_SECONDS = 90
MAX_RETRIES = 2
FOCUS_PROFILES = {
    "access-control": (
        "Focus on missing or bypassable authorization, unsafe role changes, privileged "
        "configuration updates, ownership transfer flaws, and trust boundary mistakes."
    ),
    "reentrancy-external-call": (
        "Focus on reentrancy, unsafe low-level calls, checks-effects-interactions "
        "violations, callbacks before accounting updates, and user-controlled execution."
    ),
    "upgradeability": (
        "Focus on proxy safety, implementation control, upgrade authorization, "
        "initializer misuse, delegatecall hazards, and storage-trust assumptions."
    ),
    "oracle-accounting": (
        "Focus on price/oracle trust, stale or manipulable price reads, rounding and "
        "share-accounting bugs, insolvency, reserve drift, and incorrect asset math."
    ),
    "signature-permit": (
        "Focus on permit flows, nonce misuse, replay, domain separator errors, "
        "signature malleability, unchecked signer assumptions, and auth-by-signature bugs."
    ),
    "generic-high-impact": (
        "Focus on real high-impact bugs causing fund loss, privilege escalation, "
        "denial of service, liquidation abuse, or protocol manipulation."
    ),
}


def _discover_contract_files(project_root: Path) -> list[Path]:
    files: set[Path] = set()
    for path in project_root.rglob("*"):
        if not path.is_file():
            continue
        if any(part.lower() in EXCLUDED_DIR_NAMES for part in path.parts):
            continue
        if path.suffix.lower() not in CONTRACT_SUFFIXES:
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        files.add(path)
    return sorted(files)


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _score_file(path: Path, content: str) -> int:
    score = 0
    lower_name = path.name.lower()
    lower_path = path.as_posix().lower()
    for term in SUSPICIOUS_NAME_TERMS:
        if term in lower_name:
            score += 8
        elif term in lower_path:
            score += 3
    for pattern in SUSPICIOUS_CONTENT_PATTERNS:
        matches = len(re.findall(pattern, content, flags=re.IGNORECASE))
        score += min(matches, 5) * 4
    if "contract " in content or "module " in content:
        score += 2
    if "function " in content or "fn " in content:
        score += 2
    if "modifier " in content:
        score += 2
    return score


def _build_file_record(project_root: Path, path: Path) -> dict[str, object] | None:
    content = _read_text(path)
    if not content.strip():
        return None
    relative_path = str(path.relative_to(project_root))
    return {
        "path": path,
        "relative_path": relative_path,
        "content": content,
        "score": _score_file(path, content),
        "contract_names": set(CONTRACT_NAME_PATTERN.findall(content)),
    }


def _record_focuses(record: dict[str, object]) -> list[str]:
    content = str(record["content"]).lower()
    relative_path = str(record["relative_path"]).lower()
    focuses: list[str] = []

    if any(token in content or token in relative_path for token in ("owner", "admin", "role", "govern", "treasury")):
        focuses.append("access-control")
    if any(token in content for token in ("delegatecall", "upgrade", "implementation", "proxy")) or "proxy" in relative_path:
        focuses.append("upgradeability")
    if any(token in content for token in ("call{", "call.value", "delegatecall", "withdraw", "redeem", "flash", "reentran")):
        focuses.append("reentrancy-external-call")
    if any(token in content or token in relative_path for token in ("oracle", "price", "reserve", "pool", "market", "borrow", "liquidate", "redeem")):
        focuses.append("oracle-accounting")
    if any(token in content for token in ("permit", "signature", "nonce", "ecrecover")):
        focuses.append("signature-permit")
    focuses.append("generic-high-impact")

    ordered: list[str] = []
    seen: set[str] = set()
    for focus in focuses:
        if focus in seen:
            continue
        ordered.append(focus)
        seen.add(focus)
    return ordered[:2]


def _shared_terms(path_value: str) -> set[str]:
    parts = re.split(r"[^a-z0-9]+", path_value.lower())
    return {part for part in parts if len(part) >= 4}


def _build_file_records(project_root: Path) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for path in _discover_contract_files(project_root):
        record = _build_file_record(project_root, path)
        if record is not None:
            records.append(record)
    records.sort(
        key=lambda item: (
            -int(item["score"]),
            len(str(item["content"])),
            str(item["relative_path"]),
        )
    )
    return records[:TOP_FILE_COUNT]


def _render_lines(lines: list[str], start_index: int, end_index: int) -> str:
    rendered: list[str] = []
    for index in range(start_index, end_index):
        rendered.append(f"{index + 1}: {lines[index]}")
    return "\n".join(rendered)


def _interesting_ranges(lines: list[str]) -> list[tuple[int, int, int]]:
    ranges: list[tuple[int, int, int]] = []
    for index, line in enumerate(lines):
        lowered = line.lower()
        line_score = 0
        if FUNCTION_START_PATTERN.search(line):
            line_score += 4
        for term in SUSPICIOUS_NAME_TERMS:
            if term in lowered:
                line_score += 3
        for pattern in SUSPICIOUS_CONTENT_PATTERNS:
            if re.search(pattern, line, flags=re.IGNORECASE):
                line_score += 5
        if line_score == 0:
            continue
        start = max(index - 8, 0)
        end = min(index + 14, len(lines))
        ranges.append((start, end, line_score))
    return ranges


def _merge_ranges(ranges: list[tuple[int, int, int]]) -> list[tuple[int, int, int]]:
    merged: list[tuple[int, int, int]] = []
    for start, end, score in sorted(ranges):
        if not merged or start > merged[-1][1] + 2:
            merged.append((start, end, score))
            continue
        prev_start, prev_end, prev_score = merged[-1]
        merged[-1] = (prev_start, max(prev_end, end), prev_score + score)
    return merged


def _clip_text(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit]


def _with_line_numbers(content: str) -> str:
    lines = content.splitlines()
    return "\n".join(f"{index + 1}: {line}" for index, line in enumerate(lines))


def _collect_snippet_blocks(record: dict[str, object]) -> list[dict[str, object]]:
    content = str(record["content"])
    relative_path = str(record["relative_path"])
    base_score = int(record["score"])
    lines = content.splitlines()
    if not lines:
        return []

    ranges = _merge_ranges(_interesting_ranges(lines))
    if not ranges:
        return [
            {
                "file_path": relative_path,
                "start_line": 1,
                "end_line": min(len(lines), 120),
                "score": max(base_score, 1),
                "text": _clip_text(_with_line_numbers(content), MAX_EXCERPT_CHARS),
            }
        ]

    snippets: list[dict[str, object]] = []
    for start, end, score in ranges[:TOP_SNIPPETS_PER_FILE]:
        text = _render_lines(lines, start, end)
        snippets.append(
            {
                "file_path": relative_path,
                "start_line": start + 1,
                "end_line": end,
                "score": base_score + score,
                "text": _clip_text(text, MAX_EXCERPT_CHARS),
            }
        )
    snippets.sort(
        key=lambda item: (
            -int(item["score"]),
            str(item["file_path"]),
            int(item["start_line"]),
        )
    )
    return snippets


def _select_target_records(records: list[dict[str, object]]) -> list[dict[str, object]]:
    return records[:TOP_TARGET_FILES]


def _select_related_records(
    project_root: Path,
    target: dict[str, object],
    records_by_path: dict[str, dict[str, object]],
    records: list[dict[str, object]],
) -> list[dict[str, object]]:
    related: list[dict[str, object]] = []
    seen: set[str] = {str(target["relative_path"])}
    path = Path(str(target["path"]))
    content = str(target["content"])

    for match in IMPORT_PATTERN.finditer(content):
        import_path = match.group(1) or match.group(2) or ""
        if not import_path.startswith("."):
            continue
        resolved = (path.parent / import_path).resolve()
        try:
            relative = str(resolved.relative_to(project_root))
        except ValueError:
            continue
        candidate = records_by_path.get(relative)
        if candidate is None or relative in seen:
            continue
        related.append(candidate)
        seen.add(relative)
        if len(related) >= 2:
            return related

    inherited_names: set[str] = set()
    for match in INHERITANCE_PATTERN.finditer(content):
        for part in match.group(1).split(","):
            name = part.strip().split()[-1] if part.strip() else ""
            if name:
                inherited_names.add(name)
    for record in records:
        relative = str(record["relative_path"])
        if relative in seen:
            continue
        names = record.get("contract_names")
        if isinstance(names, set) and names.intersection(inherited_names):
            related.append(record)
            seen.add(relative)
            if len(related) >= 2:
                return related

    target_path_lower = str(target["relative_path"]).lower()
    for record in records:
        relative = str(record["relative_path"])
        if relative in seen:
            continue
        if any(term in target_path_lower and term in relative.lower() for term in SUSPICIOUS_NAME_TERMS):
            related.append(record)
            seen.add(relative)
            if len(related) >= 2:
                return related

    target_terms = _shared_terms(target_path_lower)
    for record in records:
        relative = str(record["relative_path"])
        if relative in seen:
            continue
        overlap = target_terms.intersection(_shared_terms(relative))
        if overlap:
            related.append(record)
            seen.add(relative)
            if len(related) >= 2:
                return related
    return related


def _build_generation_prompt(
    target: dict[str, object],
    target_snippets: list[dict[str, object]],
    related_records: list[dict[str, object]],
    focus: str,
) -> str:
    sections = [
        "You are auditing one target smart-contract file for real exploitable vulnerabilities.",
        "Return only real high-confidence high or critical issues.",
        "Ignore style, gas, missing events, weak naming, or speculative concerns without a concrete exploit path.",
        (
            "Return strict JSON with shape "
            "{\"candidates\": [{\"title\": ..., \"description\": ..., \"severity\": ..., "
            "\"file\": ..., \"location\": ..., \"vulnerability_type\": ..., "
            "\"confidence\": ..., \"recommendation\": ..., \"evidence\": ...}]}"
        ),
        "Return at most 2 candidates. If there is nothing real, return {\"candidates\": []}.",
        f"Target file: {target['relative_path']}",
        f"Audit focus: {focus}",
        FOCUS_PROFILES[focus],
    ]
    for snippet in target_snippets:
        sections.append(
            "\n\n### Target snippet "
            f"{snippet['file_path']}:{snippet['start_line']}-{snippet['end_line']}\n"
            f"```text\n{snippet['text']}\n```"
        )
    for related in related_records:
        excerpt = _clip_text(_with_line_numbers(str(related["content"])), MAX_EXCERPT_CHARS)
        sections.append(
            f"\n\n### Related file {related['relative_path']}\n"
            f"```text\n{excerpt}\n```"
        )
    return _clip_text("\n".join(sections), MAX_PRIMARY_PROMPT_CHARS)


def _build_secondary_sweep_prompt(records: list[dict[str, object]]) -> str:
    sections = [
        "You are auditing a batch of suspicious smart-contract files for overlooked real exploitable vulnerabilities.",
        "Focus on high-confidence high or critical issues only.",
        "Prefer findings involving access control failure, unsafe upgrades, reentrancy, oracle/accounting abuse, or signature misuse.",
        (
            "Return strict JSON with shape "
            "{\"candidates\": [{\"title\": ..., \"description\": ..., \"severity\": ..., "
            "\"file\": ..., \"location\": ..., \"vulnerability_type\": ..., "
            "\"confidence\": ..., \"recommendation\": ..., \"evidence\": ...}]}"
        ),
        "Return at most 4 candidates total. If nothing real is visible, return {\"candidates\": []}.",
    ]
    remaining = MAX_SECONDARY_PROMPT_CHARS - sum(len(section) for section in sections) - 500
    for record in records:
        snippets = _collect_snippet_blocks(record)
        if not snippets:
            continue
        joined = []
        for snippet in snippets[:2]:
            joined.append(
                f"{snippet['file_path']}:{snippet['start_line']}-{snippet['end_line']}\n"
                f"```text\n{snippet['text']}\n```"
            )
        block = "\n\n### Suspicious file " + str(record["relative_path"]) + "\n" + "\n\n".join(joined)
        if len(block) > remaining:
            break
        sections.append(block)
        remaining -= len(block)
    return "\n".join(sections)


def _post_inference(inference_api: str | None, messages: list[dict[str, str]]) -> dict:
    endpoint = (inference_api or os.environ.get("INFERENCE_API") or "").rstrip("/")
    if not endpoint:
        raise ValueError("INFERENCE_API is not configured.")
    api_key = os.environ.get("INFERENCE_API_KEY", "").strip()
    if not api_key:
        raise ValueError("INFERENCE_API_KEY is not configured.")

    payload = {
        "messages": messages,
        "response_format": {"type": "json_object"},
        "max_tokens": 4000,
    }
    body = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "x-inference-api-key": api_key,
    }

    last_error: Exception | None = None
    for attempt in range(MAX_RETRIES + 1):
        request = urllib.request.Request(
            endpoint + "/inference",
            data=body,
            method="POST",
            headers=headers,
        )
        try:
            with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
                return json.loads(response.read().decode("utf-8"))
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, ValueError) as exc:
            last_error = exc
            if attempt >= MAX_RETRIES:
                break
            time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"inference request failed: {last_error}")


def _extract_content(payload: dict) -> str:
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        return ""
    message = choices[0].get("message")
    if not isinstance(message, dict):
        return ""
    content = message.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        text_parts: list[str] = []
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                text = item.get("text")
                if isinstance(text, str):
                    text_parts.append(text)
        return "".join(text_parts)
    return ""


def _clean_json_text(content: str) -> dict:
    text = content.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if lines:
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    if text.startswith("return"):
        text = text[6:].strip()
    return json.loads(text)


def _parse_response_list(content: str, key: str) -> list[dict[str, object]]:
    try:
        payload = _clean_json_text(content)
    except Exception:
        return []
    if not isinstance(payload, dict):
        return []
    value = payload.get(key)
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _safe_confidence(value: object) -> float:
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return 0.6
    if numeric < 0:
        return 0.0
    if numeric > 1:
        return 1.0
    return numeric


def _normalize_location(raw_location: str) -> str:
    location = raw_location.strip()
    if not location:
        return ""
    return re.sub(r"\s+", " ", location)


def _normalize_candidate(
    candidate: dict[str, object],
    *,
    default_file: str,
    source_score: int,
) -> dict[str, object] | None:
    severity = str(candidate.get("severity") or "").strip().lower()
    if severity not in {"high", "critical"}:
        return None
    title = str(candidate.get("title") or "").strip()
    description = str(candidate.get("description") or "").strip()
    file_path = str(candidate.get("file") or default_file).strip() or default_file
    location = _normalize_location(str(candidate.get("location") or "").strip())
    vuln_type = str(candidate.get("vulnerability_type") or "smart-contract").strip()
    recommendation = str(candidate.get("recommendation") or "").strip()
    evidence = str(candidate.get("evidence") or "").strip()
    if not title or len(description) < 60:
        return None
    return {
        "title": title,
        "description": description,
        "severity": severity,
        "file": file_path,
        "location": location or file_path,
        "vulnerability_type": vuln_type,
        "confidence": _safe_confidence(candidate.get("confidence")),
        "recommendation": recommendation,
        "evidence": evidence,
        "_source_score": source_score,
    }


def _candidate_rank(candidate: dict[str, object]) -> tuple[float, float]:
    severity_bonus = 1.0 if candidate.get("severity") == "critical" else 0.0
    confidence = float(candidate.get("confidence") or 0.0)
    source_score = float(candidate.get("_source_score") or 0.0)
    evidence_bonus = 0.05 if str(candidate.get("evidence") or "").strip() else 0.0
    return (severity_bonus + confidence + evidence_bonus, source_score)


def _candidate_key(candidate: dict[str, object]) -> tuple[str, str, str]:
    file_path = str(candidate.get("file") or "").lower()
    vuln_type = re.sub(r"[^a-z0-9]+", "", str(candidate.get("vulnerability_type") or "").lower())
    location = re.sub(r"[^a-z0-9]+", " ", str(candidate.get("location") or "").lower()).strip()
    if not location:
        location = re.sub(r"[^a-z0-9]+", " ", str(candidate.get("title") or "").lower()).strip()
    return (file_path, vuln_type, location)


def _dedupe_candidates(candidates: list[dict[str, object]]) -> list[dict[str, object]]:
    ranked = sorted(candidates, key=_candidate_rank, reverse=True)
    deduped: list[dict[str, object]] = []
    seen: set[tuple[str, str, str]] = set()
    for candidate in ranked:
        key = _candidate_key(candidate)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(candidate)
    return deduped


def _hint_tokens(candidate: dict[str, object]) -> list[str]:
    source = " ".join(
        [
            str(candidate.get("title") or ""),
            str(candidate.get("location") or ""),
            str(candidate.get("vulnerability_type") or ""),
            str(candidate.get("evidence") or ""),
        ]
    )
    tokens = []
    for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]{3,}", source):
        lower = token.lower()
        if lower not in {"this", "that", "with", "from", "into", "high", "critical"}:
            tokens.append(lower)
    return tokens[:8]


def _focused_excerpt(content: str, hints: list[str], limit: int) -> str:
    lines = content.splitlines()
    if not lines:
        return ""
    if len(content) <= limit:
        return _with_line_numbers(content)

    matches: list[int] = []
    for index, line in enumerate(lines):
        lowered = line.lower()
        if any(hint in lowered for hint in hints):
            matches.append(index)
            continue
        if FUNCTION_START_PATTERN.search(line):
            matches.append(index)
            continue
        if any(re.search(pattern, line, flags=re.IGNORECASE) for pattern in SUSPICIOUS_CONTENT_PATTERNS):
            matches.append(index)

    if not matches:
        return _clip_text(_with_line_numbers(content), limit)

    chunks: list[str] = []
    for index in matches[:10]:
        start = max(index - 8, 0)
        end = min(index + 14, len(lines))
        chunks.append(_render_lines(lines, start, end))
        combined = "\n\n...\n\n".join(chunks)
        if len(combined) >= limit:
            return combined[:limit]
    return "\n\n...\n\n".join(chunks)[:limit]


def _build_validation_prompt(
    candidates: list[dict[str, object]],
    records_by_path: dict[str, dict[str, object]],
    project_root: Path,
) -> str:
    sections = [
        "Validate the following smart-contract vulnerability candidates.",
        "Keep only findings that are likely real exploitable high or critical issues.",
        "Reject speculative, duplicate, or weak claims.",
        (
            "Return strict JSON with shape "
            "{\"vulnerabilities\": [{\"title\": ..., \"description\": ..., \"severity\": ..., "
            "\"file\": ..., \"location\": ..., \"vulnerability_type\": ..., "
            "\"confidence\": ..., \"recommendation\": ...}]}"
        ),
        "If none survive validation, return {\"vulnerabilities\": []}.",
    ]
    remaining = MAX_VALIDATION_PROMPT_CHARS - sum(len(section) for section in sections) - 500

    for index, candidate in enumerate(candidates, start=1):
        file_path = str(candidate.get("file") or "")
        record = records_by_path.get(file_path)
        if record is None:
            continue
        hints = _hint_tokens(candidate)
        primary_context = _focused_excerpt(str(record["content"]), hints, MAX_FOCUSED_CONTEXT_CHARS)
        related_records = _select_related_records(project_root, record, records_by_path, list(records_by_path.values()))
        related_blocks: list[str] = []
        for related in related_records[:1]:
            excerpt = _focused_excerpt(str(related["content"]), hints, MAX_FOCUSED_CONTEXT_CHARS // 2)
            related_blocks.append(
                f"Related file: {related['relative_path']}\n```text\n{excerpt}\n```"
            )

        block = (
            f"\n\n### Candidate {index}\n"
            f"Proposed finding:\n{json.dumps(candidate, ensure_ascii=True, indent=2)}\n\n"
            f"Primary file: {record['relative_path']}\n```text\n{primary_context}\n```\n\n"
            + "\n\n".join(related_blocks)
        )
        if len(block) > remaining:
            break
        sections.append(block)
        remaining -= len(block)
    return "\n".join(sections)


def _strip_internal_fields(candidate: dict[str, object]) -> dict[str, object]:
    return {
        "title": str(candidate.get("title") or "").strip(),
        "description": str(candidate.get("description") or "").strip(),
        "severity": str(candidate.get("severity") or "").strip().lower(),
        "file": str(candidate.get("file") or "").strip(),
        "location": str(candidate.get("location") or "").strip(),
        "vulnerability_type": str(candidate.get("vulnerability_type") or "").strip(),
        "confidence": _safe_confidence(candidate.get("confidence")),
        "recommendation": str(candidate.get("recommendation") or "").strip(),
    }


def agent_main(
    project_dir: str | None = None,
    inference_api: str | None = None,
) -> dict:
    findings: list[dict[str, object]] = []
    project_root = Path(project_dir or "/app/project_code").expanduser().resolve()
    if not project_root.exists() or not project_root.is_dir():
        return {"vulnerabilities": findings}

    deadline = time.monotonic() + MAX_AGENT_RUNTIME_SECONDS
    records = _build_file_records(project_root)
    if not records:
        return {"vulnerabilities": findings}

    records_by_path = {
        str(record["relative_path"]): record
        for record in records
    }
    targets = _select_target_records(records)
    target_paths = {str(record["relative_path"]) for record in targets}
    all_candidates: list[dict[str, object]] = []

    try:
        for target in targets:
            if time.monotonic() >= deadline - 40:
                break
            target_snippets = _collect_snippet_blocks(target)
            related_records = _select_related_records(project_root, target, records_by_path, records)
            for focus in _record_focuses(target):
                if time.monotonic() >= deadline - 30:
                    break
                prompt = _build_generation_prompt(target, target_snippets, related_records, focus)
                response = _post_inference(
                    inference_api,
                    [
                        {
                            "role": "system",
                            "content": "You are a senior smart contract security auditor. Return only strict JSON.",
                        },
                        {"role": "user", "content": prompt},
                    ],
                )
                raw_candidates = _parse_response_list(_extract_content(response), "candidates")
                for raw_candidate in raw_candidates:
                    normalized = _normalize_candidate(
                        raw_candidate,
                        default_file=str(target["relative_path"]),
                        source_score=int(target["score"]),
                    )
                    if normalized is not None:
                        all_candidates.append(normalized)

        all_candidates = _dedupe_candidates(all_candidates)
        if time.monotonic() < deadline - 25:
            secondary_records = [
                record
                for record in records
                if str(record["relative_path"]) not in target_paths
            ][:SECONDARY_SWEEP_FILES]
            if secondary_records:
                secondary_prompt = _build_secondary_sweep_prompt(secondary_records)
                secondary_response = _post_inference(
                    inference_api,
                    [
                        {
                            "role": "system",
                            "content": "You are a senior smart contract security auditor. Return only strict JSON.",
                        },
                        {"role": "user", "content": secondary_prompt},
                    ],
                )
                raw_secondary = _parse_response_list(_extract_content(secondary_response), "candidates")
                for raw_candidate in raw_secondary:
                    file_hint = str(raw_candidate.get("file") or "")
                    record = records_by_path.get(file_hint)
                    source_score = int(record["score"]) if record is not None else 0
                    normalized = _normalize_candidate(
                        raw_candidate,
                        default_file=file_hint,
                        source_score=source_score,
                    )
                    if normalized is not None:
                        all_candidates.append(normalized)
                all_candidates = _dedupe_candidates(all_candidates)
        if not all_candidates:
            return {"vulnerabilities": findings}

        validation_input = all_candidates[:TOP_VALIDATION_CANDIDATES]
        if time.monotonic() < deadline - 15:
            validation_prompt = _build_validation_prompt(
                validation_input,
                records_by_path,
                project_root,
            )
            validation_response = _post_inference(
                inference_api,
                [
                    {
                        "role": "system",
                        "content": "You are a strict smart contract vulnerability triage reviewer. Return only strict JSON.",
                    },
                    {"role": "user", "content": validation_prompt},
                ],
            )
            raw_findings = _parse_response_list(_extract_content(validation_response), "vulnerabilities")
            validated: list[dict[str, object]] = []
            for raw_finding in raw_findings:
                normalized = _normalize_candidate(
                    raw_finding,
                    default_file=str(raw_finding.get("file") or ""),
                    source_score=0,
                )
                if normalized is not None:
                    validated.append(normalized)
            validated = _dedupe_candidates(validated)
            if validated:
                findings = [_strip_internal_fields(candidate) for candidate in validated[:5]]
                return {"vulnerabilities": findings}

        fallback = all_candidates[:3]
        findings = [_strip_internal_fields(candidate) for candidate in fallback]
    except Exception:
        findings = []

    return {"vulnerabilities": findings}
