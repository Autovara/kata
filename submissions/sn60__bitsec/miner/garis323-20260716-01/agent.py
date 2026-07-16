"""Source-grounded Solidity security auditor for the SN60 miner runtime.

The agent inspects the mounted project, asks the miner-funded model to audit two
independent source batches, then asks it to verify the candidate findings against
the original source.  It has no project-specific branches or stored findings.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


MODEL = os.environ.get("KATA_MINER_MODEL", "zai-org/GLM-5.2")
MAX_FILES = 12
MAX_FILE_CHARS = 9_000
MAX_PROMPT_CHARS = 54_000
MAX_FINDINGS = 6
REQUEST_TIMEOUT_SECONDS = 195

RISK_TERMS = (
    "delegatecall",
    "call{",
    ".call(",
    "transfer",
    "withdraw",
    "deposit",
    "borrow",
    "repay",
    "liquidat",
    "flash",
    "swap",
    "mint",
    "burn",
    "upgrade",
    "initialize",
    "owner",
    "only",
    "oracle",
    "price",
    "share",
    "balance",
    "permit",
    "signature",
)
SKIP_DIRECTORIES = {
    ".git",
    "node_modules",
    "test",
    "tests",
    "script",
    "scripts",
    "mocks",
    "mock",
    "vendor",
}


def _project_root(project_dir: str | None) -> Path | None:
    for candidate in (project_dir, os.environ.get("PROJECT_DIR"), "/app/project_code", "."):
        if candidate:
            path = Path(candidate)
            if path.is_dir():
                return path.resolve()
    return None


def _is_project_source(path: Path) -> bool:
    return path.is_file() and path.suffix == ".sol" and not any(
        part.lower() in SKIP_DIRECTORIES for part in path.parts
    )


def _risk_score(relative_path: str, source: str) -> int:
    lowered = source.lower()
    score = sum(lowered.count(term) for term in RISK_TERMS)
    path = relative_path.lower()
    if path.startswith(("src/", "contracts/")):
        score += 8
    if any(term in path for term in ("vault", "pool", "manager", "router", "oracle", "token")):
        score += 5
    if "interface" in path:
        score -= 4
    return score


def _collect_sources(root: Path) -> list[dict[str, Any]]:
    sources: list[dict[str, Any]] = []
    for path in root.rglob("*.sol"):
        if not _is_project_source(path):
            continue
        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if not source.strip():
            continue
        relative_path = path.relative_to(root).as_posix()
        sources.append(
            {
                "file": relative_path,
                "source": source,
                "lines": source.count("\n") + 1,
                "score": _risk_score(relative_path, source),
            }
        )
    return sorted(sources, key=lambda item: (-int(item["score"]), str(item["file"])))[:MAX_FILES]


def _source_excerpt(source: str) -> str:
    if len(source) <= MAX_FILE_CHARS:
        return source
    head_chars = MAX_FILE_CHARS * 2 // 3
    tail_chars = MAX_FILE_CHARS - head_chars
    head = source[:head_chars]
    tail = source[-tail_chars:]
    omitted = source[head_chars:-tail_chars].count("\n") + 1
    return f"{head}\n\n/* ... {omitted} source lines omitted ... */\n\n{tail}"


def _render_sources(sources: list[dict[str, Any]], limit: int = MAX_PROMPT_CHARS) -> str:
    sections: list[str] = []
    used = 0
    for item in sources:
        section = (
            f"\n===== FILE: {item['file']} =====\n"
            f"{_source_excerpt(str(item['source']))}\n"
        )
        if sections and used + len(section) > limit:
            break
        sections.append(section)
        used += len(section)
    return "".join(sections)


def _inference_endpoint(inference_api: str | None) -> str:
    return (inference_api or os.environ.get("INFERENCE_API") or "").rstrip("/")


def _decode_response_text(payload: object) -> str:
    if not isinstance(payload, dict):
        return ""
    try:
        content = payload["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        return ""
    return content if isinstance(content, str) else ""


def _first_json_value(text: str) -> object | None:
    decoder = json.JSONDecoder()
    for match in re.finditer(r"[\[{]", text):
        try:
            value, _ = decoder.raw_decode(text[match.start() :])
        except json.JSONDecodeError:
            continue
        return value
    return None


def _ask_model(inference_api: str | None, prompt: str, max_tokens: int) -> object | None:
    endpoint = _inference_endpoint(inference_api)
    api_key = os.environ.get("INFERENCE_API_KEY", "")
    if not endpoint or not api_key:
        return None
    body = json.dumps(
        {
            "model": MODEL,
            "temperature": 0.1,
            "max_tokens": max_tokens,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a careful smart-contract security reviewer. Only report vulnerabilities "
                        "that the supplied source proves are exploitable. Do not use audit-report memory, "
                        "project names, or unsupported assumptions. Return valid JSON only."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
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
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            return _first_json_value(_decode_response_text(json.loads(response.read().decode("utf-8"))))
    except (
        urllib.error.HTTPError,
        urllib.error.URLError,
        OSError,
        ValueError,
        UnicodeDecodeError,
    ):
        return None


def _findings_from_model(value: object) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        value = value.get("findings", value.get("vulnerabilities", []))
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _audit_prompt(source_text: str) -> str:
    return (
        "Audit the following Solidity source files as one interacting protocol. Focus on exploitable "
        "high or critical issues: broken authorization, accounting/share conversion errors, unsafe external "
        "calls, reentrancy with state-impacting effects, oracle/price manipulation, liquidation and debt "
        "invariant failures, signature misuse, and upgrade or initialization flaws. Trace cross-contract "
        "call paths when visible.\n\n"
        "Return exactly this JSON shape: {\"findings\":[{\"title\":string,\"severity\":\"high\"|\"critical\","
        "\"file\":string,\"line\":integer,\"description\":string,\"exploit_scenario\":string,"
        "\"impact\":string,\"recommendation\":string}]}. A description must cite the vulnerable "
        "function and explain the state transition. Return an empty findings array if the source does not "
        "prove a high or critical issue.\n"
        + source_text
    )


def _verification_prompt(candidates: list[dict[str, Any]], source_text: str) -> str:
    return (
        "Independently verify these proposed Solidity findings against the supplied source. Reject anything "
        "that depends on missing code, privileged trust assumptions not shown in source, or a non-exploitable "
        "theoretical concern. Correct the file, line, severity, and explanation where necessary.\n\n"
        "Return exactly {\"findings\":[...]}, with the same fields as the proposals. Keep only source-proven "
        "high or critical findings with a concrete unprivileged or realistically privileged attack path.\n\n"
        "PROPOSALS:\n"
        + json.dumps(candidates, ensure_ascii=False)
        + "\n\nSOURCE:\n"
        + source_text
    )


def _resolve_file(value: object, sources: list[dict[str, Any]]) -> dict[str, Any] | None:
    requested = str(value or "").replace("\\", "/").lstrip("./")
    exact = [item for item in sources if item["file"] == requested]
    if exact:
        return exact[0]
    suffix = [item for item in sources if str(item["file"]).endswith("/" + requested)]
    if len(suffix) == 1:
        return suffix[0]
    basename = [item for item in sources if Path(str(item["file"])).name == Path(requested).name]
    return basename[0] if len(basename) == 1 else None


def _integer(value: object, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _normalize_findings(
    candidates: list[dict[str, Any]], sources: list[dict[str, Any]]
) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    seen: set[tuple[str, int, str]] = set()
    for candidate in candidates:
        severity = str(candidate.get("severity", "")).strip().lower()
        if severity not in {"high", "critical"}:
            continue
        source = _resolve_file(candidate.get("file"), sources)
        title = " ".join(str(candidate.get("title", "")).split())
        description = " ".join(str(candidate.get("description", "")).split())
        scenario = " ".join(str(candidate.get("exploit_scenario", "")).split())
        impact = " ".join(str(candidate.get("impact", "")).split())
        recommendation = " ".join(str(candidate.get("recommendation", "")).split())
        if source is None or len(title) < 12 or len(description) < 120:
            continue
        line = max(1, min(_integer(candidate.get("line"), 1), int(source["lines"])))
        key = (str(source["file"]), line, title.lower())
        if key in seen:
            continue
        seen.add(key)
        full_description = description
        if scenario:
            full_description += " Exploit scenario: " + scenario
        if impact:
            full_description += " Impact: " + impact
        if recommendation:
            full_description += " Recommended fix: " + recommendation
        findings.append(
            {
                "title": title[:220],
                "severity": severity,
                "file": str(source["file"]),
                "line": line,
                "description": full_description[:2_800],
            }
        )
    return findings[:MAX_FINDINGS]


def agent_main(project_dir: str | None = None, inference_api: str | None = None) -> dict:
    root = _project_root(project_dir)
    sources = _collect_sources(root) if root is not None else []
    proposals: list[dict[str, Any]] = []
    final_candidates: list[dict[str, Any]] = []
    if sources:
        midpoint = max(1, (len(sources) + 1) // 2)
        for batch in (sources[:midpoint], sources[midpoint:]):
            if batch:
                proposals.extend(
                    _findings_from_model(
                        _ask_model(inference_api, _audit_prompt(_render_sources(batch)), 3_400)
                    )
                )

        verification_source = _render_sources(sources, MAX_PROMPT_CHARS)
        verified = _ask_model(
            inference_api,
            _verification_prompt(proposals, verification_source),
            3_400,
        )
        final_candidates = _findings_from_model(verified)
        if verified is None:
            final_candidates = proposals
    return {"vulnerabilities": _normalize_findings(final_candidates, sources)}
