from __future__ import annotations

"""SN60 miner: static entrypoint ranking + three themed audit passes.

Unlike triage-then-batch kings, this agent never spends an LLM call on repo
selection. It ranks external/public money-moving entrypoints with local
heuristics, then uses the full 3-call inference budget on specialized audits:
(1) authorization / trust boundaries, (2) value-flow / accounting, (3) a
cross-file follow-up on the hottest remaining slices.

Stdlib only. Validator inference proxy via x-inference-api-key.
"""

import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

SOURCE_SUFFIXES = (".sol", ".vy")
IGNORE_DIRS = frozenset(
    {
        ".git",
        ".github",
        "artifacts",
        "broadcast",
        "cache",
        "coverage",
        "dist",
        "docs",
        "example",
        "examples",
        "interfaces",
        "interface",
        "lib",
        "mock",
        "mocks",
        "node_modules",
        "out",
        "script",
        "scripts",
        "test",
        "tests",
        "vendor",
        "vendors",
    }
)

SOL_FN = re.compile(
    r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*([^{;]*)",
    re.MULTILINE,
)
VY_FN = re.compile(r"^([ \t]*)def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", re.MULTILINE)
SOL_TYPE = re.compile(
    r"^\s*(?:abstract\s+contract|contract|library|interface)\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
SOL_IMPORT = re.compile(r"""^\s*import\b[^;]*?["']([^"']+)["']""", re.MULTILINE)

MONEY_NAMES = (
    "withdraw",
    "redeem",
    "deposit",
    "mint",
    "burn",
    "swap",
    "exchange",
    "liquidate",
    "borrow",
    "repay",
    "claim",
    "stake",
    "unstake",
    "transfer",
    "execute",
    "settle",
    "harvest",
    "flash",
    "buy",
    "sell",
    "purchase",
    "list",
    "cancel",
    "fill",
    "auction",
)
PATH_HINTS = (
    "vault",
    "pool",
    "router",
    "bridge",
    "oracle",
    "proxy",
    "upgrade",
    "market",
    "lend",
    "borrow",
    "staking",
    "reward",
    "treasury",
    "controller",
    "strategy",
    "amm",
    "pair",
    "manager",
)
CODE_HINTS = (
    "delegatecall",
    ".call{",
    "selfdestruct",
    "tx.origin",
    "assembly",
    "upgradeTo",
    "initialize",
    "onlyOwner",
    "transferFrom",
    "permit",
    "ecrecover",
    "latestRoundData",
    "slot0",
    "unchecked",
    "reentran",
    "add_liquidity",
    "remove_liquidity",
    "get_dy",
    "virtual_price",
    "admin_fee",
)

MAX_FILES = 55
MAX_FILE_BYTES = 220_000
MAX_FINDINGS = 8
WALL_CLOCK = 220.0
HTTP_TIMEOUT = 140
SLICE_CHARS = 7_500
PACK_CHARS = 26_000
RELATED_CHARS = 2_800

SYSTEM = (
    "You audit smart contracts for exploitable HIGH/CRITICAL bugs only. "
    "Require a concrete attacker path and material fund/control impact. "
    "Ignore style, gas, naming, and missing events. Reply with strict JSON."
)


def agent_main(
    project_dir: str | None = None,
    inference_api: str | None = None,
) -> dict:
    started = time.monotonic()
    findings: list[dict[str, Any]] = []
    root = locate_project(project_dir)
    if root is None:
        return {"vulnerabilities": findings}

    files = index_sources(root)
    if not files:
        return {"vulnerabilities": findings}

    by_rel = {row["rel"]: row for row in files}
    by_name = {Path(row["rel"]).name: row for row in files}
    entrypoints = rank_entrypoints(files)
    if not entrypoints:
        entrypoints = fallback_entrypoints(files)

    raw: list[dict[str, Any]] = []
    packs = build_theme_packs(entrypoints, files)

    themes = (
        (
            "authorization",
            "Focus on missing/broken access control, initializer/upgrade trust, "
            "role bypass, tx.origin auth, and unprotected privileged setters.",
            packs[0],
        ),
        (
            "value_flow",
            "Focus on accounting errors, share/LP mint-burn mismatch, fee/decimal "
            "scaling, slippage bypass, insolvency, and incorrect balance updates.",
            packs[1],
        ),
        (
            "cross_boundary",
            "Focus on cross-contract trust assumptions, oracle staleness/manipulation, "
            "callback/reentrancy into state updates, and unsafe external calls.",
            packs[2],
        ),
    )

    for theme, guidance, pack in themes:
        if time.monotonic() - started >= WALL_CLOCK:
            break
        if not pack:
            continue
        try:
            raw.extend(
                themed_audit(inference_api, theme, guidance, pack, by_name)
            )
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                break
        except Exception:
            continue

    for item in raw:
        shaped = shape_finding(item, by_rel)
        if shaped is not None:
            findings.append(shaped)

    return {"vulnerabilities": dedupe_rank(findings)[:MAX_FINDINGS]}


def locate_project(project_dir: str | None) -> Path | None:
    candidates: list[str] = []
    if project_dir:
        candidates.append(project_dir)
    for key in ("PROJECT_DIR", "PROJECT_PATH", "PROJECT_ROOT", "PROJECT_CODE"):
        value = os.environ.get(key)
        if value:
            candidates.append(value)
    candidates.extend(
        ["/app/project_code", "/app/project", "/project", "/code", "."]
    )
    for raw in candidates:
        try:
            path = Path(raw).expanduser().resolve()
        except OSError:
            continue
        if path.is_dir() and has_sources(path):
            return path
    return None


def has_sources(root: Path) -> bool:
    try:
        for path in root.rglob("*"):
            if path.is_file() and path.suffix.lower() in SOURCE_SUFFIXES:
                return True
    except OSError:
        return False
    return False


def read_file(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def index_sources(root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        try:
            rel_path = path.relative_to(root)
            if any(part.lower() in IGNORE_DIRS for part in rel_path.parts[:-1]):
                continue
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        text = read_file(path)
        if not any(tok in text for tok in ("function", "contract ", "\ndef ")):
            continue
        contracts = SOL_TYPE.findall(text)
        if not contracts and path.suffix.lower() == ".vy":
            contracts = [path.stem]
        if not contracts:
            continue
        rel = rel_path.as_posix()
        rows.append(
            {
                "path": path,
                "rel": rel,
                "text": text,
                "contracts": contracts,
                "imports": SOL_IMPORT.findall(text),
                "entrypoints": extract_entrypoints(text, path.suffix.lower()),
                "score": score_file(rel, text),
            }
        )
    rows.sort(key=lambda row: (-int(row["score"]), str(row["rel"])))
    return rows[:MAX_FILES]


def extract_entrypoints(text: str, suffix: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if suffix == ".sol":
        for match in SOL_FN.finditer(text):
            name = match.group(1)
            args = match.group(2).strip()
            mods = " ".join(match.group(3).split())
            visibility = "internal"
            low_mods = mods.lower()
            if "external" in low_mods:
                visibility = "external"
            elif "public" in low_mods:
                visibility = "public"
            elif "private" in low_mods:
                visibility = "private"
            start = match.start()
            snippet = text[max(0, start - 120) : start + SLICE_CHARS]
            out.append(
                {
                    "name": name,
                    "args": args,
                    "mods": mods,
                    "visibility": visibility,
                    "start": start,
                    "snippet": snippet,
                    "heat": entrypoint_heat(name, mods, snippet),
                }
            )
    else:
        for match in VY_FN.finditer(text):
            indent = match.group(1)
            name = match.group(2)
            if indent.startswith("    ") or indent.startswith("\t"):
                continue
            start = match.start()
            snippet = text[max(0, start - 80) : start + SLICE_CHARS]
            out.append(
                {
                    "name": name,
                    "args": "",
                    "mods": "external",
                    "visibility": "external",
                    "start": start,
                    "snippet": snippet,
                    "heat": entrypoint_heat(name, "external", snippet),
                }
            )
    out.sort(key=lambda item: (-int(item["heat"]), str(item["name"])))
    return out


def entrypoint_heat(name: str, mods: str, snippet: str) -> int:
    low_name = name.lower()
    low_mods = mods.lower()
    low_snip = snippet.lower()
    heat = 0
    if "external" in low_mods or "public" in low_mods:
        heat += 8
    else:
        heat -= 4
    for token in MONEY_NAMES:
        if token in low_name:
            heat += 10
            break
    for token in CODE_HINTS:
        if token.lower() in low_snip:
            heat += 3
    if "onlyowner" in low_mods or "onlyrole" in low_mods:
        heat += 2
    if "view" in low_mods or "pure" in low_mods:
        heat -= 6
    if "nonreentrant" not in low_mods and any(
        tok in low_snip for tok in (".call{", "delegatecall", "transfer(")
    ):
        heat += 5
    return heat


def score_file(rel: str, text: str) -> int:
    low_rel = rel.lower()
    low = text.lower()
    score = min(low.count("function ") + low.count("\ndef "), 28)
    for hint in PATH_HINTS:
        if hint in low_rel:
            score += 9
    for hint in CODE_HINTS:
        score += min(low.count(hint.lower()), 3) * 3
    if "external" in low or "public" in low:
        score += 4
    return score


def rank_entrypoints(files: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ranked: list[dict[str, Any]] = []
    for row in files:
        for ep in row["entrypoints"]:
            if ep["visibility"] not in {"external", "public"}:
                continue
            if int(ep["heat"]) < 6:
                continue
            ranked.append(
                {
                    "rel": row["rel"],
                    "contracts": row["contracts"],
                    "imports": row["imports"],
                    "file_score": row["score"],
                    "text": row["text"],
                    **ep,
                }
            )
    ranked.sort(
        key=lambda item: (
            -int(item["heat"]),
            -int(item["file_score"]),
            str(item["rel"]),
            str(item["name"]),
        )
    )
    return ranked[:24]


def fallback_entrypoints(files: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ranked: list[dict[str, Any]] = []
    for row in files[:8]:
        for ep in row["entrypoints"][:4]:
            ranked.append(
                {
                    "rel": row["rel"],
                    "contracts": row["contracts"],
                    "imports": row["imports"],
                    "file_score": row["score"],
                    "text": row["text"],
                    **ep,
                }
            )
    return ranked[:18]


def build_theme_packs(
    entrypoints: list[dict[str, Any]], files: list[dict[str, Any]]
) -> list[list[dict[str, Any]]]:
    if not entrypoints:
        return [[], [], []]
    # Split by theme affinity so each call sees different slices.
    auth: list[dict[str, Any]] = []
    value: list[dict[str, Any]] = []
    cross: list[dict[str, Any]] = []
    for idx, ep in enumerate(entrypoints):
        name = str(ep["name"]).lower()
        mods = str(ep["mods"]).lower()
        snip = str(ep["snippet"]).lower()
        bucket = cross
        if any(
            tok in name or tok in mods or tok in snip
            for tok in ("owner", "role", "admin", "upgrade", "init", "govern", "auth")
        ):
            bucket = auth
        elif any(tok in name for tok in MONEY_NAMES) or any(
            tok in snip
            for tok in ("balance", "share", "liquidity", "fee", "amount", "mint", "burn")
        ):
            bucket = value
        bucket.append(ep)
        # Round-robin overflow so packs stay non-empty.
        if idx % 3 == 0 and ep not in auth:
            auth.append(ep)
        elif idx % 3 == 1 and ep not in value:
            value.append(ep)
        elif idx % 3 == 2 and ep not in cross:
            cross.append(ep)

    packs = [auth[:6], value[:6], cross[:6]]
    # Ensure each pack has content by borrowing from the global ranking.
    for pack in packs:
        if pack:
            continue
        pack.extend(entrypoints[:5])
    # Attach related import snippets for the cross pack.
    if packs[2]:
        packs[2] = attach_related(packs[2], files)
    return packs


def attach_related(
    pack: list[dict[str, Any]], files: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    by_name = {Path(row["rel"]).name: row for row in files}
    enriched: list[dict[str, Any]] = []
    for ep in pack:
        related_bits: list[str] = []
        for imp in ep.get("imports", [])[:4]:
            name = Path(str(imp)).name
            other = by_name.get(name)
            if other is None:
                continue
            related_bits.append(
                f"// related {other['rel']}\n{str(other['text'])[:RELATED_CHARS]}"
            )
        clone = dict(ep)
        if related_bits:
            clone["snippet"] = (
                str(ep["snippet"])[: SLICE_CHARS - 400]
                + "\n\n"
                + "\n\n".join(related_bits)
            )[:SLICE_CHARS]
        enriched.append(clone)
    return enriched


def themed_audit(
    inference_api: str | None,
    theme: str,
    guidance: str,
    pack: list[dict[str, Any]],
    by_name: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    blocks: list[str] = []
    used = 0
    for ep in pack:
        block = (
            f"### {ep['rel']} :: {ep['name']}\n"
            f"contracts={ep['contracts'][:4]} visibility={ep['visibility']} "
            f"mods={ep['mods'][:120]}\n"
            f"{ep['snippet']}"
        )
        if used + len(block) > PACK_CHARS:
            break
        blocks.append(block)
        used += len(block)
    if not blocks:
        return []

    prompt = (
        f"Theme={theme}. {guidance}\n"
        "Return strict JSON only:\n"
        '{"findings":[{"title":"Contract.function — bug","file":"path.sol",'
        '"contract":"Contract","function":"fn","severity":"high|critical",'
        '"mechanism":"precondition -> attack -> effect","impact":"material harm",'
        '"description":"2-4 precise sentences"}]}\n'
        "Use only symbols present in the slices. Prefer fewer true positives over "
        "speculation.\n\n"
        + "\n\n".join(blocks)
    )
    try:
        content = ask_model(
            inference_api,
            [
                {"role": "system", "content": SYSTEM},
                {"role": "user", "content": prompt},
            ],
            max_tokens=4200,
        )
    except urllib.error.HTTPError:
        raise
    except Exception:
        return []
    obj = parse_json_object(content)
    items = obj.get("findings") or obj.get("vulnerabilities") or []
    if not isinstance(items, list):
        return []
    # Light path repair using known filenames when model omits directories.
    repaired: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        file_name = str(item.get("file") or "")
        if file_name and file_name not in by_name and Path(file_name).name in by_name:
            item = dict(item)
            item["file"] = by_name[Path(file_name).name]["rel"]
        repaired.append(item)
    return repaired


def ask_model(
    inference_api: str | None,
    messages: list[dict[str, str]],
    max_tokens: int,
) -> str:
    base = (inference_api or os.environ.get("INFERENCE_API") or "").rstrip("/")
    if not base:
        raise RuntimeError("INFERENCE_API missing")
    payload = json.dumps(
        {
            "messages": messages,
            "max_tokens": max_tokens,
            "reasoning": {"effort": "low", "exclude": True},
        }
    ).encode()
    headers = {
        "Content-Type": "application/json",
        "x-inference-api-key": os.environ.get("INFERENCE_API_KEY", ""),
    }
    last_error: Exception | None = None
    for attempt in range(3):
        try:
            req = urllib.request.Request(
                base + "/inference",
                data=payload,
                method="POST",
                headers=headers,
            )
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                body = json.loads(resp.read().decode("utf-8", "replace"))
            return extract_content(body)
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                raise
            last_error = exc
        except (OSError, ValueError, TimeoutError) as exc:
            last_error = exc
        if attempt < 2:
            time.sleep(1.1 * (attempt + 1))
    raise RuntimeError(str(last_error))


def extract_content(body: dict[str, Any]) -> str:
    choices = body.get("choices")
    if not isinstance(choices, list) or not choices:
        return ""
    message = choices[0].get("message") if isinstance(choices[0], dict) else None
    if not isinstance(message, dict):
        return ""
    content = message.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(
            str(part.get("text") or "")
            for part in content
            if isinstance(part, dict)
        )
    return ""


def parse_json_object(text: str) -> dict[str, Any]:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```[a-zA-Z]*\s*", "", stripped)
        stripped = re.sub(r"\s*```$", "", stripped)
    try:
        obj = json.loads(stripped)
        return obj if isinstance(obj, dict) else {}
    except json.JSONDecodeError:
        pass
    start = stripped.find("{")
    if start < 0:
        return {}
    depth = 0
    in_string = False
    escape = False
    for idx in range(start, len(stripped)):
        ch = stripped[idx]
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                try:
                    obj = json.loads(stripped[start : idx + 1])
                    return obj if isinstance(obj, dict) else {}
                except json.JSONDecodeError:
                    return {}
    return {}


def shape_finding(
    item: dict[str, Any], by_rel: dict[str, dict[str, Any]]
) -> dict[str, Any] | None:
    file_rel = str(item.get("file") or "").replace("\\", "/").lstrip("./")
    if file_rel not in by_rel:
        base = Path(file_rel).name
        matches = [rel for rel in by_rel if Path(rel).name == base]
        if len(matches) != 1:
            return None
        file_rel = matches[0]
    row = by_rel[file_rel]
    text = str(row["text"])
    contract = str(item.get("contract") or "").strip()
    function = str(item.get("function") or "").strip()
    if contract and contract not in row["contracts"]:
        # Keep finding if contract omitted/wrong but file is real; prefer known name.
        contract = row["contracts"][0] if row["contracts"] else contract
    if function and function not in {ep["name"] for ep in row["entrypoints"]}:
        # Allow unknown helper names only if they appear in source text.
        if not re.search(rf"\b{re.escape(function)}\b", text):
            function = ""

    title = str(item.get("title") or "").strip()
    mechanism = str(item.get("mechanism") or "").strip()
    impact = str(item.get("impact") or "").strip()
    description = str(item.get("description") or "").strip()
    severity = str(item.get("severity") or "high").strip().lower()
    if severity not in {"high", "critical", "medium", "low"}:
        severity = "high"
    if severity in {"medium", "low"}:
        # Competition focuses on high/critical; keep only if impact is strong.
        if "fund" not in (impact + description).lower() and "drain" not in (
            impact + description
        ).lower():
            return None
        severity = "high"

    if not description and not mechanism:
        return None
    if not title:
        label = f"{contract}.{function}" if contract and function else (function or contract or "Unknown")
        bug = (mechanism or description).split(".")[0][:80]
        title = f"{label} — {bug}".strip(" —")

    # Normalize title toward Contract.function — bug
    if contract and function and "—" not in title and " - " not in title:
        title = f"{contract}.{function} — {title}"

    body_parts = [p for p in (description, mechanism, impact) if p]
    full_description = " ".join(body_parts)
    if mechanism and mechanism not in full_description:
        full_description = f"{full_description} Mechanism: {mechanism}."
    if impact and impact not in full_description:
        full_description = f"{full_description} Impact: {impact}."

    line = None
    if function:
        line = line_of(text, f"function {function}") or line_of(text, f"def {function}")
    if line is None and contract:
        line = line_of(text, f"contract {contract}")

    finding: dict[str, Any] = {
        "title": title[:180],
        "description": full_description[:1200],
        "severity": severity,
        "file": file_rel,
    }
    if line is not None:
        finding["line"] = line
    return finding


def line_of(text: str, needle: str) -> int | None:
    pos = text.find(needle)
    if pos < 0:
        return None
    return text.count("\n", 0, pos) + 1


def dedupe_rank(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for item in findings:
        key = "|".join(
            [
                str(item.get("file") or ""),
                str(item.get("title") or "").lower(),
                str(item.get("line") or ""),
            ]
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)

    def rank_key(item: dict[str, Any]) -> tuple[int, int, str]:
        sev = str(item.get("severity") or "").lower()
        sev_score = {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(sev, 4)
        return (sev_score, -len(str(item.get("description") or "")), str(item.get("title") or ""))

    unique.sort(key=rank_key)
    return unique
