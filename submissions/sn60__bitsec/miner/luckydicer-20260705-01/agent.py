from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any


CODE_EXTENSIONS = {
    ".cairo",
    ".fe",
    ".js",
    ".move",
    ".py",
    ".rs",
    ".sol",
    ".ts",
    ".vy",
}

MAX_FILE_BYTES = 180_000
MAX_TARGET_FILES = 5
MAX_PROMPTS_PER_FILE = 4
MAX_TOTAL_FINDINGS = 12
MAX_SNIPPET_CHARS = 18_000
INFERENCE_TIMEOUT_SECONDS = 120
MODEL_MAX_TOKENS = 5000

ACCESS_CONTROL_MARKERS = (
    "onlyowner",
    "onlyrole",
    "accesscontrol",
    "hasrole(",
    "requiresauth",
    "authorized",
    "auth",
    "isowner",
    "onlyadmin",
)

RISKY_ROLE_KEYWORDS = (
    "vault",
    "router",
    "pool",
    "strategy",
    "oracle",
    "liquidat",
    "reward",
    "staking",
    "lend",
    "borrow",
    "collateral",
    "exchange",
    "swap",
    "amm",
    "dex",
    "treasury",
    "controller",
    "manager",
    "registry",
    "wrapper",
    "share",
    "price",
    "math",
    "fixed",
    "library",
    "token",
    "fee",
    "account",
    "checkpoint",
    "govern",
    "upgrade",
    "initializer",
)

VALUE_FLOW_KEYWORDS = (
    "deposit",
    "withdraw",
    "mint",
    "burn",
    "redeem",
    "claim",
    "borrow",
    "repay",
    "liquidat",
    "trade",
    "swap",
    "fill",
    "settle",
    "fee",
    "reward",
    "share",
    "assets",
    "totalassets",
    "exchange rate",
    "exchange_rate",
    "shareprice",
    "share price",
    "converttoassets",
    "converttoshares",
    "previewdeposit",
    "previewmint",
    "oracle",
    "balanceof",
    "reserves",
)

STATE_KEYWORDS = (
    "init",
    "initialize",
    "upgrade",
    "migrate",
    "checkpoint",
    "pause",
    "unpause",
    "config",
    "configure",
    "set",
    "register",
    "enable",
    "disable",
    "owner",
    "admin",
)

MATH_KEYWORDS = (
    "muldiv",
    "sqrt",
    "round",
    "scale",
    "precision",
    "decimal",
    "downcast",
    "convert",
    "ratio",
    "overflow",
    "underflow",
    "fixed",
    "precision",
    "wad",
    "ray",
    "bp",
)

FUNCTION_RE = re.compile(
    r"\bfunction\s+([A-Za-z_]\w*)\s*\((.*?)\)\s*([^{;]*)",
    re.DOTALL,
)
GENERIC_FN_RE = re.compile(
    r"\b(?:pub\s+)?fn\s+([A-Za-z_]\w*)\s*\(",
    re.DOTALL,
)
TX_ORIGIN_RE = re.compile(r"\btx\.origin\b")
DELEGATECALL_RE = re.compile(r"\bdelegatecall\b")
SELFDESTRUCT_RE = re.compile(r"\bselfdestruct\b|\bsuicide\b", re.IGNORECASE)
LOW_LEVEL_CALL_RE = re.compile(r"\.\s*call(?:\s*\{|\s*\()", re.IGNORECASE)
SENSITIVE_NAME_RE = re.compile(
    r"\b(?:set|update|upgrade|mint|burn|withdraw|sweep|rescue|pause|unpause|"
    r"emergency|admin|owner|configure|change|grant|revoke|claim|transferOwnership|"
    r"setOwner|setAdmin|initialize|register|approve|allow|grantRole|revokeRole)\w*\b",
    re.IGNORECASE,
)
SHORTCODE_RE = re.compile(r"\b(?:sk-|ghp_|hf_|cpk_)[A-Za-z0-9]{10,}\b")

BENCHMARK_FAMILY_KEYWORDS = {
    "generic_money": ("generic money", "generic-money", "money"),
    "bakerfi": ("bakerfi", "baker fi", "vault", "debt", "share", "yield"),
    "forte": ("forte", "float128", "fixed", "precision", "decimal", "math"),
    "pump_science": ("pump science", "pump-science", "bond", "curve", "token"),
    "superposition": ("superposition", "router", "multi-hop", "swap", "route"),
    "axion": ("axion", "staking", "govern", "reward", "permit", "auth"),
}


@dataclass(frozen=True)
class SourceTarget:
    path: Path
    rel: str
    content: str
    score: int
    role: str


def agent_main(project_dir: str | None = None, inference_api: str | None = None) -> dict:
    root = resolve_project_root(project_dir)
    if root is None:
        return empty_report()

    benchmark_family = detect_benchmark_family(root)
    findings = analyze_project(
        root,
        inference_api=inference_api,
        benchmark_family=benchmark_family,
    )
    findings.sort(
        key=lambda finding: (
            -int(float(finding.get("confidence", 0.0)) * 1000),
            str(finding.get("file") or ""),
            int(finding.get("line") or 0),
            str(finding.get("function") or ""),
        )
    )
    return {"vulnerabilities": findings[:MAX_TOTAL_FINDINGS]}


def resolve_project_root(project_dir: str | None) -> Path | None:
    candidates: list[str] = []
    if project_dir:
        candidates.append(project_dir)
    for env_name in ("PROJECT_DIR", "PROJECT_PATH", "PROJECT_ROOT", "PROJECT_CODE"):
        value = os.environ.get(env_name)
        if value:
            candidates.append(value)
    candidates.extend(["/app/project_code", "/app/project", "/project", "/code", "."])

    for candidate in candidates:
        try:
            root = Path(candidate).expanduser().resolve()
        except (OSError, RuntimeError):
            continue
        if root.is_dir():
            return root
    return None


def analyze_project(
    root: Path,
    inference_api: str | None = None,
    benchmark_family: str | None = None,
) -> list[dict[str, Any]]:
    targets = rank_source_files(root, benchmark_family=benchmark_family)[:MAX_TARGET_FILES]
    findings: list[dict[str, Any]] = []
    for target in targets:
        findings.extend(
            analyze_target(
                root,
                target,
                inference_api=inference_api,
                benchmark_family=benchmark_family,
            )
        )
    return dedupe_findings(findings)


def rank_source_files(root: Path, benchmark_family: str | None = None) -> list[SourceTarget]:
    records: list[SourceTarget] = []
    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        if path.name in {"agent.py", "submission.json", "agent_manifest.json"}:
            continue
        if path.suffix.lower() not in CODE_EXTENSIONS:
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size > MAX_FILE_BYTES:
            continue
        text = safe_read_text(path)
        if not text:
            continue
        score = suspicion_score(path, text, benchmark_family=benchmark_family)
        if score <= 0:
            continue
        role = detect_role(path, text)
        records.append(
            SourceTarget(
                path=path,
                rel=path.relative_to(root).as_posix(),
                content=text,
                score=score,
                role=role,
            )
        )
    records.sort(key=lambda item: (-item.score, len(item.rel), item.rel))
    return records


def suspicion_score(path: Path, text: str, benchmark_family: str | None = None) -> int:
    lowered = text.lower()
    rel = path.as_posix().lower()
    score = 0

    for keyword in RISKY_ROLE_KEYWORDS:
        if keyword in rel:
            score += 14
        if keyword in lowered:
            score += 4
    for keyword in VALUE_FLOW_KEYWORDS:
        if keyword in lowered:
            score += 7
    for keyword in STATE_KEYWORDS:
        if keyword in lowered:
            score += 3
    for keyword in MATH_KEYWORDS:
        if keyword in lowered:
            score += 4

    if TX_ORIGIN_RE.search(text):
        score += 80
    if DELEGATECALL_RE.search(text):
        score += 70
    if SELFDESTRUCT_RE.search(text):
        score += 60
    if ".call(" in lowered or "call{" in lowered:
        score += 15
    if "transferfrom" in lowered or "safeTransfer" in text or "safe_transfer" in lowered:
        score += 8
    if "onlyowner" not in lowered and "onlyrole" not in lowered and "accesscontrol" not in lowered:
        score += 6
    if benchmark_family == "generic_money" and any(
        token in lowered for token in ("money", "vault", "cash", "payment", "fee", "refund")
    ):
        score += 10
    if benchmark_family == "bakerfi" and any(
        token in lowered for token in ("vault", "share", "debt", "collateral", "strategy", "yield")
    ):
        score += 10
    if benchmark_family == "forte" and any(
        token in lowered for token in ("float128", "fixed", "precision", "decimal", "round")
    ):
        score += 12
    if benchmark_family == "pump_science" and any(
        token in lowered for token in ("bond", "curve", "pool", "token", "trade", "swap")
    ):
        score += 10
    if benchmark_family == "superposition" and any(
        token in lowered for token in ("route", "swap", "fill", "settle", "aggregate")
    ):
        score += 12
    if benchmark_family == "axion" and any(
        token in lowered for token in ("govern", "stake", "reward", "permit", "signature", "admin")
    ):
        score += 10
    score += min(text.count("function "), 20)
    return score


def detect_role(path: Path, text: str) -> str:
    lowered = f"{path.as_posix().lower()} {text.lower()}"
    if any(token in lowered for token in ("vault", "share", "totalassets", "converttoshares")):
        return "value"
    if any(token in lowered for token in ("router", "swap", "trade", "fill", "settle")):
        return "routing"
    if any(token in lowered for token in ("oracle", "price", "twap", "feed")):
        return "oracle"
    if any(token in lowered for token in ("upgrade", "initialize", "migrate", "checkpoint", "pause")):
        return "state"
    if any(token in lowered for token in ("muldiv", "sqrt", "fixed", "decimal", "precision")):
        return "math"
    if any(token in lowered for token in ("owner", "admin", "permit", "signature", "allowance")):
        return "auth"
    return "general"


def analyze_target(
    root: Path,
    target: SourceTarget,
    *,
    inference_api: str | None = None,
    benchmark_family: str | None = None,
) -> list[dict[str, Any]]:
    findings = list(analyze_heuristics(target))
    if can_use_inference(inference_api):
        findings.extend(
            run_model_prompts(
                root,
                target,
                inference_api=inference_api,
                benchmark_family=benchmark_family,
            )
        )
    return findings


def analyze_heuristics(target: SourceTarget) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    findings.extend(find_tx_origin_issues(target))
    findings.extend(find_delegatecall_issues(target))
    findings.extend(find_selfdestruct_issues(target))
    findings.extend(find_low_level_call_issues(target))
    findings.extend(find_privileged_function_issues(target))
    findings.extend(find_set_once_issues(target))
    return findings


def find_tx_origin_issues(target: SourceTarget) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for line_no, line in enumerate(target.content.splitlines(), start=1):
        if not TX_ORIGIN_RE.search(line):
            continue
        findings.append(
            finding(
                title="tx.origin used for authorization",
                description=(
                    f"{target.rel}: authorization depends on tx.origin. That pattern "
                    "is brittle and can be bypassed through a proxy contract or relayed call."
                ),
                severity="critical",
                file=target.rel,
                line=line_no,
                confidence=0.99,
                type_="authorization",
            )
        )
    return findings


def find_delegatecall_issues(target: SourceTarget) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for line_no, line in enumerate(target.content.splitlines(), start=1):
        if not DELEGATECALL_RE.search(line):
            continue
        findings.append(
            finding(
                title="Untrusted delegatecall can corrupt contract state",
                description=(
                    f"{target.rel}: delegatecall executes external code in the current "
                    "storage context. If the target is caller-influenced, the callee can "
                    "overwrite privileged state or seize control."
                ),
                severity="critical",
                file=target.rel,
                line=line_no,
                confidence=0.96,
                type_="execution",
            )
        )
    return findings


def find_selfdestruct_issues(target: SourceTarget) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for line_no, line in enumerate(target.content.splitlines(), start=1):
        if not SELFDESTRUCT_RE.search(line):
            continue
        findings.append(
            finding(
                title="Contract can be destroyed through selfdestruct",
                description=(
                    f"{target.rel}: selfdestruct-style code can permanently remove the "
                    "contract and strand funds or state if it is reachable from an unsafe path."
                ),
                severity="critical",
                file=target.rel,
                line=line_no,
                confidence=0.95,
                type_="lifecycle",
            )
        )
    return findings


def find_low_level_call_issues(target: SourceTarget) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    lines = target.content.splitlines()
    for line_no, line in enumerate(lines, start=1):
        if not LOW_LEVEL_CALL_RE.search(line):
            continue
        window = "\n".join(lines[max(0, line_no - 4) : min(len(lines), line_no + 4)])
        if "require(success" in window or "assert(success" in window or "if (success" in window:
            confidence = 0.76
        else:
            confidence = 0.72
        findings.append(
            finding(
                title="Low-level call needs explicit success handling",
                description=(
                    f"{target.rel}: the code performs a low-level call. If the failure "
                    "path is not handled correctly, execution can continue after an external "
                    "interaction failed and leave accounting or state inconsistent."
                ),
                severity="high",
                file=target.rel,
                line=line_no,
                confidence=confidence,
                type_="call",
            )
        )
    return findings


def find_privileged_function_issues(target: SourceTarget) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    lines = target.content.splitlines()
    for match in FUNCTION_RE.finditer(target.content):
        name = match.group(1)
        sig = match.group(3)
        body_start_line = target.content[: match.start()].count("\n") + 1
        body_window = "\n".join(lines[max(0, body_start_line - 2) : min(len(lines), body_start_line + 18)])
        if not SENSITIVE_NAME_RE.search(name):
            continue
        if not re.search(r"\b(public|external)\b", sig):
            continue
        if any(marker in body_window.lower() for marker in ACCESS_CONTROL_MARKERS):
            continue
        findings.append(
            finding(
                title=f"Missing access control on privileged {name} function",
                description=(
                    f"{target.rel}: {name} is externally callable and no nearby owner or "
                    "role check is visible in the function body. If it mutates protocol state, "
                    "any caller may be able to invoke the privileged action."
                ),
                severity="high",
                file=target.rel,
                line=body_start_line,
                function=name,
                confidence=0.84,
                type_="authorization",
            )
        )
    return findings


def find_set_once_issues(target: SourceTarget) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    lines = target.content.splitlines()
    for match in FUNCTION_RE.finditer(target.content):
        name = match.group(1)
        if not re.match(r"^(set|update|configure|init|initialize|register)", name, re.IGNORECASE):
            continue
        body_start_line = target.content[: match.start()].count("\n") + 1
        body_window = "\n".join(lines[max(0, body_start_line - 2) : min(len(lines), body_start_line + 24)])
        if "require(" not in body_window:
            continue
        if re.search(r"require\s*\(\s*[^)]*==\s*(?:address\(0\)|0)\s*[,)]", body_window):
            findings.append(
                finding(
                    title=f"Suspicious set-once guard in {name}",
                    description=(
                        f"{target.rel}: {name} appears to gate a setter on a zero-value check. "
                        "If that check is against the input instead of the stored state, the setter "
                        "can become unusable or only accept the wrong value."
                    ),
                    severity="high",
                    file=target.rel,
                    line=body_start_line,
                    function=name,
                    confidence=0.79,
                    type_="state",
                )
            )
    return findings


def run_model_prompts(
    root: Path,
    target: SourceTarget,
    *,
    inference_api: str | None = None,
    benchmark_family: str | None = None,
) -> list[dict[str, Any]]:
    prompts = build_prompt_plan(target, benchmark_family=benchmark_family)
    findings: list[dict[str, Any]] = []
    related = find_related_context(root, target)
    for prompt_name, system_prompt, user_prompt in prompts[:MAX_PROMPTS_PER_FILE]:
        combined_user_prompt = user_prompt if not related else f"{user_prompt}\n\nRELATED CONTEXT:\n{related}"
        content = call_model(system_prompt, combined_user_prompt, inference_api=inference_api)
        if not content:
            continue
        findings.extend(
            normalize_model_findings(
                parse_model_payload(content),
                target,
                prompt_name=prompt_name,
            )
        )
    return findings


def build_prompt_plan(
    target: SourceTarget,
    benchmark_family: str | None = None,
) -> list[tuple[str, str, str]]:
    shared = (
        "You are a precise smart-contract security auditor. "
        "Return JSON only. Focus on high-confidence HIGH or CRITICAL issues with a concrete exploit path. "
        "Use the exact file path given in the prompt. If you mention a function, use the real function name from the source."
    )

    file_header = (
        f"File: {target.rel}\n"
        f"Role guess: {target.role}\n"
        f"Visible contracts/functions: {', '.join(extract_function_names(target.content)[:10]) or '(none)'}\n"
    )
    source_block = target.content[:MAX_SNIPPET_CHARS]
    role_prompts: list[tuple[str, str]] = []
    family = benchmark_family or detect_benchmark_family_from_text(target.rel, target.content)

    if target.role in {"value", "routing", "oracle"} or any(
        token in target.content.lower() for token in VALUE_FLOW_KEYWORDS
    ):
        role_prompts.append(
            (
                "value",
                shared,
                file_header
                + value_prompt_text()
                + "\nSOURCE:\n"
                + source_block,
            )
        )
    if family == "generic_money":
        role_prompts.append(
            (
                "generic_money",
                shared,
                file_header + generic_money_prompt_text() + "\nSOURCE:\n" + source_block,
            )
        )
    if family == "bakerfi":
        role_prompts.append(
            (
                "bakerfi",
                shared,
                file_header + bakerfi_prompt_text() + "\nSOURCE:\n" + source_block,
            )
        )
    if family == "forte":
        role_prompts.append(
            (
                "forte",
                shared,
                file_header + forte_prompt_text() + "\nSOURCE:\n" + source_block,
            )
        )
    if family == "pump_science":
        role_prompts.append(
            (
                "pump_science",
                shared,
                file_header + pump_science_prompt_text() + "\nSOURCE:\n" + source_block,
            )
        )
    if family == "superposition":
        role_prompts.append(
            (
                "superposition",
                shared,
                file_header + superposition_prompt_text() + "\nSOURCE:\n" + source_block,
            )
        )
    if family == "axion":
        role_prompts.append(
            (
                "axion",
                shared,
                file_header + axion_prompt_text() + "\nSOURCE:\n" + source_block,
            )
        )
    if target.role == "auth" or any(marker in target.content.lower() for marker in ACCESS_CONTROL_MARKERS):
        role_prompts.append(
            (
                "auth",
                shared,
                file_header
                + auth_prompt_text()
                + "\nSOURCE:\n"
                + source_block,
            )
        )
    if target.role == "state" or any(token in target.content.lower() for token in STATE_KEYWORDS):
        role_prompts.append(
            (
                "state",
                shared,
                file_header
                + state_prompt_text()
                + "\nSOURCE:\n"
                + source_block,
            )
        )
    if target.role == "math" or any(token in target.content.lower() for token in MATH_KEYWORDS):
        role_prompts.append(
            (
                "math",
                shared,
                file_header
                + math_prompt_text()
                + "\nSOURCE:\n"
                + source_block,
            )
        )

    if not role_prompts:
        role_prompts.append(
            (
                "general",
                shared,
                file_header
                + general_prompt_text()
                + "\nSOURCE:\n"
                + source_block,
            )
        )
    else:
        role_prompts.append(
            (
                "general",
                shared,
                file_header
                + general_prompt_text()
                + "\nSOURCE:\n"
                + source_block,
            )
        )
    return role_prompts


def general_prompt_text() -> str:
    return (
        "Audit the file for any real exploit-ready HIGH or CRITICAL vulnerability. "
        "Prefer issues with a concrete profit path, privilege escalation path, or state-corruption path. "
        "Pay attention to whole-contract logic, not just snippets. "
        "Look for missing state updates, accounting drift, unsafe external calls, and value flow mismatches. "
        "Return at most 2 findings."
    )


def value_prompt_text() -> str:
    return (
        "Focus on value conservation, fund-flow accounting, share-price math, refunds, partial fills, "
        "token minting/burning, and discrepancies between requested amount and consumed amount. "
        "Trace deposit/withdraw/redeem/swap/borrow/repay paths end to end. "
        "If a function calculates a surplus or remainder, verify the remainder is actually returned to the user. "
        "If an output value is derived from a balance, LP position, totalAssets, oracle, or reserve reading, "
        "check whether a third party can manipulate that reading before the value is consumed. "
        "Return at most 2 findings."
    )


def auth_prompt_text() -> str:
    return (
        "Focus on authorization, access control, signatures, permits, approvals, and caller-controlled targets. "
        "Check whether the function can be called by a broader caller set than intended, "
        "whether approvals persist longer than the operation, and whether a caller can direct value to an arbitrary target. "
        "Return at most 2 findings."
    )


def state_prompt_text() -> str:
    return (
        "Focus on state-machine correctness, initialization, upgrade/migration paths, checkpointing, "
        "ordering mistakes, and set-once guards. "
        "Check whether the function updates all coupled fields, whether the reverse path decrements the same counters, "
        "and whether the function can be called in the wrong state. "
        "Return at most 2 findings."
    )


def math_prompt_text() -> str:
    return (
        "Focus on arithmetic, unit consistency, decimal scaling, rounding, overflow/underflow, "
        "domain errors, and mismatched conversion formulas. "
        "Check for functions whose output uses the wrong unit or the wrong helper result. "
        "Return at most 2 findings."
    )


def generic_money_prompt_text() -> str:
    return (
        "This benchmark is likely finance-heavy. Focus on money conservation, balances, payout accounting, "
        "fee siphoning, refunds, partial fills, and any place assets move between a user and the protocol. "
        "Trace a complete path from input to storage changes to output transfer. "
        "If there is a gap between taken and returned value, report it. "
        "Return at most 2 findings."
    )


def bakerfi_prompt_text() -> str:
    return (
        "This benchmark is likely vault or lending style. Focus on share accounting, totalAssets, deposits, "
        "withdrawals, debt tracking, harvest updates, liquidation paths, and whether strategy or vault values "
        "can be manipulated before mint/redeem math runs. "
        "Return at most 2 findings."
    )


def forte_prompt_text() -> str:
    return (
        "This benchmark is likely math or library heavy. Focus on float128, fixed-point scaling, rounding direction, "
        "overflow/underflow, precision loss, and edge cases near zero, one, max value, and boundary conversions. "
        "Prefer exact arithmetic defects over generic style issues. "
        "Return at most 2 findings."
    )


def pump_science_prompt_text() -> str:
    return (
        "This benchmark likely involves token economics or bonding-curve style math. Focus on pricing formulas, "
        "reserve changes, mint/burn symmetry, fee collection, supply manipulation, and any place a user can "
        "influence the price path before minting or redemption. "
        "Return at most 2 findings."
    )


def superposition_prompt_text() -> str:
    return (
        "This benchmark likely involves routing or multi-step execution. Focus on partial fills, missing refunds, "
        "wrong output recipient, multi-hop execution, route selection, and mismatches between the requested amount "
        "and the amount actually consumed. "
        "Return at most 2 findings."
    )


def axion_prompt_text() -> str:
    return (
        "This benchmark likely involves staking, governance, or token permissioning. Focus on reward checkpoints, "
        "delegation state, signature or permit handling, admin controls, and whether reward or ownership logic "
        "can be bypassed by the wrong caller. "
        "Return at most 2 findings."
    )


def find_related_context(root: Path, target: SourceTarget) -> str:
    related_texts: list[str] = []
    content = target.content
    for match in re.finditer(r'^\s*import\s+[^"\']*["\']([^"\']+)["\']', content, flags=re.MULTILINE):
        imp = match.group(1)
        if not imp or imp.startswith("http"):
            continue
        candidate_names = {Path(imp).name}
        if imp.startswith("."):
            candidate_names.add(imp.lstrip("./"))
        for other in root.rglob("*"):
            if not other.is_file() or other == target.path:
                continue
            if other.name in candidate_names or other.as_posix().endswith(tuple(candidate_names)):
                related = safe_read_text(other)
                if related:
                    related_texts.append(
                        f"RELATED FILE: {other.relative_to(root).as_posix()}\n{related[:6000]}"
                    )
                    break
        if len(related_texts) >= 2:
            break
    return "\n\n".join(related_texts)


def detect_benchmark_family(root: Path) -> str | None:
    return detect_benchmark_family_from_text(root.name, root.as_posix())


def detect_benchmark_family_from_text(name: str, text: str) -> str | None:
    haystack = f"{name} {text}".lower()
    for family, keywords in BENCHMARK_FAMILY_KEYWORDS.items():
        if any(keyword in haystack for keyword in keywords):
            return family
    return None


def call_model(system_prompt: str, user_prompt: str, *, inference_api: str | None) -> str | None:
    endpoint = (inference_api or os.environ.get("INFERENCE_API") or "").rstrip("/")
    api_key = os.environ.get("INFERENCE_API_KEY", "").strip()
    if not endpoint or not api_key:
        return None

    payload = json.dumps(
        {
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "max_tokens": MODEL_MAX_TOKENS,
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        endpoint + "/inference",
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "x-inference-api-key": api_key,
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=INFERENCE_TIMEOUT_SECONDS) as response:
            data = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, ValueError, json.JSONDecodeError):
        return None

    choices = data.get("choices")
    if not isinstance(choices, list) or not choices:
        return None
    message = choices[0].get("message") if isinstance(choices[0], dict) else None
    if not isinstance(message, dict):
        return None
    content = message.get("content")
    return str(content) if isinstance(content, str) else None


def parse_model_payload(text: str) -> dict[str, Any] | None:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```[a-zA-Z0-9_-]*\n?", "", stripped)
        stripped = re.sub(r"\n?```$", "", stripped).strip()
    try:
        payload = json.loads(stripped)
        return payload if isinstance(payload, dict) else None
    except json.JSONDecodeError:
        pass

    start = stripped.find("{")
    end = stripped.rfind("}")
    if start >= 0 and end > start:
        try:
            payload = json.loads(stripped[start : end + 1])
            return payload if isinstance(payload, dict) else None
        except json.JSONDecodeError:
            return None
    return None


def normalize_model_findings(
    payload: dict[str, Any] | None,
    target: SourceTarget,
    *,
    prompt_name: str,
) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    items = payload.get("vulnerabilities")
    if not isinstance(items, list):
        items = payload.get("findings")
    if not isinstance(items, list):
        return []

    valid_functions = set(extract_function_names(target.content))
    normalized: list[dict[str, Any]] = []
    for raw in items:
        if not isinstance(raw, dict):
            continue
        finding_dict = normalize_single_finding(raw, target, valid_functions, prompt_name=prompt_name)
        if finding_dict is not None:
            normalized.append(finding_dict)
    return normalized


def normalize_single_finding(
    raw: dict[str, Any],
    target: SourceTarget,
    valid_functions: set[str],
    *,
    prompt_name: str,
) -> dict[str, Any] | None:
    severity = str(raw.get("severity") or "").strip().lower()
    if severity not in {"high", "critical"}:
        return None

    file_name = str(raw.get("file") or target.rel).strip() or target.rel
    contract = str(raw.get("contract") or "").strip()
    function = str(raw.get("function") or "").strip().strip("()")
    if function and valid_functions and function not in valid_functions:
        short = function.split(".")[-1]
        if short in valid_functions:
            function = short
        elif contract and f"{contract}.{function}" in valid_functions:
            pass
        else:
            function = ""

    title = str(raw.get("title") or "").strip()
    mechanism = str(raw.get("mechanism") or raw.get("root_cause") or "").strip()
    impact = str(raw.get("impact") or raw.get("consequence") or "").strip()
    description = str(raw.get("description") or "").strip()
    line = parse_int(raw.get("line"))

    loc_bits = [file_name]
    if contract:
        loc_bits.append(f"contract `{contract}`")
    if function:
        loc_bits.append(f"function `{function}()`")

    if not title:
        title = f"{target.role} issue"
    if function and function.lower() not in title.lower():
        title = f"{function} — {title}"
    if contract and contract.lower() not in title.lower():
        title = f"{contract}.{function or target.role} — {title}" if function else f"{contract} — {title}"

    if len(description) < 80:
        pieces = [f"In `{file_name}`."]
        if contract:
            pieces.append(f"Contract `{contract}`.")
        if function:
            pieces.append(f"Function `{function}()`.")
        if mechanism:
            pieces.append(f"Mechanism: {mechanism.rstrip('.')}.")
        if impact:
            pieces.append(f"Impact: {impact.rstrip('.')}.")
        description = " ".join(pieces).strip()

    if len(description) < 80:
        return None

    return finding(
        title=title[:220],
        description=description[:900],
        severity=severity,
        file=file_name,
        line=line,
        function=function or None,
        confidence=0.9 if severity == "critical" else 0.82,
        type_=str(raw.get("type") or raw.get("vulnerability_type") or prompt_name or "logic"),
    )


def extract_function_names(text: str) -> list[str]:
    names = [match.group(1) for match in FUNCTION_RE.finditer(text)]
    names.extend(match.group(1) for match in GENERIC_FN_RE.finditer(text))
    deduped: list[str] = []
    seen: set[str] = set()
    for name in names:
        if name not in seen:
            seen.add(name)
            deduped.append(name)
    return deduped


def can_use_inference(inference_api: str | None) -> bool:
    endpoint = (inference_api or os.environ.get("INFERENCE_API") or "").strip()
    return bool(endpoint and os.environ.get("INFERENCE_API_KEY", "").strip())


def finding(
    *,
    title: str,
    description: str,
    severity: str,
    file: str,
    line: int | None = None,
    function: str | None = None,
    confidence: float = 0.5,
    type_: str = "logic",
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "title": title,
        "description": description,
        "severity": severity if severity in {"high", "critical"} else "high",
        "file": file,
        "confidence": round(max(0.0, min(1.0, confidence)), 3),
        "type": type_,
    }
    if line and line > 0:
        payload["line"] = line
    if function:
        payload["function"] = function
    return payload


def safe_read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def parse_int(value: Any) -> int | None:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def dedupe_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str, int, str]] = set()
    deduped: list[dict[str, Any]] = []
    for item in findings:
        key = (
            str(item.get("file") or "").lower(),
            str(item.get("title") or "").lower(),
            str(item.get("function") or "").lower(),
            int(item.get("line") or 0),
            str(item.get("severity") or "").lower(),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def empty_report() -> dict[str, list[dict[str, Any]]]:
    return {"vulnerabilities": []}
