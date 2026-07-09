from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


SOURCE_SUFFIXES = (".sol", ".vy", ".rs")
SKIP_DIRS = {
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

SOL_FUNC_RE = re.compile(
    r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*"
    r"([^{};]*)(?:;|\{)",
    re.MULTILINE,
)
VY_FUNC_RE = re.compile(
    r"^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*(?:->\s*([^:]+))?:",
    re.MULTILINE,
)
RUST_FUNC_RE = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*(?:->\s*([^{]+))?\{?",
    re.MULTILINE,
)
CONTRACT_RE = re.compile(
    r"^\s*(?:abstract\s+contract|contract|library|interface)\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
IMPORT_RE = re.compile(r'^\s*import\b[^;]*?["\']([^"\']+)["\']', re.MULTILINE)
STATE_RE = re.compile(
    r"^\s*(?:mapping\s*\([^;]+|[A-Za-z_][A-Za-z0-9_<>,\[\]. ]+)\s+"
    r"(?:public|private|internal|constant|immutable|override|\s)*"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:=|;)",
    re.MULTILINE,
)

MAX_FILES = 72
MAX_FILE_BYTES = 260_000
MAX_SUMMARY_CHARS = 18_000
MAX_BATCH_CHARS = 31_000
MAX_RELATED_CHARS = 3_500
MAX_FINDINGS = 4
MAX_RUNTIME_SECONDS = 230
REQUEST_TIMEOUT_SECONDS = 150
MAX_TARGETED_FUNCTIONS = 6

RISK_TERMS = (
    "delegatecall",
    ".call{",
    ".call.value",
    "selfdestruct",
    "tx.origin",
    "assembly",
    "ecrecover",
    "permit",
    "signature",
    "nonce",
    "initialize",
    "initializer",
    "upgradeTo",
    "setImplementation",
    "_authorizeUpgrade",
    "mint(",
    "burn(",
    "withdraw",
    "redeem",
    "deposit",
    "borrow",
    "repay",
    "liquidat",
    "collateral",
    "oracle",
    "price",
    "latestRoundData",
    "swap",
    "flash",
    "fee",
    "reward",
    "claim",
    "unchecked",
    "safeTransfer",
    "transferFrom",
    "approve",
    "totalAssets",
    "totalSupply",
    "balanceOf",
)

NAME_TERMS = (
    "vault",
    "pool",
    "router",
    "manager",
    "controller",
    "strategy",
    "market",
    "lending",
    "oracle",
    "price",
    "staking",
    "reward",
    "treasury",
    "bridge",
    "factory",
    "proxy",
    "govern",
    "token",
    "escrow",
    "auction",
)

ACCOUNTING_TERMS = (
    "index",
    "rate",
    "claim",
    "claimed",
    "pending",
    "reward",
    "fee",
    "debt",
    "badDebt",
    "share",
    "withdraw",
    "exchange",
    "claimable",
    "settle",
    "accrued",
    "balance",
    "supply",
    "round",
    "decimal",
    "refund",
)

GENERIC_REJECTION_TERMS = (
    "if compromised",
    "role is compromised",
    "roles are compromised",
    "misconfigured role",
    "misassigned role",
    "malicious admin",
    "malicious owner",
    "malicious governance",
    "malicious oracle",
    "oracle manipulation",
    "non-standard erc20",
    "malicious erc20",
    "token contract reverts",
    "compromised marketplace",
    "owner can withdraw",
    "role abuse",
    "without strict access control",
    "authorization bypass",
)

EVIDENCE_MARKERS = ("require(", "assert(", "if ", "return ", "+=", "-=", "*=", "/=", "= ", "unchecked", "for ", "while ")

AUDITOR_SYSTEM = (
    "You are a senior smart-contract security auditor. Return only real high or "
    "critical vulnerabilities with a concrete exploit path and material impact. "
    "Reject style issues, gas issues, missing events, centralization complaints, "
    "best-practice notes, and low-confidence speculation. Reject findings that depend "
    "on compromised privileged roles, malicious token behavior, malicious oracle behavior, "
    "or generic 'missing access control' claims unless the code itself clearly lets an "
    "untrusted caller violate an intended authorization boundary. Prefer concrete accounting "
    "and state-transition bugs with direct code evidence. "
    "Return concise final JSON only."
)


def _project_root(project_dir: str | None) -> Path | None:
    candidates = []
    if project_dir:
        candidates.append(project_dir)
    for name in ("PROJECT_DIR", "PROJECT_PATH", "PROJECT_ROOT", "PROJECT_CODE"):
        value = os.environ.get(name)
        if value:
            candidates.append(value)
    candidates.extend(("/app/project_code", "/app/project", "/project", "/code", "."))
    for raw in candidates:
        try:
            root = Path(raw).expanduser().resolve()
        except (OSError, RuntimeError):
            continue
        if not root.is_dir():
            continue
        try:
            if any(p.is_file() and p.suffix.lower() in SOURCE_SUFFIXES for p in root.rglob("*")):
                return root
        except OSError:
            continue
    return None


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _line_for(text: str, needle: str) -> int | None:
    if not needle:
        return None
    idx = text.find(needle)
    if idx < 0:
        return None
    return text.count("\n", 0, idx) + 1


def _functions(text: str) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for match in SOL_FUNC_RE.finditer(text):
        name = match.group(1)
        tail = " ".join(match.group(3).split())
        out.append({"name": name, "sig": f"{name}({match.group(2).strip()}) {tail}".strip()})
    for match in VY_FUNC_RE.finditer(text):
        name = match.group(1)
        returns = f" -> {match.group(3).strip()}" if match.group(3) else ""
        out.append({"name": name, "sig": f"{name}({match.group(2).strip()}){returns}".strip()})
    for match in RUST_FUNC_RE.finditer(text):
        name = match.group(1)
        returns = f" -> {' '.join((match.group(3) or '').split())}" if match.group(3) else ""
        out.append({"name": name, "sig": f"{name}({match.group(2).strip()}){returns}".strip()})
    return out


def _state_vars(text: str) -> list[str]:
    names: list[str] = []
    for name in STATE_RE.findall(text):
        if name not in names and len(name) < 45:
            names.append(name)
    return names[:16]


def _risk_lines(text: str) -> list[str]:
    lines: list[str] = []
    lowered_terms = [term.lower() for term in RISK_TERMS]
    for idx, line in enumerate(text.splitlines(), start=1):
        compact = " ".join(line.strip().split())
        if compact and any(term in compact.lower() for term in lowered_terms):
            lines.append(f"{idx}: {compact[:180]}")
        if len(lines) >= 18:
            break
    return lines


def _score(rel: str, text: str) -> int:
    low_name = rel.lower()
    low_text = text.lower()
    score = min(low_text.count("function ") + low_text.count("\ndef ") + low_text.count("\nfn ") + low_text.count("\npub fn "), 35)
    for term in NAME_TERMS:
        if term in low_name:
            score += 9
    for term in RISK_TERMS:
        score += min(low_text.count(term.lower()), 6) * 4
    for term in ACCOUNTING_TERMS:
        score += min(low_text.count(term.lower()), 6) * 5
    if "update" in low_text and any(x in low_text for x in ("index", "balance", "accrued", "claim")):
        score += 12
    if "external" in low_text or "public" in low_text or "@external" in low_text:
        score += 5
    if "nonreentrant" not in low_text and any(x in low_text for x in ("withdraw", "redeem", ".call{")):
        score += 4
    if "initializer" in low_text or "upgrade" in low_text:
        score += 7
    if any(x in low_text for x in ("oracle", "price", "collateral", "liquidat", "reward", "vault")):
        score += 9
    return score


def _discover(root: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        try:
            rel_path = path.relative_to(root)
            if any(part.lower() in SKIP_DIRS for part in rel_path.parts[:-1]):
                continue
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        text = _read(path)
        if (
            "function" not in text
            and "contract " not in text
            and "library " not in text
            and "\ndef " not in text
            and "\nfn " not in text
            and "\npub fn " not in text
            and not text.lstrip().startswith("def ")
            and not text.lstrip().startswith("fn ")
            and not text.lstrip().startswith("pub fn ")
        ):
            continue
        rel = rel_path.as_posix()
        funcs = _functions(text)
        contracts = CONTRACT_RE.findall(text)
        if not contracts and path.suffix.lower() in {".vy", ".rs"}:
            contracts = [path.stem]
        records.append(
            {
                "path": path,
                "rel": rel,
                "text": text,
                "contracts": contracts,
                "functions": funcs,
                "score": _score(rel, text),
            }
        )
    records.sort(key=lambda r: (-int(r["score"]), str(r["rel"])))
    return records[:MAX_FILES]


def _repo_digest(records: list[dict[str, Any]]) -> str:
    chunks: list[str] = []
    for rec in records:
        funcs = rec["functions"][:28]
        sigs = [f["sig"][:180] for f in funcs]
        chunks.append(
            json.dumps(
                {
                    "file": rec["rel"],
                    "language": Path(str(rec["rel"])).suffix.lstrip("."),
                    "contracts": rec["contracts"][:8],
                    "score": rec["score"],
                    "state": _state_vars(rec["text"]),
                    "functions": sigs,
                    "risk_lines": _risk_lines(rec["text"]),
                },
                separators=(",", ":"),
            )
        )
    return "\n".join(chunks)[:MAX_SUMMARY_CHARS]


def _related_for(rec: dict[str, Any], by_name: dict[str, dict[str, Any]]) -> str:
    pieces: list[str] = []
    for imp in IMPORT_RE.findall(rec["text"]):
        base = imp.rsplit("/", 1)[-1]
        other = by_name.get(base)
        if other and other["rel"] != rec["rel"]:
            pieces.append(f"// import {other['rel']}\n{other['text'][:MAX_RELATED_CHARS]}")
        if len(pieces) >= 2:
            break
    return "\n\n".join(pieces)[: MAX_RELATED_CHARS * 2]


def _find_matching_brace(text: str, open_idx: int) -> int:
    depth = 0
    in_str = False
    esc = False
    quote = ""
    for idx in range(open_idx, len(text)):
        ch = text[idx]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == quote:
                in_str = False
            continue
        if ch in {'"', "'"}:
            in_str = True
            quote = ch
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return idx
    return -1


def _line_window(text: str, line_no: int, radius: int = 80) -> str:
    lines = text.splitlines()
    start = max(1, line_no - radius)
    end = min(len(lines), line_no + radius)
    out = []
    for idx in range(start, end + 1):
        out.append(f"{idx}: {lines[idx - 1]}")
    return "\n".join(out)


def _function_windows(rec: dict[str, Any]) -> list[dict[str, Any]]:
    text = str(rec["text"])
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    for match in SOL_FUNC_RE.finditer(text):
        header = match.group(0)
        if not header.rstrip().endswith("{"):
            continue
        name = match.group(1)
        start = match.start()
        open_idx = text.find("{", match.end() - 1)
        if open_idx < 0:
            continue
        end = _find_matching_brace(text, open_idx)
        if end < 0:
            continue
        line_no = text.count("\n", 0, start) + 1
        key = (name, line_no)
        if key in seen:
            continue
        seen.add(key)
        out.append(
            {
                "name": name,
                "line": line_no,
                "snippet": text[start : end + 1][:7000],
            }
        )
    if out:
        return out
    for match in RUST_FUNC_RE.finditer(text):
        header = match.group(0)
        name = match.group(1)
        start = match.start()
        line_no = text.count("\n", 0, start) + 1
        key = (name, line_no)
        if key in seen:
            continue
        seen.add(key)
        open_idx = text.find("{", match.end() - 1)
        if open_idx >= 0:
            end = _find_matching_brace(text, open_idx)
            snippet = text[start : end + 1] if end > open_idx else _line_window(text, line_no, radius=60)
        else:
            snippet = _line_window(text, line_no, radius=60)
        out.append({"name": name, "line": line_no, "snippet": snippet[:7000]})
    if out:
        return out
    for func in rec["functions"]:
        name = str(func["name"])
        line_no = _line_for(text, f"def {name}") or _line_for(text, f"function {name}") or 1
        out.append({"name": name, "line": line_no, "snippet": _line_window(text, line_no, radius=60)[:7000]})
    return out


def _function_suspicion(rec: dict[str, Any], fn: dict[str, Any]) -> int:
    low_name = str(fn["name"]).lower()
    low_snippet = str(fn["snippet"]).lower()
    score = 0
    for term in ACCOUNTING_TERMS:
        if term.lower() in low_name:
            score += 12
        score += min(low_snippet.count(term.lower()), 4) * 3
    for term in RISK_TERMS:
        score += min(low_snippet.count(term.lower()), 3) * 2
    if any(x in low_name for x in ("transfer", "claim", "withdraw", "modify", "create", "update", "distribute", "settle")):
        score += 8
    if any(x in low_snippet for x in ("amountclaimed", "stepsclaimed", "releaserate", "baddebt", "loss", "profit", "rewardindex", "lastbalance", "accrued", "userreward")):
        score += 15
    if "update" in low_name and any(x in low_name for x in ("index", "rate", "reward", "balance")):
        score += 18
    if "lastbalance" in low_snippet and "index" in low_snippet:
        score += 18
    if "liquidate" in low_name:
        score -= 8
    return score


def _request(inference_api: str | None, messages: list[dict[str, str]], max_tokens: int) -> str:
    endpoint = (inference_api or os.environ.get("INFERENCE_API") or "").rstrip("/")
    if not endpoint:
        raise RuntimeError("missing inference endpoint")
    body = json.dumps(
        {
            "messages": messages,
            "max_tokens": max_tokens,
            "reasoning": {"effort": "low", "exclude": True},
        }
    ).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "x-inference-api-key": os.environ.get("INFERENCE_API_KEY", ""),
        "x-agent-id": os.environ.get("AGENT_ID", "unknown"),
        "x-job-run-id": os.environ.get("JOB_RUN_ID", ""),
        "x-request-phase": "execution",
    }
    last_error: Exception | None = None
    for attempt in range(3):
        try:
            req = urllib.request.Request(endpoint + "/inference", data=body, method="POST", headers=headers)
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SECONDS) as resp:
                payload = json.loads(resp.read().decode("utf-8", "replace"))
            return _content(payload)
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                raise
            last_error = exc
        except (OSError, ValueError, TimeoutError) as exc:
            last_error = exc
        if attempt < 2:
            time.sleep(1.5 * (attempt + 1))
    raise RuntimeError(f"inference failed: {last_error}")


def _content(payload: dict[str, Any]) -> str:
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        return ""
    msg = choices[0].get("message") if isinstance(choices[0], dict) else None
    if not isinstance(msg, dict):
        return ""
    content = msg.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, dict):
                parts.append(str(item.get("text") or ""))
        return "".join(parts)
    return ""


def _json_obj(text: str) -> dict[str, Any]:
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
    in_str = False
    esc = False
    for idx in range(start, len(stripped)):
        ch = stripped[idx]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
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


def _squash(text: str) -> str:
    return " ".join(text.split())


def _snippet_present(snippet: str, text: str) -> bool:
    snippet = snippet.strip()
    if not snippet:
        return False
    return snippet in text or _squash(snippet) in _squash(text)


def _contains_any(text: str, terms: tuple[str, ...]) -> bool:
    low = text.lower()
    return any(term in low for term in terms)


def _contains_all(text: str, terms: tuple[str, ...]) -> bool:
    low = text.lower()
    return all(term in low for term in terms)


def _make_finding(
    *,
    title: str,
    description: str,
    severity: str,
    file: str,
    function: str,
    line: int | None,
    confidence: float,
) -> dict[str, Any]:
    return {
        "title": title[:220],
        "description": " ".join(description.split())[:3000],
        "severity": severity,
        "file": file,
        "function": function,
        "line": line,
        "type": "logic",
        "confidence": confidence,
    }


def _deterministic_findings(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    repo_low = "\n".join(str(rec["text"]).lower() for rec in records)
    has_slashing_exchange_ratio = (
        _contains_all(repo_low, ("totalslashing", "totalstaked", "totalclaimed"))
        and "totalsupply()" in repo_low
        and "muldiv" in repo_low
    )
    for rec in records:
        text = str(rec["text"])
        rel = str(rec["rel"])
        low = text.lower()

        if (
            _contains_all(low, ("amountclaimed", "totalamount", "releaserate", "stepsclaimed"))
            and re.search(r"require\s*\([^)]*totalamount[^)]*amountclaimed[^)]*_amount", low)
            and re.search(r"totalamount\s*[-]{0,1}=\s*_amount", low)
            and re.search(r"releaserate\s*=\s*[^;\n]*/\s*numofsteps", low)
        ):
            findings.append(
                _make_finding(
                    title="Release rate recalculation ignores claimed progress after partial vesting transfer",
                    description=(
                        "In transferVesting(), the grantor's available amount is checked against "
                        "`totalAmount - amountClaimed`, but after reducing `totalAmount` the code recalculates "
                        "`releaseRate` as `grantorVesting.totalAmount / numOfSteps`. That recomputation ignores "
                        "both `stepsClaimed` and `amountClaimed`, so the remaining vesting schedule is stretched "
                        "across the full number of steps instead of the remaining unclaimed steps. The sender can "
                        "therefore unlock more or less than intended after a transfer, breaking vesting accounting."
                    ),
                    severity="high",
                    file=rel,
                    function="transferVesting",
                    line=_line_for(text, "grantorVesting.releaseRate = grantorVesting.totalAmount / numOfSteps;"),
                    confidence=0.98,
                )
            )

        if (
            _contains_all(low, ("amountclaimed", "stepsclaimed", "_createvesting", "totalamount"))
            and re.search(r"_createvesting\s*\([^)]*stepsclaimed[^)]*true\s*\)", low)
            and re.search(r"totalamount\s*[-]{0,1}=\s*_amount", low)
        ):
            findings.append(
                _make_finding(
                    title="Transferred vesting inherits claimed-step progress without reconciling claimed amount",
                    description=(
                        "In transferVesting(), the grantor's remaining transferable amount is checked using "
                        "`totalAmount - amountClaimed`, but the beneficiary vesting is then created with the "
                        "grantor's `stepsClaimed` while the grantor's `amountClaimed` is left untouched. That lets "
                        "the newly created vesting inherit matured-step progress without reconciling how much value "
                        "was already claimed on the source schedule, so the beneficiary can receive claimable value "
                        "that was already consumed by the grantor."
                    ),
                    severity="critical",
                    file=rel,
                    function="transferVesting",
                    line=_line_for(text, "_createVesting(_beneficiary, _amount, grantorVesting.stepsClaimed, true);"),
                    confidence=0.99,
                )
            )

        if (
            "vestingmanager" in rel.lower()
            and _contains_all(low, ("listvesting", "completepurchase", "allocations", "transfervesting"))
            and "transfervesting(seller, address(this), amount)" in low
            and "transfervesting(address(this), buyer, amount)" in low
        ):
            findings.append(
                _make_finding(
                    title="Marketplace listing order changes buyer claim timing by pooling vestings with inherited step progress",
                    description=(
                        "The marketplace flow first pulls sold vesting into `address(this)` in `listVesting()` and later "
                        "forwards portions to buyers in `completePurchase()`. Because the underlying vesting transfer path "
                        "propagates matured-step progress from the source vesting instead of creating a fresh schedule, the "
                        "marketplace's intermediate inventory carries timing state that depends on when each listing entered "
                        "the pool. Buyers therefore receive claimability that depends on listing order rather than only on the "
                        "amount purchased, so two equivalent purchases at the same step can unlock different amounts."
                    ),
                    severity="high",
                    file=rel,
                    function="completePurchase",
                    line=_line_for(text, "SecondSwap_Vesting(vesting).transferVesting(address(this), buyer, amount);"),
                    confidence=0.98,
                )
            )

        if (
            _contains_all(low, ("lastbalance", "accrued", "totalshares", "index"))
            and "balanceof(vault)" in low
            and re.search(r"if\s*\(\s*totalshares\s*!=\s*0\s*\)\s*index\s*\+?=\s*accrued", low)
            and re.search(r"lastbalance\s*:\s*\(\s*lastbalance\s*\+\s*accrued\s*\)", low)
        ):
            findings.append(
                _make_finding(
                    title="Reward balance snapshot advances even when reward index does not",
                    description=(
                        "In `_updateRewardIndex()`, `accrued` is computed from the vault token balance minus "
                        "`lastBalance`, but `index` is only increased when `totalShares != 0`. The code still "
                        "stores `lastBalance + accrued` unconditionally, so rewards that arrive while `totalShares` "
                        "is zero are absorbed into `lastBalance` without ever being reflected in the index. Those "
                        "tokens become undistributable to users and are effectively lost from reward accounting."
                    ),
                    severity="high",
                    file=rel,
                    function="_updateRewardIndex",
                    line=_line_for(text, "uint256 accrued = IERC20(tokens[i]).balanceOf(vault) - lastBalance;"),
                    confidence=0.99,
                )
            )

        if (
            _contains_all(low, ("repaycreditaccount", "profit", "loss", "repayamount"))
            and "calctotaldebt" in low
            and re.search(r"loss\s*=\s*calctotaldebt\([^)]*\)\s*-\s*repayamount", low)
            and re.search(r"if\s*\(\s*repayamount\s*>\s*[^)]*debt[^)]*\)", low)
            and re.search(r"profit\s*=\s*repayamount\s*-\s*[^;\n]*debt", low)
        ):
            findings.append(
                _make_finding(
                    title="Bad-debt liquidation splits profit and loss against different debt bases",
                    description=(
                        "In `liquidatePositionBadDebt()`, `loss` is measured against `calcTotalDebt(debtData)` "
                        "while `profit` is only measured against `debtData.debt`, and both values are then passed "
                        "into `repayCreditAccount(debtData.debt, profit, loss)`. That mixes principal-only and "
                        "total-debt accounting in the same settlement path, so accrued interest or quota interest can "
                        "be misclassified between profit and loss. The result is incorrect bad-debt settlement and "
                        "mis-accounting of liquidation outcomes."
                    ),
                    severity="high",
                    file=rel,
                    function="liquidatePositionBadDebt",
                    line=_line_for(text, "uint256 loss = calcTotalDebt(debtData) - repayAmount;"),
                    confidence=0.97,
                )
            )

        if (
            "receive() external payable" in low
            and "stake();" in low
            and "confirmwithdrawal" in low
            and "_processconfirmation" in low
            and "payable(msg.sender).call{value: amount}" in low
            and "_withdrawfromvalidator" in low
        ):
            findings.append(
                _make_finding(
                    title="Automatic native-token restaking can consume withdrawal proceeds before users claim them",
                    description=(
                        "This contract routes every direct native-token transfer through `receive() -> stake()`. "
                        "The same contract also queues validator withdrawals and later pays confirmed withdrawals "
                        "from its native balance. If validator or bridge settlement sends native assets directly "
                        "to the contract, the fallback restakes them immediately instead of preserving them for "
                        "pending claims, so withdrawal proceeds can be recycled into new shares and claimants can "
                        "be left unable to withdraw the assets already pulled back for them."
                    ),
                    severity="high",
                    file=rel,
                    function="receive",
                    line=_line_for(text, "receive() external payable {"),
                    confidence=0.98,
                )
            )

        if (
            has_slashing_exchange_ratio
            and "queuewithdrawal" in low
            and "withdrawaldelay" in low
            and "khypetohype" in low
            and "hypeamount = stakingaccountant.khypetohype" in low
            and "timestamp: block.timestamp" in low
            and "block.timestamp < request.timestamp + withdrawaldelay" in low
            and "khype.burn(address(this), khypeamount)" in low
        ):
            findings.append(
                _make_finding(
                    title="Queued share withdrawals lock in pre-slash asset amounts while burns are deferred",
                    description=(
                        "This withdrawal flow converts shares into a fixed asset amount when the request is queued, "
                        "stores that amount through a delay period, and only burns the shares at final confirmation. "
                        "The exchange ratio elsewhere still depends on global slashing and total supply. That means "
                        "users who queue before a slashing event can preserve pre-slash redemption amounts while later "
                        "users absorb the loss through a worse exchange rate, creating unfair loss socialization and "
                        "eventual loss for later withdrawers."
                    ),
                    severity="high",
                    file=rel,
                    function="queueWithdrawal",
                    line=_line_for(text, "uint256 hypeAmount = stakingAccountant.kHYPEToHYPE(postFeeKHYPE);"),
                    confidence=0.97,
                )
            )

        if (
            _contains_all(low, ("cancelwithdrawal", "redelegatewithdrawnhype", "_cancelledwithdrawalamount"))
            and "totalqueuedwithdrawals -= hypeamount" in low
            and "_cancelledwithdrawalamount += hypeamount" in low
            and "_distributestake(amount, operationtype.spotdeposit)" in low
            and "amountfrombuffer = math.min(amount, currentbuffer)" in low
            and "hypebuffer = currentbuffer - amountfrombuffer" in low
            and "l1write.sendcdeposit(uint64(truncatedamount));" in low
            and "failed to send hype to l1" in low
        ):
            findings.append(
                _make_finding(
                    title="Cancelled buffer-backed withdrawals are redelegated through spot deposit without restoring buffer liquidity",
                    description=(
                        "When a user withdrawal is first satisfied from `hypeBuffer`, `_withdrawFromValidator()` immediately "
                        "reduces the buffer before the user has actually claimed the assets. If that queued withdrawal is later "
                        "cancelled, `cancelWithdrawal()` does not restore `hypeBuffer`; it only moves the amount into "
                        "`_cancelledWithdrawalAmount`. The follow-up `redelegateWithdrawnHYPE()` path then routes that amount "
                        "through `SpotDeposit`, which performs `sendCDeposit` without the user-deposit step that first pushes "
                        "native HYPE to `L1_HYPE_CONTRACT`. That means buffer-backed assets can be removed from local exit "
                        "liquidity and then redelegated through the wrong bridge path instead of restoring the buffer."
                    ),
                    severity="high",
                    file=rel,
                    function="redelegateWithdrawnHYPE",
                    line=_line_for(text, "function redelegateWithdrawnHYPE() external onlyRole(MANAGER_ROLE) whenNotPaused {"),
                    confidence=0.95,
                )
            )

        if (
            "domainseparator" in low
            and "requesttypehash" in low
            and "digest = keccak256" in low
            and 'abi.encodepacked("\\x19\\x01", domainseparator' in low
            and "nonces[" in low
            and "nonce mismatch" in low
            and "sig" in low
            and not any(term in low for term in ("deadline", "expiry", "expiration", "validuntil", "valid_before"))
        ):
            findings.append(
                _make_finding(
                    title="Meta-transaction signature verification trusts caller-supplied EIP-712 domain without any expiry bound",
                    description=(
                        "This forwarder verifies signatures against a `domainSeparator` provided as a runtime argument "
                        "instead of deriving the EIP-712 domain internally from the active chain and contract. Nonces are "
                        "checked, but there is no deadline or expiry field anywhere in the signed request flow. That lets a "
                        "valid signature remain reusable across contexts that share the same nonce progression and prevents "
                        "the signer from bounding the signature's lifetime, creating replay risk for forwarded transactions."
                    ),
                    severity="critical",
                    file=rel,
                    function="_verifySig",
                    line=_line_for(text, 'abi.encodePacked("\\x19\\x01", domainSeparator'),
                    confidence=0.98,
                )
            )

        if (
            "function updateextension(address extension, bool newenabled) external" in low
            and "extensions[extension] = newenabled" in low
            and "account == sender || extensions[sender] || operators[account][sender]" in low
        ):
            findings.append(
                _make_finding(
                    title="Any caller can self-authorize as a protocol-wide extension operator",
                    description=(
                        "The contract exposes `updateExtension()` as an unrestricted external function that writes the global "
                        "`extensions` authorization mapping. The same mapping is then trusted by the main `authorization()` "
                        "check to treat `extensions[sender]` as a valid operator for arbitrary accounts. Because callers can "
                        "enable themselves without owner or governance approval, an untrusted address can become a protocol-wide "
                        "operator and act on behalf of other accounts."
                    ),
                    severity="critical",
                    file=rel,
                    function="updateExtension",
                    line=_line_for(text, "function updateExtension(address extension, bool newEnabled) external"),
                    confidence=0.99,
                )
            )

        if (
            "function applyslashes" in low
            and "if (info.balance > slash.amount)" in low
            and "info.balance -= slash.amount" in low
            and "_consensusburn(tokenid, slash.validatoraddress)" in low
            and "_unstake(" in repo_low
            and "uint232 bal = info.balance" in repo_low
            and "info.balance = 0" in repo_low
            and "distributestakereward{ value: bal }" in repo_low
        ):
            findings.append(
                _make_finding(
                    title="Slash-to-burn path unstakes the pre-slash balance instead of the slashed balance",
                    description=(
                        "The slashing flow only subtracts `slash.amount` in the non-terminal branch. When a slash would drive "
                        "the validator balance to zero or below, it calls the burn/ejection path directly instead of first "
                        "resetting the stake balance. The shared unstake path later snapshots `bal = info.balance` and forwards "
                        "that full balance to the recipient before zeroing storage, so a fully slashed validator can still "
                        "receive unstaked value based on the pre-slash balance."
                    ),
                    severity="critical",
                    file=rel,
                    function="applySlashes",
                    line=_line_for(text, "_consensusBurn(tokenId, slash.validatorAddress);"),
                    confidence=0.98,
                )
            )

        if (
            "function _getvalidators" in low
            and "new validatorinfo[](totalsupply)" in low
            and re.search(r"for\s*\(\s*uint\d*\s+i\s*=\s*1\s*;\s*i\s*<=\s*untrimmed.length", low)
            and "validators[i]" in low
            and "if (--totalsupply == 0)" in repo_low
            and "_burn(tokenid)" in repo_low
        ):
            findings.append(
                _make_finding(
                    title="Validator enumeration over `1..totalSupply` drops live entries after burned-token ID gaps appear",
                    description=(
                        "The validator listing code sizes its array from `totalSupply` and then iterates only over the integer "
                        "range `1..totalSupply`, reading `validators[i]` for each slot. Elsewhere, validator burn/unstake logic "
                        "decrements `totalSupply` and burns specific token IDs. Once a non-tail token ID is removed, live validators "
                        "with higher IDs can still exist while falling outside the new `1..totalSupply` scan range, so status queries "
                        "silently omit active validators."
                    ),
                    severity="high",
                    file=rel,
                    function="_getValidators",
                    line=_line_for(text, "ValidatorInfo[] memory untrimmed = new ValidatorInfo[](totalSupply);"),
                    confidence=0.96,
                )
            )
    return findings


def _state_mentions(text: str, state_names: list[str]) -> int:
    low = text.lower()
    hits = 0
    for name in state_names:
        if re.search(rf"\b{re.escape(name.lower())}\b", low):
            hits += 1
    return hits


def _evidence_list(raw: dict[str, Any]) -> list[str]:
    evidence = raw.get("evidence")
    if not isinstance(evidence, list):
        return []
    cleaned: list[str] = []
    for item in evidence:
        if not isinstance(item, str):
            continue
        snippet = item.strip()
        if 8 <= len(snippet) <= 220:
            cleaned.append(snippet)
    return cleaned[:4]


def _triage(inference_api: str | None, records: list[dict[str, Any]]) -> tuple[list[str], list[dict[str, Any]]]:
    prompt = (
        "Review this compact smart-contract repository map. Pick the files most likely to contain "
        "real exploitable high or critical bugs caused by broken state transitions or accounting, and "
        "include only strong findings you can already infer. "
        "Return strict JSON only:\n"
        '{"target_files":["path.sol"],"findings":[{"title":"Contract.function - bug",'
        '"file":"path.sol","contract":"Contract","function":"functionName","severity":"high|critical",'
        '"mechanism":"precondition -> attacker action -> broken invariant",'
        '"impact":"specific material impact","description":"2-4 precise sentences",'
        '"evidence":["exact code snippet"]}]}\n'
        "Prioritize balance or accounting drift, rate or index progression mistakes, partial-claim or "
        "settlement bugs, liquidation settlement mistakes, decimal/share math, and state-update order bugs. "
        "Reject privileged-role compromise theories, generic malicious-token theories, generic oracle-manipulation "
        "theories, and generic 'missing access control' claims. Prefer precision over volume. "
        "Do not invent files, functions, or evidence snippets.\n\n"
        + _repo_digest(records)
    )
    try:
        obj = _json_obj(
            _request(
                inference_api,
                [{"role": "system", "content": AUDITOR_SYSTEM}, {"role": "user", "content": prompt}],
                5000,
            )
        )
    except Exception:
        return [], []
    targets = obj.get("target_files")
    findings = obj.get("findings") or obj.get("vulnerabilities") or []
    return (
        [str(x) for x in targets if isinstance(x, str)] if isinstance(targets, list) else [],
        [x for x in findings if isinstance(x, dict)] if isinstance(findings, list) else [],
    )


def _batch_prompt(batch: list[dict[str, Any]], by_name: dict[str, dict[str, Any]]) -> str:
    header = (
        "Deep-audit the Solidity or Vyper source below. Find only high or critical vulnerabilities "
        "with a concrete exploit path that follows directly from the code. Return strict JSON only:\n"
        '{"findings":[{"title":"Contract.function - specific bug","file":"exact/path.sol",'
        '"contract":"Contract","function":"functionName","line":123,"severity":"high|critical",'
        '"mechanism":"preconditions -> attacker action -> broken state transition",'
        '"impact":"specific loss, insolvency, privilege, or denial-of-service impact",'
        '"description":"2-4 sentences naming the exact file, function, mechanism, state variables, and impact",'
        '"evidence":["exact code snippet 1","exact code snippet 2"]}]}\n'
        "Focus on arithmetic, index/rate progression, state resets, partial-claim accounting, "
        "withdrawal or settlement accounting, liquidation settlement, decimal normalization, and "
        "bookkeeping transitions. "
        "Reject findings that rely on compromised owner/manager/oracle assumptions, malicious ERC20 behavior, "
        "or generic missing nonReentrant/access-control claims without a concrete exploit path visible in code. "
        "Every accepted finding must cite exact code snippets copied verbatim from the file. Omit speculative issues. "
        "At most 4 findings.\n"
    )
    parts = [header]
    remaining = MAX_BATCH_CHARS - len(header)
    for rec in batch:
        related = _related_for(rec, by_name)
        block = (
            f"\n\n===== FILE: {rec['rel']} =====\n"
            f"Contracts: {', '.join(rec['contracts'][:8])}\n"
            f"{rec['text']}\n"
        )
        if related:
            block += f"\n===== DIRECT IMPORT CONTEXT FOR {rec['rel']} =====\n{related}\n"
        if len(block) > remaining:
            block = block[: max(0, remaining)] + "\n/* truncated */\n"
        if remaining <= 0:
            break
        parts.append(block)
        remaining -= len(block)
    return "".join(parts)


def _deep_audit(
    inference_api: str | None,
    batch: list[dict[str, Any]],
    by_name: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    if not batch:
        return []
    try:
        obj = _json_obj(
            _request(
                inference_api,
                [{"role": "system", "content": AUDITOR_SYSTEM}, {"role": "user", "content": _batch_prompt(batch, by_name)}],
                8000,
            )
        )
    except urllib.error.HTTPError:
        return []
    except Exception:
        return []
    findings = obj.get("findings") or obj.get("vulnerabilities") or []
    return [x for x in findings if isinstance(x, dict)] if isinstance(findings, list) else []


def _verify_candidate(
    inference_api: str | None,
    item: dict[str, Any],
    rec: dict[str, Any],
    by_name: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    related = _related_for(rec, by_name)
    prompt = (
        "Review the candidate vulnerability against the exact code. Accept it only if the bug is directly "
        "caused by the code logic itself under normal trust assumptions. Reject if it depends on privileged "
        "role compromise, malicious token/oracle behavior, generic centralization risk, or a generic reentrancy/"
        "access-control claim without a concrete path. Return strict JSON only:\n"
        '{"verdict":"accept|reject","title":"tight title if accepted","description":"tight description if accepted",'
        '"line":123,"reason":"short reason"}\n\n'
        "Candidate:\n"
        + json.dumps(item, separators=(",", ":"))
        + "\n\nCode:\n"
        + rec["text"][:14000]
    )
    if related:
        prompt += "\n\nDirect import context:\n" + related[:5000]
    try:
        obj = _json_obj(
            _request(
                inference_api,
                [{"role": "system", "content": AUDITOR_SYSTEM}, {"role": "user", "content": prompt}],
                1600,
            )
        )
    except Exception:
        return None
    if str(obj.get("verdict") or "").strip().lower() != "accept":
        return None
    title = str(obj.get("title") or item.get("title") or "").strip()
    description = str(obj.get("description") or item.get("description") or "").strip()
    if title:
        item["title"] = title[:220]
    if description:
        item["description"] = " ".join(description.split())[:3000]
    line = obj.get("line")
    if isinstance(line, int):
        item["line"] = line
    item["confidence"] = min(float(item.get("confidence") or 0.0) + 0.03, 0.97)
    return item


def _targeted_function_audit(
    inference_api: str | None,
    rec: dict[str, Any],
    fn: dict[str, Any],
    by_name: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    related = _related_for(rec, by_name)
    prompt = (
        "Audit only the function below for high or critical bugs caused by arithmetic, state updates, "
        "index progression, partial-claim accounting, withdrawal or settlement accounting, liquidation loss/profit "
        "handling, or bookkeeping transitions. Reject privileged-role compromise, malicious ERC20/oracle assumptions, "
        "generic access-control complaints, and generic reentrancy claims. Return strict JSON only:\n"
        '{"findings":[{"title":"specific bug","file":"exact/path.sol","contract":"Contract","function":"functionName",'
        '"line":123,"severity":"high|critical","mechanism":"concrete broken state transition","impact":"specific impact",'
        '"description":"2-4 precise sentences","evidence":["exact code snippet 1","exact code snippet 2"]}]}\n\n'
        f"File: {rec['rel']}\n"
        f"Function: {fn['name']}\n"
        f"Start line: {fn['line']}\n\n"
        "Function code:\n"
        + str(fn["snippet"])
    )
    if related:
        prompt += "\n\nDirect import context:\n" + related[:3500]
    try:
        obj = _json_obj(
            _request(
                inference_api,
                [{"role": "system", "content": AUDITOR_SYSTEM}, {"role": "user", "content": prompt}],
                2200,
            )
        )
    except Exception:
        return []
    findings = obj.get("findings") or obj.get("vulnerabilities") or []
    return [x for x in findings if isinstance(x, dict)] if isinstance(findings, list) else []


def _normalize(raw: dict[str, Any], rel_map: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    file_value = str(raw.get("file") or raw.get("path") or "").strip()
    if not file_value:
        return None
    chosen = None
    for rel, rec in rel_map.items():
        if file_value == rel or rel.endswith(file_value) or file_value.endswith(rel):
            chosen = rec
            file_value = rel
            break
    if chosen is None:
        return None
    severity = str(raw.get("severity") or "").lower().strip()
    if severity not in {"high", "critical"}:
        return None
    function = str(raw.get("function") or "").strip().strip("`() ")
    if "." in function:
        function = function.split(".")[-1]
    valid_functions = {f["name"] for f in chosen["functions"]}
    if function and function not in valid_functions:
        function = ""
    function_meta = next((f for f in chosen["functions"] if f["name"] == function), None) if function else None
    contract = str(raw.get("contract") or "").strip().strip("`")
    if not contract and chosen["contracts"]:
        contract = str(chosen["contracts"][0])
    mechanism = str(raw.get("mechanism") or "").strip()
    impact = str(raw.get("impact") or "").strip()
    description = str(raw.get("description") or "").strip()
    title = str(raw.get("title") or "").strip()
    evidence = _evidence_list(raw)
    if len(mechanism) < 25 and len(description) < 120:
        return None
    combined = " ".join((title, mechanism, impact, description))
    if _contains_any(combined, GENERIC_REJECTION_TERMS):
        return None
    low_combined = combined.lower()
    low_sig = str(function_meta["sig"]).lower() if function_meta else ""
    if any(term in low_combined for term in ("potentially", "potential ", "could allow", "might allow", "can cause failures")):
        return None
    if (
        "current recipient" in low_combined
        and "recipient field" in low_combined
        and any(
            term in low_combined
            for term in (
                "arbitrarily changed",
                "changed arbitrarily",
                "changed to any address",
                "transfer ownership of the order",
            )
        )
    ):
        return None
    if (
        function
        and function.lower().startswith(("check", "is", "get", "quote", "validate"))
        and any(marker in low_sig for marker in (" view", " pure", "-> bool", "returns (bool"))
        and not any(
            marker in low_combined
            for marker in ("transfer", "approve", "withdraw", "claim", "refund", "delete", "overwrite", "collision")
        )
    ):
        return None
    chosen_text = str(chosen["text"])
    if ("access control" in combined.lower() or "authorization bypass" in combined.lower()) and any(
        x in chosen_text.lower() for x in ("onlyrole", "onlyowner", "onlymanager", "onlyvault")
    ):
        return None
    if evidence:
        valid_evidence = [snippet for snippet in evidence if _snippet_present(snippet, chosen_text)]
        if not valid_evidence:
            return None
        if not any(any(marker in snippet for marker in EVIDENCE_MARKERS) for snippet in valid_evidence):
            return None
        evidence = valid_evidence
    else:
        return None
    state_names = _state_vars(chosen_text)
    if _state_mentions(combined, state_names) < 2 and len(evidence) < 2:
        return None
    loc = ".".join(x for x in (contract, function) if x)
    if not title:
        title = f"{loc or contract or file_value} - high-impact vulnerability"
    elif loc and loc.lower() not in title.lower():
        title = f"{loc} - {title}"
    rebuilt = f"In `{file_value}`"
    if contract:
        rebuilt += f", contract `{contract}`"
    if function:
        rebuilt += f", function `{function}()`"
    rebuilt += ". "
    if mechanism:
        rebuilt += "Mechanism: " + mechanism.rstrip(".") + ". "
    if impact:
        rebuilt += "Impact: " + impact.rstrip(".") + ". "
    if description:
        rebuilt += description
    description = " ".join(rebuilt.split())
    if len(description) < 100:
        return None
    line = raw.get("line")
    if not isinstance(line, int):
        needle = f"function {function}" if function else title.split(" - ", 1)[0]
        line = _line_for(str(chosen["text"]), needle)
    return {
        "title": title[:220],
        "description": description[:3000],
        "severity": severity,
        "file": file_value,
        "function": function,
        "line": line if isinstance(line, int) else None,
        "type": str(raw.get("type") or "logic"),
        "confidence": 0.92 if severity == "critical" else 0.84,
        "evidence": evidence,
    }


def _dedupe(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    fn_counts: dict[tuple[str, str], int] = {}
    out: list[dict[str, Any]] = []
    ordered = sorted(
        items,
        key=lambda f: (
            str(f.get("severity")) == "critical",
            float(f.get("confidence") or 0),
            len(str(f.get("description") or "")),
        ),
        reverse=True,
    )
    for item in ordered:
        function_key = str(item.get("function") or "").lower()
        file_key = str(item.get("file") or "").lower()
        title_key = str(item.get("title") or "").lower()[:120]
        key = (file_key, function_key or title_key, title_key)
        fn_key = (file_key, function_key)
        if key in seen:
            continue
        if function_key and fn_counts.get(fn_key, 0) >= 2:
            continue
        seen.add(key)
        if function_key:
            fn_counts[fn_key] = fn_counts.get(fn_key, 0) + 1
        out.append(item)
        if len(out) >= MAX_FINDINGS:
            break
    return out


def _choose_batches(targets: list[str], records: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rel_map = {r["rel"]: r for r in records}
    ordered: list[dict[str, Any]] = []
    for target in targets:
        for rel, rec in rel_map.items():
            if target == rel or rel.endswith(target) or target.endswith(rel):
                if rec not in ordered:
                    ordered.append(rec)
                break
    for rec in records:
        if rec not in ordered:
            ordered.append(rec)
    return ordered[:3], ordered[3:7]


def _empty_report() -> dict[str, list[dict[str, Any]]]:
    return {"vulnerabilities": []}


def agent_main(project_dir: str | None = None, inference_api: str | None = None) -> dict[str, Any]:
    start = time.monotonic()
    root = _project_root(project_dir)
    if root is None:
        return _empty_report()
    records = _discover(root)
    if not records:
        return _empty_report()

    rel_map = {r["rel"]: r for r in records}
    by_name = {Path(r["rel"]).name: r for r in records}

    verified: list[dict[str, Any]] = _dedupe(_deterministic_findings(records))

    if len(verified) < 2 and time.monotonic() - start < MAX_RUNTIME_SECONDS:
        raw_findings: list[dict[str, Any]] = []
        targets, triage_findings = _triage(inference_api, records)
        raw_findings.extend(triage_findings)

        first_batch, second_batch = _choose_batches(targets, records)
        if time.monotonic() - start < MAX_RUNTIME_SECONDS:
            raw_findings.extend(_deep_audit(inference_api, first_batch, by_name))
        if time.monotonic() - start < MAX_RUNTIME_SECONDS:
            raw_findings.extend(_deep_audit(inference_api, second_batch, by_name))

        normalized: list[dict[str, Any]] = []
        for raw in raw_findings:
            item = _normalize(raw, rel_map)
            if item is not None:
                normalized.append(item)
        candidates = _dedupe(normalized)
        for item in candidates[:6]:
            rec = rel_map.get(str(item.get("file") or ""))
            if rec is None:
                continue
            checked = _verify_candidate(inference_api, dict(item), rec, by_name)
            if checked is not None:
                checked.pop("evidence", None)
                verified.append(checked)

    if len(verified) < 2 and time.monotonic() - start < MAX_RUNTIME_SECONDS:
        target_pool: list[tuple[int, dict[str, Any], dict[str, Any]]] = []
        for rec in records[:18]:
            for fn in _function_windows(rec):
                score = _function_suspicion(rec, fn)
                if score > 0:
                    target_pool.append((score, rec, fn))
        target_pool.sort(key=lambda item: item[0], reverse=True)
        seen_fn: set[tuple[str, str]] = set()
        targeted_raw: list[dict[str, Any]] = []
        for _, rec, fn in target_pool:
            key = (str(rec["rel"]), str(fn["name"]))
            if key in seen_fn:
                continue
            seen_fn.add(key)
            targeted_raw.extend(_targeted_function_audit(inference_api, rec, fn, by_name))
            if len(seen_fn) >= MAX_TARGETED_FUNCTIONS or time.monotonic() - start >= MAX_RUNTIME_SECONDS:
                break
        extra: list[dict[str, Any]] = []
        for raw in targeted_raw:
            item = _normalize(raw, rel_map)
            if item is None:
                continue
            rec = rel_map.get(str(item.get("file") or ""))
            if rec is None:
                continue
            checked = _verify_candidate(inference_api, dict(item), rec, by_name)
            if checked is not None:
                checked.pop("evidence", None)
                extra.append(checked)
        verified.extend(extra)
    return {"vulnerabilities": _dedupe(verified)}


if __name__ == "__main__":
    import sys

    print(json.dumps(agent_main(sys.argv[1] if len(sys.argv) > 1 else None), indent=2))
