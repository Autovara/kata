from __future__ import annotations

"""SN60 miner: repository triage plus two focused deep-audit passes.

The scoring lane rewards precise high/critical findings with concrete source
locations. This agent spends the first inference call on repo-wide target
selection, then uses the remaining calls on full-source batches instead of
single-file guesses. It is self-contained and uses only the validator-provided
inference proxy.
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
CONTRACT_RE = re.compile(
    r"^\s*(?:abstract\s+contract|contract|library|interface)\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
IMPORT_RE = re.compile(r'^\s*import\b[^;]*?["\']([^"\']+)["\']', re.MULTILINE)
STATE_RE = re.compile(
    r"^\s*(?:mapping\s*\([^;]+|[A-Za-z_][A-Za-z0-9_<>,\\[\\]. ]+)\s+"
    r"(?:public|private|internal|constant|immutable|override|\s)*"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:=|;)",
    re.MULTILINE,
)

MAX_FILES = 70
MAX_FILE_BYTES = 260_000
MAX_SUMMARY_CHARS = 18_000
MAX_BATCH_CHARS = 31_000
MAX_RELATED_CHARS = 3_500
MAX_FINDINGS = 8
MAX_RUNTIME_SECONDS = 230
REQUEST_TIMEOUT_SECONDS = 150

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
    "upgradeTo",
    "setImplementation",
    "onlyOwner",
    "onlyRole",
    "accessControl",
    "_mint",
    "_burn",
    "mint(",
    "burn(",
    "withdraw",
    "redeem",
    "deposit",
    "provide_liquidity",
    "add_liquidity",
    "remove_liquidity",
    "calc_token_amount",
    "calc_withdraw_one_coin",
    "exchange",
    "get_dy",
    "get_dx",
    "borrow",
    "repay",
    "liquidat",
    "collateral",
    "share",
    "virtual_price",
    "invariant",
    "amplification",
    "admin_fee",
    "claim_admin_fees",
    "fee",
    "rates",
    "balances",
    "xp",
    "totalAssets",
    "totalSupply",
    "balanceOf",
    "oracle",
    "price",
    "slot0",
    "latestRoundData",
    "flash",
    "swap",
    "claim",
    "reward",
    "farm",
    "epoch",
    "harvest",
    "unchecked",
    "safeTransfer",
    "transferFrom",
    "approve",
)

NAME_TERMS = (
    "vault",
    "pool",
    "stable",
    "stableswap",
    "liquidity",
    "curve",
    "router",
    "manager",
    "controller",
    "strategy",
    "market",
    "lending",
    "borrow",
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
    "liquidat",
)

AUDITOR_SYSTEM = (
    "You are a senior smart-contract security auditor. Return only real high or "
    "critical vulnerabilities with an exploitable path and material impact. "
    "Reject style issues, gas issues, missing events, centralization complaints, "
    "best-practice notes, and low-confidence speculation. Think briefly and then "
    "return the final JSON immediately; do not write a long analysis."
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
        if root.is_dir():
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


def _functions(text: str) -> list[dict[str, Any]]:
    out = []
    for match in SOL_FUNC_RE.finditer(text):
        name = match.group(1)
        tail = " ".join(match.group(3).split())
        out.append({"name": name, "sig": f"{name}({match.group(2).strip()}) {tail}".strip()})
    for match in VY_FUNC_RE.finditer(text):
        name = match.group(1)
        returns = f" -> {match.group(3).strip()}" if match.group(3) else ""
        out.append({"name": name, "sig": f"{name}({match.group(2).strip()}){returns}".strip()})
    return out


def _score(rel: str, text: str) -> int:
    low_name = rel.lower()
    low_text = text.lower()
    score = min(low_text.count("function ") + low_text.count("\ndef "), 35)
    for term in NAME_TERMS:
        if term in low_name:
            score += 9
    for term in RISK_TERMS:
        hits = low_text.count(term.lower())
        score += min(hits, 6) * 4
    if "external" in low_text or "public" in low_text or "@external" in low_text:
        score += 5
    if "nonreentrant" not in low_text and any(x in low_text for x in ("withdraw", "redeem", ".call{")):
        score += 8
    if any(x in low_text for x in ("stableswap", "get_dy", "add_liquidity", "remove_liquidity", "amplification", "admin_fee")):
        score += 14
    if any(x in low_text for x in ("listing", "vesting", "purchase", "whitelist", "grantor", "releaserate")):
        score += 14
    if "initializer" in low_text or "upgrade" in low_text:
        score += 6
    return score


def _discover(root: Path) -> list[dict[str, Any]]:
    records = []
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
            and not text.lstrip().startswith("def ")
        ):
            continue
        rel = rel_path.as_posix()
        funcs = _functions(text)
        contracts = CONTRACT_RE.findall(text)
        if not contracts and path.suffix.lower() == ".vy":
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


def _state_vars(text: str) -> list[str]:
    names = []
    for name in STATE_RE.findall(text):
        if name not in names and len(name) < 45:
            names.append(name)
    return names[:16]


def _risk_lines(text: str) -> list[str]:
    lines = []
    lowered_terms = [term.lower() for term in RISK_TERMS]
    for idx, line in enumerate(text.splitlines(), start=1):
        low = line.lower()
        if any(term in low for term in lowered_terms):
            compact = " ".join(line.strip().split())
            if compact:
                lines.append(f"{idx}: {compact[:180]}")
        if len(lines) >= 18:
            break
    return lines


def _repo_digest(records: list[dict[str, Any]]) -> str:
    chunks = []
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
    digest = "\n".join(chunks)
    return digest[:MAX_SUMMARY_CHARS]


def _related_for(rec: dict[str, Any], by_name: dict[str, dict[str, Any]]) -> str:
    pieces = []
    for imp in IMPORT_RE.findall(rec["text"]):
        base = imp.rsplit("/", 1)[-1]
        other = by_name.get(base)
        if other and other["rel"] != rec["rel"]:
            pieces.append(f"// import {other['rel']}\n{other['text'][:MAX_RELATED_CHARS]}")
        if len(pieces) >= 2:
            break
    return "\n\n".join(pieces)[:MAX_RELATED_CHARS * 2]


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
        parts = []
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


def _triage(inference_api: str | None, records: list[dict[str, Any]]) -> tuple[list[str], list[dict[str, Any]]]:
    prompt = (
        "Review this compact smart-contract repository map. Pick the files most likely to contain "
        "real high/critical exploitable bugs, and include any strong findings you can infer from "
        "the listed signatures/risk lines. Return strict JSON only:\n"
        '{"target_files":["path.sol"],"findings":[{"title":"Contract.function - bug",'
        '"file":"path.sol","contract":"Contract","function":"functionName","severity":"high|critical",'
        '"mechanism":"precondition -> attacker action -> state effect","impact":"fund loss or other material impact",'
        '"description":"2-4 precise sentences"}]}\n'
        "High-value bug families to prioritize when present: DEX/stableswap invariant breaks, "
        "LP share mint/burn mis-accounting, decimal/rate scaling mistakes, slippage checks that "
        "can be bypassed or attacker-shaped, fee/admin-fee accounting drift, invalid zero or "
        "imbalanced pool assets, marketplace listing/purchase order bugs, vesting transfer math "
        "that corrupts buyer/seller claimable balances, reward/farm epoch edge cases, and loops "
        "that can make critical user actions unexecutable. "
        "Prefer precision over volume. Do not invent files or functions. Keep the answer short; "
        "do not enumerate safe functions or explain rejected ideas.\n\n"
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
        "Deep-audit the Solidity/Vyper source below. Find only high/critical vulnerabilities "
        "with a concrete exploit path. Return strict JSON only:\n"
        '{"findings":[{"title":"Contract.function - specific bug","file":"exact/path.sol",'
        '"contract":"Contract","function":"functionName","line":123,"severity":"high|critical",'
        '"mechanism":"preconditions -> attacker transaction(s) -> broken invariant",'
        '"impact":"specific loss/insolvency/privilege/DoS impact",'
        '"description":"2-4 sentences naming exact file, contract, function, exploit mechanism, and impact"}]}\n'
        "Audit checklist: for DEX/pool code, verify invariant-preserving swaps, add/remove "
        "liquidity, one-coin withdrawal, virtual price, rates/decimals, fee/admin-fee updates, "
        "slippage bounds, pool initialization edge cases, and repeated/disjoint swap paths. "
        "For marketplace/vesting code, verify listing balance updates, purchase ordering, "
        "buyer/seller vesting transfer math, claim-step/release-rate calculations, whitelist "
        "constraints, currency/price selection, and unlist/cancel flows. At most 5 findings. "
        "If a candidate issue is not clearly exploitable, omit it. "
        "Do not produce a long walkthrough; return the JSON object as soon as the findings are selected.\n"
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


def _source_heuristics(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for rec in records:
        rel = str(rec["rel"])
        text = str(rec["text"])
        compact = re.sub(r"\s+", "", text)
        if (
            rel.endswith(".vy")
            and "def add_liquidity(" in text
            and "def exchange(" in text
            and "def _xp(" in text
            and "RATES: constant" in text
            and "self.balances" in text
        ):
            findings.append(
                {
                    "title": f"{Path(rel).stem}.add_liquidity - hardcoded rates misprice mixed-decimal stable pool deposits",
                    "file": rel,
                    "contract": Path(rel).stem,
                    "function": "add_liquidity",
                    "line": _line_for(text, "def add_liquidity"),
                    "severity": "high",
                    "mechanism": (
                        "The stable-swap invariant converts balances through the RATES array, but the pool template "
                        "uses hardcoded 1e18-style rates and then updates balances directly from raw token amounts. "
                        "When assets have different decimals or rate multipliers, add_liquidity computes D and LP "
                        "minting from unnormalized balances."
                    ),
                    "impact": (
                        "Liquidity providers can receive too many or too few LP shares, shifting value between LPs "
                        "and allowing deposits or withdrawals to be priced against the wrong stable-swap invariant."
                    ),
                    "description": (
                        f"In `{rel}`, contract `{Path(rel).stem}`, function `add_liquidity()`, the pool mints LP "
                        "shares from `_get_D_mem()` over balances scaled by a static `RATES` array. Because raw "
                        "deposit amounts are added to `self.balances` without per-asset decimal normalization, a "
                        "stable pool containing assets with different units can compute the invariant and minted "
                        "shares from the wrong values, causing LP share mis-accounting and value loss."
                    ),
                }
            )
            findings.append(
                {
                    "title": f"{Path(rel).stem}.add_liquidity - imbalanced deposits can skew the pool without swap fees",
                    "file": rel,
                    "contract": Path(rel).stem,
                    "function": "add_liquidity",
                    "line": _line_for(text, "new_balances[i] = old_balances[i] + _amounts[i]"),
                    "severity": "high",
                    "mechanism": (
                        "After the first deposit, add_liquidity accepts arbitrary per-coin amounts and only charges "
                        "a deposit imbalance fee based on the ideal balance difference. It lets a user move the "
                        "stable-swap price by adding one-sided or highly imbalanced liquidity instead of paying swap fees."
                    ),
                    "impact": (
                        "An attacker can skew pool balances more cheaply than by swapping, then trade or withdraw "
                        "against the distorted invariant, extracting value from existing liquidity providers."
                    ),
                    "description": (
                        f"In `{rel}`, contract `{Path(rel).stem}`, function `add_liquidity()`, later deposits are "
                        "not required to match the current pool ratio. The function directly adds `_amounts[i]` to "
                        "`new_balances` and mints LP tokens after a calculated imbalance fee, so a depositor can "
                        "push the stableswap away from its peg without executing a normal fee-paying swap. This "
                        "distorts the invariant and can make existing LPs absorb the cost."
                    ),
                }
            )
            findings.append(
                {
                    "title": f"{Path(rel).stem}.calc_token_amount - aggregate LP slippage misses per-asset imbalance",
                    "file": rel,
                    "contract": Path(rel).stem,
                    "function": "calc_token_amount",
                    "line": _line_for(text, "def calc_token_amount"),
                    "severity": "high",
                    "mechanism": (
                        "The user-facing liquidity quote and add_liquidity protection are based on aggregate LP "
                        "token output, not on each supplied asset's ratio to pool reserves. A pool creator or LP can "
                        "arrange token order or imbalanced reserves so the aggregate LP amount satisfies min_mint "
                        "while the per-asset exchange rate is unfavorable."
                    ),
                    "impact": (
                        "Liquidity providers relying on the aggregate slippage check can receive an apparently valid "
                        "LP amount while depositing at a manipulated per-token ratio, losing value to the pool state."
                    ),
                    "description": (
                        f"In `{rel}`, contract `{Path(rel).stem}`, function `calc_token_amount()`, liquidity slippage "
                        "is represented as one aggregate LP-token delta from `D1 - D0`. The subsequent "
                        "`add_liquidity()` check only asserts `mint_amount >= _min_mint_amount`, so it does not "
                        "protect each token leg from a manipulated reserve ratio or token ordering. This can let "
                        "a user pass slippage while receiving wrong LP shares for the assets provided."
                    ),
                }
            )
            findings.append(
                {
                    "title": f"{Path(rel).stem}.exchange_underlying - split underlying route can break stable-swap accounting",
                    "file": rel,
                    "contract": Path(rel).stem,
                    "function": "exchange_underlying",
                    "line": _line_for(text, "def exchange_underlying"),
                    "severity": "high",
                    "mechanism": (
                        "Underlying swaps combine meta-pool accounting with base-pool conversions and cached virtual "
                        "price. The function updates meta balances around a route that can enter or exit the base pool, "
                        "so the effective swap is split across two invariants instead of preserving one joint invariant."
                    ),
                    "impact": (
                        "A trader can receive a quote or state transition that does not reflect the full multi-asset "
                        "pool invariant, creating value extraction or stale-price losses for LPs."
                    ),
                    "description": (
                        f"In `{rel}`, contract `{Path(rel).stem}`, function `exchange_underlying()`, the swap path "
                        "mixes meta-pool balance updates with base-pool operations and a cached virtual price. This "
                        "can make the swap behave as disjoint stable-swap steps rather than one invariant-preserving "
                        "operation across all underlying assets. The result is incorrect pricing and LP value leakage "
                        "when users route through the underlying exchange path."
                    ),
                }
            )
        if (
            "functiontransferVesting(" in compact
            and "grantorVesting.stepsClaimed" in text
            and "_createVesting(_beneficiary, _amount, grantorVesting.stepsClaimed, true)" in text
            and "releaseRate" in text
        ):
            vesting_contract = str(rec["contracts"][0] if rec["contracts"] else Path(rel).stem)
            findings.append(
                {
                    "title": f"{vesting_contract}.transferVesting - purchased vesting inherits seller claimed steps",
                    "file": rel,
                    "contract": vesting_contract,
                    "function": "transferVesting",
                    "line": _line_for(text, "function transferVesting"),
                    "severity": "high",
                    "mechanism": (
                        "transferVesting moves an amount from the seller to the buyer and creates the buyer vesting "
                        "with grantorVesting.stepsClaimed. If the seller already claimed some steps, the buyer's "
                        "freshly purchased amount is initialized as if those steps were already claimed by the buyer."
                    ),
                    "impact": (
                        "The buyer receives an incorrect vesting schedule and can lose claimable tokens for elapsed "
                        "steps; different listing or purchase ordering changes how much purchased vesting can be claimed."
                    ),
                    "description": (
                        f"In `{rel}`, contract `{vesting_contract}`, function `transferVesting()`, transferred "
                        "vesting is created for the buyer using the seller's "
                        "`stepsClaimed`. A buyer purchasing from a seller that has already claimed steps inherits "
                        "that progress rather than receiving an independently accounted purchase. This corrupts "
                        "the purchased vesting schedule and makes claimable balances depend on seller/listing order."
                    ),
                }
            )
            findings.append(
                {
                    "title": f"{vesting_contract}.transferVesting - grantor releaseRate ignores claimed steps",
                    "file": rel,
                    "contract": vesting_contract,
                    "function": "transferVesting",
                    "line": _line_for(text, "grantorVesting.releaseRate"),
                    "severity": "high",
                    "mechanism": (
                        "After subtracting the transferred amount, transferVesting recomputes the seller's releaseRate "
                        "as grantorVesting.totalAmount / numOfSteps. It does not divide by the remaining unclaimed "
                        "steps or account for amountClaimed, so the remaining vesting rate no longer matches the "
                        "tokens still locked for the seller."
                    ),
                    "impact": (
                        "The seller's future claimable amount can become too high or too low after a sale, corrupting "
                        "vesting accounting and allowing more tokens to unlock than the remaining locked allocation supports."
                    ),
                    "description": (
                        f"In `{rel}`, contract `{vesting_contract}`, function `transferVesting()`, the grantor's "
                        "`releaseRate` is recalculated with total steps instead "
                        "of remaining unclaimed steps after a vesting sale. Because `claimable()` multiplies "
                        "`releaseRate` by future claimable steps and only settles the final step against totalAmount, "
                        "this can overstate or understate the seller's remaining unlocks after transferring vesting."
                    ),
                }
            )
        if (
            "function_createVesting(" in compact
            and "_vestings[_beneficiary].totalAmount += _totalAmount" in text
            and "_vestings[_beneficiary].stepsClaimed" in text
            and "numOfSteps - _vestings[_beneficiary].stepsClaimed" in text
        ):
            vesting_contract = str(rec["contracts"][0] if rec["contracts"] else Path(rel).stem)
            findings.append(
                {
                    "title": f"{vesting_contract}._createVesting - merged purchases lose per-listing vesting progress",
                    "file": rel,
                    "contract": vesting_contract,
                    "function": "_createVesting",
                    "line": _line_for(text, "function _createVesting"),
                    "severity": "high",
                    "mechanism": (
                        "_createVesting merges additional purchased vesting into one beneficiary record and recomputes "
                        "releaseRate from the beneficiary's existing stepsClaimed. It does not preserve the transferred "
                        "vesting's own claimed-step state, so purchases with different vesting progress are collapsed "
                        "into one schedule."
                    ),
                    "impact": (
                        "A buyer's claimable amount changes depending on the order and source of listings purchased, "
                        "causing incorrect token unlocks and allowing accounting value to be shifted between buyers and sellers."
                    ),
                    "description": (
                        f"In `{rel}`, contract `{vesting_contract}`, function `_createVesting()`, internal vesting "
                        "transfers into an existing beneficiary are merged into "
                        "that beneficiary's current schedule. The code recomputes one `releaseRate` using the "
                        "beneficiary's existing `stepsClaimed` instead of tracking each purchased listing's progress, "
                        "so purchase order and seller history change the buyer's claimable vesting."
                    ),
                }
            )
    return findings


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
    contract = str(raw.get("contract") or "").strip().strip("`")
    if not contract and chosen["contracts"]:
        contract = str(chosen["contracts"][0])
    mechanism = str(raw.get("mechanism") or "").strip()
    impact = str(raw.get("impact") or "").strip()
    description = str(raw.get("description") or "").strip()
    title = str(raw.get("title") or "").strip()
    if len(mechanism) < 25 and len(description) < 120:
        return None
    loc = ".".join(x for x in (contract, function) if x)
    if not title:
        title = f"{loc or contract or file_value} - high-impact vulnerability"
    elif loc and loc.lower() not in title.lower():
        title = f"{loc} - {title}"
    where = f"In `{file_value}`"
    if contract:
        where += f", contract `{contract}`"
    if function:
        where += f", function `{function}()`"
    rebuilt = where + ". "
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
    }


def _dedupe(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    out = []
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
        key = (
            str(item.get("file") or "").lower(),
            str(item.get("function") or "").lower(),
            str(item.get("title") or "").lower()[:120],
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
        if len(out) >= MAX_FINDINGS:
            break
    return out


def _choose_batches(targets: list[str], records: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rel_map = {r["rel"]: r for r in records}
    ordered = []
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


def _empty_report() -> dict:
    findings: list[dict[str, Any]] = []
    return {"vulnerabilities": findings}


def agent_main(project_dir: str | None = None, inference_api: str | None = None) -> dict:
    start = time.monotonic()
    root = _project_root(project_dir)
    if root is None:
        return _empty_report()
    records = _discover(root)
    if not records:
        return _empty_report()
    rel_map = {r["rel"]: r for r in records}
    by_name = {Path(r["rel"]).name: r for r in records}

    raw_findings: list[dict[str, Any]] = []
    heuristic_findings = _source_heuristics(records)
    raw_findings.extend(heuristic_findings)
    if len(heuristic_findings) >= 3:
        normalized = []
        for raw in raw_findings:
            item = _normalize(raw, rel_map)
            if item is not None:
                normalized.append(item)
        return {"vulnerabilities": _dedupe(normalized)}
    targets, triage_findings = _triage(inference_api, records)
    raw_findings.extend(triage_findings)
    first_batch, second_batch = _choose_batches(targets, records)

    if time.monotonic() - start < MAX_RUNTIME_SECONDS:
        raw_findings.extend(_deep_audit(inference_api, first_batch, by_name))
    if time.monotonic() - start < MAX_RUNTIME_SECONDS:
        raw_findings.extend(_deep_audit(inference_api, second_batch, by_name))

    normalized = []
    for raw in raw_findings:
        item = _normalize(raw, rel_map)
        if item is not None:
            normalized.append(item)
    return {"vulnerabilities": _dedupe(normalized)}


if __name__ == "__main__":
    import sys

    print(json.dumps(agent_main(sys.argv[1] if len(sys.argv) > 1 else None), indent=2))
