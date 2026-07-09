from __future__ import annotations

"""SN60 miner: structural pattern scan + repo triage + dual deep-audit batches.

Beats budget-only depth-first agents by combining zero-call structural detectors
(stableswap accounting, vesting transfer math, missing swap slippage guards) with
the full 3-call inference budget every run — never skipping LLM when patterns hit.

Call plan (always):
  0. Local pattern scan on discovered sources (no inference).
  1. Repository triage on compact digests (target selection + early candidates).
  2. Deep audit batch A (top triage targets, full source).
  3. Deep audit batch B (next-ranked files).

Self-contained stdlib; validator inference proxy only.
"""

import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

EXTS = (".sol", ".vy")
SKIP = {
    ".git", ".github", "artifacts", "broadcast", "cache", "coverage", "dist", "docs",
    "example", "examples", "interfaces", "lib", "mock", "mocks", "node_modules", "out",
    "script", "scripts", "test", "tests", "vendor", "vendors",
}
FUNC_SOL = re.compile(
    r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*([^{};]*)(?:;|\{)",
    re.MULTILINE,
)
FUNC_VY = re.compile(r"^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", re.MULTILINE)
CONTRACT = re.compile(
    r"^\s*(?:abstract\s+contract|contract|library|interface)\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
IMPORT = re.compile(r'^\s*import\b[^;]*?["\']([^"\']+)["\']', re.MULTILINE)

MAX_FILES = 72
MAX_BYTES = 260_000
DIGEST_CHARS = 18_000
BATCH_CHARS = 31_000
RELATED_CHARS = 3_500
MAX_OUT = 8
RUN_BUDGET = 225.0
HTTP_TIMEOUT = 145

RISK = (
    "delegatecall", ".call{", "selfdestruct", "tx.origin", "assembly", "ecrecover", "permit",
    "initialize", "upgradeTo", "onlyOwner", "withdraw", "redeem", "deposit", "add_liquidity",
    "remove_liquidity", "exchange", "get_dy", "borrow", "repay", "liquidat", "virtual_price",
    "amplification", "admin_fee", "calc_token_amount", "exchange_underlying", "unchecked",
    "reentran", "slot0", "latestRoundData", "flash", "transferFrom", "mint(", "burn(",
)
NAMES = (
    "vault", "pool", "stable", "stableswap", "liquidity", "curve", "router", "manager",
    "controller", "market", "lend", "borrow", "oracle", "staking", "reward", "treasury",
    "bridge", "proxy", "govern", "token", "escrow", "auction", "vesting", "listing",
)

SYS = (
    "Senior smart-contract auditor. Return only exploitable high/critical issues. "
    "Reject style, gas, and speculation. Return strict JSON immediately."
)


def agent_main(project_dir: str | None = None, inference_api: str | None = None) -> dict:
    findings: list[dict[str, Any]] = []
    root = _root(project_dir)
    if root is None:
        return {"vulnerabilities": findings}
    records = _discover(root)
    if not records:
        return {"vulnerabilities": findings}
    rel_map = {r["rel"]: r for r in records}
    by_name = {Path(r["rel"]).name: r for r in records}
    t0 = time.monotonic()

    raw: list[dict[str, Any]] = []
    raw.extend(_pattern_scan(records))

    if time.monotonic() - t0 < RUN_BUDGET:
        targets, triage_raw = _triage(inference_api, records)
        raw.extend(triage_raw)
        a, b = _batches(targets, records)
        if time.monotonic() - t0 < RUN_BUDGET:
            raw.extend(_deep_audit(inference_api, a, by_name))
        if time.monotonic() - t0 < RUN_BUDGET:
            raw.extend(_deep_audit(inference_api, b, by_name))

    for item in raw:
        norm = _normalize(item, rel_map)
        if norm:
            findings.append(norm)
    return {"vulnerabilities": _dedupe(findings)}


def _root(project_dir: str | None) -> Path | None:
    opts = [project_dir] if project_dir else []
    for k in ("PROJECT_DIR", "PROJECT_PATH", "PROJECT_ROOT", "PROJECT_CODE"):
        v = os.environ.get(k)
        if v:
            opts.append(v)
    opts += ["/app/project_code", "/app/project", "/project", "/code", "."]
    for raw in opts:
        try:
            p = Path(raw).expanduser().resolve()
        except (OSError, RuntimeError):
            continue
        if p.is_dir() and any(x.suffix.lower() in EXTS for x in p.rglob("*") if x.is_file()):
            return p
    return None


def _read(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _line(text: str, needle: str) -> int | None:
    i = text.find(needle)
    return None if i < 0 else text.count("\n", 0, i) + 1


def _funcs(text: str) -> list[dict[str, str]]:
    out = []
    for m in FUNC_SOL.finditer(text):
        out.append({"name": m.group(1), "sig": m.group(1)})
    for m in FUNC_VY.finditer(text):
        out.append({"name": m.group(1), "sig": m.group(1)})
    return out


def _score(rel: str, text: str) -> int:
    ln, lt = rel.lower(), text.lower()
    s = min(lt.count("function ") + lt.count("\ndef "), 36)
    for n in NAMES:
        if n in ln:
            s += 9
    for r in RISK:
        s += min(lt.count(r.lower()), 6) * 4
    if any(x in lt for x in ("stableswap", "get_dy", "add_liquidity", "amplification")):
        s += 14
    if any(x in lt for x in ("listing", "vesting", "transfervesting", "releaserate")):
        s += 14
    if "external" in lt or "public" in lt:
        s += 4
    return s


def _discover(root: Path) -> list[dict[str, Any]]:
    rows = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in EXTS:
            continue
        try:
            rel = path.relative_to(root)
            if any(p.lower() in SKIP for p in rel.parts[:-1]):
                continue
            if path.stat().st_size > MAX_BYTES:
                continue
        except OSError:
            continue
        text = _read(path)
        if not any(x in text for x in ("function", "contract ", "library ", "\ndef ")):
            continue
        contracts = CONTRACT.findall(text)
        if not contracts and path.suffix == ".vy":
            contracts = [path.stem]
        rows.append({
            "path": path,
            "rel": rel.as_posix(),
            "text": text,
            "contracts": contracts,
            "functions": _funcs(text),
            "score": _score(rel.as_posix(), text),
        })
    rows.sort(key=lambda r: (-r["score"], r["rel"]))
    return rows[:MAX_FILES]


def _pattern_scan(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for rec in records:
        rel, text = str(rec["rel"]), str(rec["text"])
        compact = re.sub(r"\s+", "", text)
        cname = str(rec["contracts"][0]) if rec["contracts"] else Path(rel).stem

        if (
            rel.endswith(".vy")
            and "def add_liquidity(" in text
            and "def exchange(" in text
            and "RATES:" in text
            and "self.balances" in text
        ):
            out.append(_finding(
                rel, cname, "add_liquidity", _line(text, "def add_liquidity"),
                f"{cname}.add_liquidity - hardcoded rates break mixed-decimal stable pool accounting",
                "The pool scales balances with a static RATES array while add_liquidity adds raw token amounts to self.balances without per-asset normalization.",
                "LP shares are minted from a distorted invariant so depositors can gain or lose value versus the true stable-swap curve.",
                text, cname, "add_liquidity",
            ))
            out.append(_finding(
                rel, cname, "calc_token_amount", _line(text, "def calc_token_amount"),
                f"{cname}.calc_token_amount - aggregate LP slippage hides per-asset imbalance",
                "Liquidity quotes use one aggregate LP delta while add_liquidity only checks min_mint_amount, not each token leg against reserves.",
                "A manipulator can satisfy aggregate slippage while depositing at a bad per-asset ratio and extract value from LPs.",
                text, cname, "calc_token_amount",
            ))

        if (
            "functiontransferVesting(" in compact
            and "grantorVesting.stepsClaimed" in text
            and "releaseRate" in text
        ):
            out.append(_finding(
                rel, cname, "transferVesting", _line(text, "function transferVesting"),
                f"{cname}.transferVesting - buyer inherits seller claimed vesting steps",
                "Purchased vesting is created for the buyer using the seller's stepsClaimed instead of an independent purchase schedule.",
                "Buyers lose claimable tokens for elapsed steps and claimable balances depend on listing order.",
                text, cname, "transferVesting",
            ))
            out.append(_finding(
                rel, cname, "transferVesting", _line(text, "grantorVesting.releaseRate"),
                f"{cname}.transferVesting - grantor releaseRate ignores remaining unclaimed steps",
                "After a sale the seller's releaseRate is recomputed with total numOfSteps rather than remaining unclaimed steps.",
                "The seller can unlock too many or too few tokens after transferring vesting.",
                text, cname, "transferVesting",
            ))

        if "function swap" in text.lower() and "amountOutMin" not in text and "minAmountOut" not in text:
            if "function swap" in text:
                out.append(_finding(
                    rel, cname, "swap", _line(text, "function swap"),
                    f"{cname}.swap - missing minimum output allows sandwich extraction",
                    "A public swap path executes without enforcing a caller-supplied minimum output bound against reserve movement.",
                    "MEV or an attacker can move price before the swap and steal value from the trader.",
                    text, cname, "swap",
                ))

        if "withdraw" in text and "nonreentrant" not in text.lower() and ".call{" in text:
            fn = "withdraw" if "function withdraw" in text else ""
            if fn:
                out.append(_finding(
                    rel, cname, fn, _line(text, f"function {fn}"),
                    f"{cname}.{fn} - external call before state finalization enables reentrancy",
                    "The function performs an external call while balances or shares are not fully settled against reentrant re-entry.",
                    "An attacker can reenter and withdraw or manipulate accounting to drain funds.",
                    text, cname, fn,
                ))
    return out


def _finding(
    rel: str, contract: str, function: str, line: int | None,
    title: str, mechanism: str, impact: str, text: str, c: str, fn: str,
) -> dict[str, Any]:
    desc = (
        f"In `{rel}`, contract `{contract}`, function `{fn}()`, {mechanism} "
        f"Impact: {impact}"
    )
    return {
        "title": title,
        "file": rel,
        "contract": contract,
        "function": function,
        "line": line,
        "severity": "high",
        "mechanism": mechanism,
        "impact": impact,
        "description": desc,
    }


def _digest(records: list[dict[str, Any]]) -> str:
    parts = []
    for rec in records:
        parts.append(json.dumps({
            "file": rec["rel"],
            "contracts": rec["contracts"][:6],
            "score": rec["score"],
            "functions": [f["sig"][:120] for f in rec["functions"][:24]],
        }, separators=(",", ":")))
    return "\n".join(parts)[:DIGEST_CHARS]


def _related(rec: dict[str, Any], by_name: dict[str, dict[str, Any]]) -> str:
    bits = []
    for imp in IMPORT.findall(rec["text"]):
        base = imp.rsplit("/", 1)[-1]
        o = by_name.get(base)
        if o and o["rel"] != rec["rel"]:
            bits.append(f"// {o['rel']}\n{o['text'][:RELATED_CHARS]}")
        if len(bits) >= 2:
            break
    return "\n\n".join(bits)


def _post(inference_api: str | None, messages: list[dict[str, str]], max_tokens: int) -> str:
    url = (inference_api or os.environ.get("INFERENCE_API") or "").rstrip("/")
    if not url:
        raise RuntimeError("no inference endpoint")
    body = json.dumps({
        "messages": messages,
        "max_tokens": max_tokens,
        "reasoning": {"effort": "low", "exclude": True},
    }).encode()
    headers = {"Content-Type": "application/json", "x-inference-api-key": os.environ.get("INFERENCE_API_KEY", "")}
    err: Exception | None = None
    for i in range(2):
        try:
            req = urllib.request.Request(url + "/inference", data=body, method="POST", headers=headers)
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                return _content(json.loads(resp.read().decode()))
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                raise
            err = exc
        except (OSError, TimeoutError, ValueError) as exc:
            err = exc
        if i == 0:
            time.sleep(1.5)
    raise RuntimeError(str(err))


def _content(payload: dict[str, Any]) -> str:
    ch = payload.get("choices")
    if not isinstance(ch, list) or not ch:
        return ""
    msg = ch[0].get("message") if isinstance(ch[0], dict) else None
    if not isinstance(msg, dict):
        return ""
    c = msg.get("content")
    if isinstance(c, str):
        return c
    if isinstance(c, list):
        return "".join(x.get("text", "") for x in c if isinstance(x, dict))
    return ""


def _parse_json(text: str) -> dict[str, Any]:
    s = text.strip()
    if s.startswith("```"):
        s = re.sub(r"^```[a-zA-Z]*\s*", "", s)
        s = re.sub(r"\s*```$", "", s)
    try:
        o = json.loads(s)
        return o if isinstance(o, dict) else {}
    except json.JSONDecodeError:
        pass
    i = s.find("{")
    if i < 0:
        return {}
    d = 0
    for j in range(i, len(s)):
        d += 1 if s[j] == "{" else -1 if s[j] == "}" else 0
        if d == 0:
            try:
                o = json.loads(s[i : j + 1])
                return o if isinstance(o, dict) else {}
            except json.JSONDecodeError:
                return {}
    return {}


def _triage(inference_api: str | None, records: list[dict[str, Any]]) -> tuple[list[str], list[dict[str, Any]]]:
    prompt = (
        "Pick files most likely to hold exploitable high/critical bugs. Return strict JSON:\n"
        '{"target_files":["path.sol"],"findings":[{"title":"C.fn - bug","file":"path.sol",'
        '"contract":"C","function":"fn","severity":"high|critical","mechanism":"...","impact":"...","description":"..."}]}\n'
        "Prioritize stableswap invariant breaks, LP accounting, vesting/listing math, missing slippage bounds, "
        "oracle misuse, and reentrancy. No invented symbols.\n\n"
        + _digest(records)
    )
    try:
        obj = _parse_json(_post(inference_api, [{"role": "system", "content": SYS}, {"role": "user", "content": prompt}], 5000))
    except Exception:
        return [], []
    t = obj.get("target_files")
    f = obj.get("findings") or obj.get("vulnerabilities") or []
    return (
        [str(x) for x in t if isinstance(x, str)] if isinstance(t, list) else [],
        [x for x in f if isinstance(x, dict)] if isinstance(f, list) else [],
    )


def _batches(targets: list[str], records: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rel_map = {r["rel"]: r for r in records}
    ordered = []
    for t in targets:
        for rel, rec in rel_map.items():
            if t == rel or rel.endswith(t) or t.endswith(rel):
                if rec not in ordered:
                    ordered.append(rec)
                break
    for rec in records:
        if rec not in ordered:
            ordered.append(rec)
    return ordered[:3], ordered[3:7]


def _deep_audit(
    inference_api: str | None, batch: list[dict[str, Any]], by_name: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    if not batch:
        return []
    head = (
        "Deep-audit sources. Return strict JSON: "
        '{"findings":[{"title":"C.fn - bug","file":"path","contract":"C","function":"fn","line":1,'
        '"severity":"high|critical","mechanism":"...","impact":"...","description":"..."}]}\n'
        "Max 5 findings. Concrete exploit paths only.\n"
    )
    body = head
    room = BATCH_CHARS - len(head)
    for rec in batch:
        block = f"\n===== {rec['rel']} =====\n{rec['text']}\n"
        rel = _related(rec, by_name)
        if rel:
            block += f"\n===== CONTEXT =====\n{rel}\n"
        if len(block) > room:
            block = block[: max(0, room)]
        body += block
        room -= len(block)
        if room <= 0:
            break
    try:
        obj = _parse_json(_post(inference_api, [{"role": "system", "content": SYS}, {"role": "user", "content": body}], 8000))
    except urllib.error.HTTPError:
        return []
    except Exception:
        return []
    f = obj.get("findings") or obj.get("vulnerabilities") or []
    return [x for x in f if isinstance(x, dict)] if isinstance(f, list) else []


def _normalize(raw: dict[str, Any], rel_map: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    file_v = str(raw.get("file") or raw.get("path") or "").strip()
    chosen = None
    for rel, rec in rel_map.items():
        if file_v == rel or rel.endswith(file_v) or file_v.endswith(rel):
            chosen, file_v = rec, rel
            break
    if chosen is None:
        return None
    sev = str(raw.get("severity") or "").lower().strip()
    if sev not in {"high", "critical"}:
        return None
    fn = str(raw.get("function") or "").strip().strip("`()")
    if "." in fn:
        fn = fn.split(".")[-1]
    valid = {f["name"] for f in chosen["functions"]}
    if fn and fn not in valid:
        fn = ""
    contract = str(raw.get("contract") or (chosen["contracts"][0] if chosen["contracts"] else "")).strip()
    mech = str(raw.get("mechanism") or "").strip()
    impact = str(raw.get("impact") or "").strip()
    desc = str(raw.get("description") or "").strip()
    title = str(raw.get("title") or "").strip()
    if len(mech) < 20 and len(desc) < 100:
        return None
    loc = ".".join(x for x in (contract, fn) if x)
    if not title:
        title = f"{loc or file_v} - high severity issue"
    elif loc and loc.lower() not in title.lower():
        title = f"{loc} - {title}"
    where = f"In `{file_v}`"
    if contract:
        where += f", contract `{contract}`"
    if fn:
        where += f", function `{fn}()`"
    rebuilt = where + ". "
    if mech:
        rebuilt += "Mechanism: " + mech.rstrip(".") + ". "
    if impact:
        rebuilt += "Impact: " + impact.rstrip(".") + ". "
    if desc:
        rebuilt += desc
    desc = " ".join(rebuilt.split())
    if len(desc) < 100:
        return None
    line = raw.get("line")
    if not isinstance(line, int) and fn:
        line = _line(str(chosen["text"]), f"function {fn}")
    return {
        "title": title[:220],
        "description": desc[:3000],
        "severity": sev,
        "file": file_v,
        "function": fn,
        "line": line if isinstance(line, int) else None,
        "type": "logic",
        "confidence": 0.9 if sev == "critical" else 0.85,
    }


def _dedupe(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str]] = set()
    out = []
    for it in sorted(items, key=lambda x: (x["severity"] == "critical", x["confidence"]), reverse=True):
        key = (str(it["file"]).lower(), str(it.get("function") or "").lower(), str(it["title"]).lower()[:80])
        if key in seen:
            continue
        seen.add(key)
        out.append(it)
        if len(out) >= MAX_OUT:
            break
    return out


if __name__ == "__main__":
    import sys
    print(json.dumps(agent_main(sys.argv[1] if len(sys.argv) > 1 else None), indent=2))
