import json
import os
import re
import time
import urllib.error
import urllib.request


EXTENSIONS = (".sol", ".vy", ".cairo")
SKIP_DIRS = {
    ".git", ".github", ".hg", ".svn", "__pycache__", ".venv", "venv",
    "node_modules", "lib", "libs", "vendor", "vendors", "dependencies",
    "test", "tests", "mock", "mocks", "script", "scripts", "out",
    "build", "cache", "artifacts", "broadcast", "coverage", "docs",
    "examples", "example", "interfaces", "target", "dist",
}
MAX_SCAN_FILES = 72
MAX_FILE_BYTES = 320000
MAX_RETURNED = 12
MAP_LIMIT = 17000
FILE_LIMIT = 19000
AUDIT_LIMIT = 51000
RUN_SECONDS = 165.0
MAX_CALLS = 3
MAX_REPLY = 6200

SOL_FN = re.compile(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\((.*?)\)\s*([^{};]*)(?:\{|;)", re.S)
VY_FN = re.compile(r"^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\((.*?)\)\s*:", re.M | re.S)
CAIRO_FN = re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:<[^>{}]*>)?\s*\(", re.S)
SOL_UNIT = re.compile(r"^\s*(?:abstract\s+)?(?:contract|library|interface)\s+([A-Za-z_][A-Za-z0-9_]*)", re.M)
CAIRO_UNIT = re.compile(r"^\s*(?:#\[[^\]]+\]\s*)?(?:mod|impl|trait)\s+([A-Za-z_][A-Za-z0-9_]*)", re.M)
IMPORT_PATH = re.compile(r"^\s*import\b[^;{]*?['\"]([^'\"]+)['\"]", re.M)

RISK_TERMS = {
    "delegatecall": 12, "selfdestruct": 12, "tx.origin": 11, ".call": 7, "call{": 7,
    "assembly": 5, "unchecked": 5, "ecrecover": 7, "signature": 5, "permit": 6,
    "oracle": 7, "price": 5, "twap": 6, "roundid": 4, "stale": 5,
    "withdraw": 6, "redeem": 6, "claim": 5, "mint": 5, "burn": 5,
    "deposit": 4, "stake": 4, "unstake": 5, "borrow": 6, "repay": 5,
    "liquidat": 7, "swap": 5, "bridge": 7, "vault": 6, "pool": 4,
    "share": 5, "accounting": 5, "collateral": 6, "solvency": 7,
    "initialize": 7, "upgrade": 7, "owner": 4, "role": 3,
    "fee": 3, "slippage": 5, "rounding": 5, "nonce": 4,
}
NAME_TERMS = (
    "vault", "pool", "router", "market", "lending", "borrow", "liquidat",
    "oracle", "bridge", "staking", "reward", "treasury", "manager",
    "controller", "strategy", "exchange", "escrow", "govern", "proxy",
)
AUTH_HINTS = (
    "onlyowner", "onlyrole", "requiresauth", "auth", "_checkowner",
    "assertonlyowner", "adminonly", "ownable", "hasrole",
)
NOISE_NAME = ("test", "mock", "script", "fixture", "helper")


def agent_main(project_dir=None, inference_api=None):
    started = time.monotonic()
    calls = 0
    found = []
    try:
        root = choose_root(project_dir)
        if not root:
            return {"vulnerabilities": found}
        files = collect_sources(root, started)
        if not files:
            return {"vulnerabilities": found}
        by_path = {item["path"]: item for item in files}
        by_name = {}
        for item in files:
            by_name.setdefault(os.path.basename(item["path"]).lower(), item)

        found.extend(probe_project(files))

        triage_targets, triage_notes = triage_call(inference_api, files, started)
        calls += 1 if triage_notes is not None else 0
        found.extend(triage_notes or [])

        ordered = schedule_files(files, triage_targets)
        batch_a = ordered[:3]
        batch_b = choose_diverse(ordered, batch_a, 4)

        if calls < MAX_CALLS and enough_time(started, 45):
            got = audit_call(inference_api, batch_a, by_name, started, "primary value paths")
            calls += 1 if got is not None else 0
            found.extend(got or [])
        if calls < MAX_CALLS and enough_time(started, 45):
            got = audit_call(inference_api, batch_b, by_name, started, "cross-file edge paths")
            calls += 1 if got is not None else 0
            found.extend(got or [])

        return {"vulnerabilities": finalize(found, by_path)}
    except Exception:
        return {"vulnerabilities": finalize(found, {})}


def choose_root(project_dir):
    choices = []
    if project_dir:
        choices.append(project_dir)
    for key in ("PROJECT_DIR", "PROJECT_ROOT", "PROJECT_PATH", "PROJECT_CODE"):
        value = os.environ.get(key)
        if value:
            choices.append(value)
    choices.extend(("/app/project_code", "/app/project", "/project", "/code", "."))
    for raw in choices:
        try:
            root = os.path.abspath(os.path.expanduser(str(raw)))
            if os.path.isdir(root) and quick_has_source(root):
                return root
        except OSError:
            pass
    return None


def quick_has_source(root):
    try:
        for current, dirs, names in os.walk(root):
            prune_dirs(dirs)
            for name in names:
                if lower_ext(name) in EXTENSIONS and not ignore_file_name(name):
                    return True
    except OSError:
        return False
    return False


def prune_dirs(dirs):
    keep = []
    for name in dirs:
        low = name.lower()
        if low in SKIP_DIRS or low.startswith("."):
            continue
        keep.append(name)
    dirs[:] = keep


def lower_ext(name):
    return os.path.splitext(name)[1].lower()


def ignore_file_name(name):
    low = name.lower()
    return low.endswith((".t.sol", ".s.sol", "_test.sol", ".test.sol", ".spec.sol"))


def collect_sources(root, started):
    out = []
    try:
        for current, dirs, names in os.walk(root):
            if not enough_time(started, 8):
                break
            prune_dirs(dirs)
            for name in sorted(names):
                ext = lower_ext(name)
                if ext not in EXTENSIONS or ignore_file_name(name):
                    continue
                path = os.path.join(current, name)
                try:
                    if os.path.getsize(path) > MAX_FILE_BYTES:
                        continue
                    rel = os.path.relpath(path, root).replace(os.sep, "/")
                    if rel_is_noise(rel):
                        continue
                    text = read_limited(path)
                except OSError:
                    continue
                if not looks_contract_like(text, ext):
                    continue
                item = describe_file(rel, text, ext)
                out.append(item)
                if len(out) >= MAX_SCAN_FILES * 2:
                    break
            if len(out) >= MAX_SCAN_FILES * 2:
                break
    except OSError:
        pass
    out.sort(key=lambda x: (-x["score"], x["path"]))
    return out[:MAX_SCAN_FILES]


def rel_is_noise(rel):
    parts = rel.lower().split("/")
    for part in parts[:-1]:
        if part in SKIP_DIRS or part.startswith("."):
            return True
    return any(word in parts[-1] for word in NOISE_NAME)


def read_limited(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as handle:
        return handle.read(MAX_FILE_BYTES)


def looks_contract_like(text, ext):
    if ext == ".vy":
        return "def " in text or "@external" in text
    if ext == ".cairo":
        return "fn " in text or "#[starknet::contract]" in text or "impl " in text
    return "function " in text or "contract " in text or "library " in text


def describe_file(rel, text, ext):
    funcs = functions_in(text, ext)
    units = units_in(text, ext, rel)
    risks = risk_lines(text)
    return {
        "path": rel,
        "ext": ext,
        "text": text,
        "units": units,
        "functions": funcs,
        "risks": risks,
        "score": risk_score(rel, text, funcs, risks),
    }


def functions_in(text, ext):
    rows = []
    patterns = [SOL_FN]
    if ext == ".vy":
        patterns = [VY_FN]
    elif ext == ".cairo":
        patterns = [CAIRO_FN, SOL_FN]
    for pattern in patterns:
        for match in pattern.finditer(text):
            sig = " ".join(match.group(0).split())
            rows.append({
                "name": match.group(1),
                "line": line_number(text, match.start()),
                "sig": sig[:220],
                "start": match.start(),
            })
    rows.sort(key=lambda x: x["line"])
    return rows[:80]


def units_in(text, ext, rel):
    names = SOL_UNIT.findall(text)
    if ext == ".cairo":
        names += CAIRO_UNIT.findall(text)
    clean = []
    for name in names:
        if name not in clean:
            clean.append(name)
    return clean or [os.path.splitext(os.path.basename(rel))[0]]


def line_number(text, offset):
    if offset is None or offset < 0:
        return 1
    return text.count("\n", 0, offset) + 1


def risk_lines(text):
    hits = []
    lowered_terms = tuple(RISK_TERMS)
    for number, line in enumerate(text.splitlines(), 1):
        low = line.lower().replace(" ", "")
        if any(term.replace(" ", "") in low for term in lowered_terms):
            compact = " ".join(line.strip().split())
            if compact:
                hits.append(str(number) + ": " + compact[:180])
        if len(hits) >= 16:
            break
    return hits


def risk_score(rel, text, funcs, risks):
    low_rel = rel.lower()
    low_text = text.lower()
    compact = low_text.replace(" ", "")
    score = min(len(funcs), 45) + len(risks) * 2
    for word in NAME_TERMS:
        if word in low_rel:
            score += 10
        elif word in low_text:
            score += 2
    for word, weight in RISK_TERMS.items():
        needle = word.replace(" ", "")
        if needle in compact:
            score += weight
    if "external" in low_text or "public" in low_text or "@external" in low_text:
        score += 7
    if "nonreentrant" not in compact and (".call" in compact or "call{" in compact):
        score += 8
    return score


def probe_project(files):
    hits = []
    for item in files:
        text = item["text"]
        low = text.lower()
        hits.extend(probe_delegation(item, text, low))
        hits.extend(probe_origin(item, text, low))
        hits.extend(probe_value_flow(item, text))
        hits.extend(probe_privileged_names(item, text))
        hits.extend(probe_oracles(item, text, low))
        hits.extend(probe_signatures(item, text, low))
        if len(hits) >= 10:
            break
    return hits[:10]


def probe_delegation(item, text, low):
    hits = []
    for match in re.finditer(r"\bdelegatecall\b|\bselfdestruct\b", low):
        fn = nearest_function(item, match.start())
        body = function_body(text, fn)
        line = line_number(text, match.start())
        if "delegatecall" in match.group(0):
            if not has_auth(body + " " + fn.get("sig", "")):
                hits.append(make_finding(
                    "Unrestricted delegatecall can execute attacker code",
                    item, "critical", line, fn.get("name", ""),
                    "An externally reachable path performs delegatecall without a clear owner or role gate.",
                    "A caller can point execution at malicious code and overwrite storage or drain assets.",
                    "delegatecall",
                ))
        else:
            if not has_auth(body + " " + fn.get("sig", "")):
                hits.append(make_finding(
                    "Unrestricted selfdestruct destroys contract state",
                    item, "critical", line, fn.get("name", ""),
                    "A reachable path invokes selfdestruct without a clear privileged guard.",
                    "An attacker can remove the contract or force asset movement, breaking protocol accounting.",
                    "selfdestruct",
                ))
    return hits


def probe_origin(item, text, low):
    hits = []
    idx = low.find("tx.origin")
    if idx >= 0 and any(token in low[max(0, idx - 140):idx + 180] for token in ("require", "assert", "if", "revert")):
        fn = nearest_function(item, idx)
        hits.append(make_finding(
            "Authorization depends on tx.origin",
            item, "high", line_number(text, idx), fn.get("name", ""),
            "The authorization branch checks tx.origin in a security decision.",
            "A phishing contract can make the victim originate the transaction and bypass the intended caller check.",
            "access-control",
        ))
    return hits


def probe_value_flow(item, text):
    hits = []
    for fn in function_slices(text, item["ext"]):
        body_low = fn["body"].lower().replace(" ", "")
        sig_low = fn["sig"].lower().replace(" ", "")
        if (".call" in body_low or "call{" in body_low) and "nonreentrant" not in body_low + sig_low:
            if state_change_after_call(fn["body"]) or state_change_before_call(fn["body"]):
                hits.append(make_finding(
                    "External value transfer is exposed to reentrancy",
                    item, "high", fn["line"], fn["name"],
                    "The function performs an external call while updating accounting without a reentrancy guard.",
                    "A nested call can observe inconsistent state and withdraw or claim more value than intended.",
                    "reentrancy",
                ))
        if "unchecked" in body_low and any(x in fn["name"].lower() for x in ("withdraw", "redeem", "mint", "burn", "claim", "liquidat")):
            hits.append(make_finding(
                "Unchecked arithmetic in value accounting path",
                item, "high", fn["line"], fn["name"],
                "A value-moving function uses unchecked arithmetic around balances, shares, or debt.",
                "Boundary inputs can overflow, underflow, or round in favor of the attacker, corrupting accounting.",
                "accounting",
            ))
        if ("send(" in body_low or "transfer(" in body_low) and "bool" not in body_low and "require" not in body_low:
            hits.append(make_finding(
                "Native transfer result is not safely handled",
                item, "high", fn["line"], fn["name"],
                "The function relies on a low-level native transfer path without robust failure handling.",
                "A failed payout can leave user balances or protocol liabilities inconsistent.",
                "unchecked-call",
            ))
    return hits


def probe_privileged_names(item, text):
    hits = []
    sensitive = re.compile(r"^(set|update|add|remove|enable|disable|upgrade|pause|unpause|mint|burn|sweep|rescue|withdraw)")
    for fn in function_slices(text, item["ext"]):
        low_sig = fn["sig"].lower()
        low_body = fn["body"].lower()
        if sensitive.search(fn["name"].lower()) and ("external" in low_sig or "public" in low_sig or "@external" in low_body):
            if not has_auth(low_sig + low_body[:800]):
                hits.append(make_finding(
                    "Privileged function lacks access control",
                    item, "high", fn["line"], fn["name"],
                    "A sensitive external entrypoint changes configuration, roles, minting, withdrawals, or upgrade state without an owner or role check.",
                    "Any caller can perform administrative actions and steal funds or disable protocol safety controls.",
                    "access-control",
                ))
    return hits


def probe_oracles(item, text, low):
    hits = []
    if not any(x in low for x in ("oracle", "price", "latestanswer", "latestrounddata", "getprice", "twap")):
        return hits
    for fn in function_slices(text, item["ext"]):
        body = fn["body"].lower()
        if any(x in body for x in ("latestanswer", "latestrounddata", "getprice", "slot0", "observe(")):
            freshness = any(x in body for x in ("updatedat", "answeredinaround", "heartbeat", "stale", "block.timestamp", "twap"))
            sanity = any(x in body for x in ("minprice", "maxprice", "> 0", "!= 0", "bounds", "deviation"))
            if not (freshness and sanity):
                hits.append(make_finding(
                    "Oracle price lacks freshness or bounds validation",
                    item, "high", fn["line"], fn["name"],
                    "The price path consumes an oracle value without complete stale-round and sanity-bound validation.",
                    "A stale or manipulated price can drive undercollateralized borrows, unfair liquidations, or mispriced swaps.",
                    "oracle",
                ))
    return hits


def probe_signatures(item, text, low):
    hits = []
    if "ecrecover" not in low and "recover(" not in low and "isvalidsignature" not in low:
        return hits
    for fn in function_slices(text, item["ext"]):
        body = fn["body"].lower()
        if any(x in body for x in ("ecrecover", "recover(", "isvalidsignature")):
            checks = sum(1 for x in ("nonce", "deadline", "chainid", "block.timestamp", "used", "domainseparator") if x in body)
            if checks < 3:
                hits.append(make_finding(
                    "Signature verification is replayable",
                    item, "high", fn["line"], fn["name"],
                    "The signature path does not combine nonce, deadline, chain binding, and consumed-signature protection.",
                    "A valid authorization can be replayed to repeat transfers, approvals, or privileged actions.",
                    "signature",
                ))
    return hits


def has_auth(text):
    low = text.lower().replace("_", "")
    return any(h.replace("_", "") in low for h in AUTH_HINTS)


def function_slices(text, ext):
    funcs = []
    patterns = [SOL_FN]
    if ext == ".vy":
        patterns = [VY_FN]
    elif ext == ".cairo":
        patterns = [CAIRO_FN, SOL_FN]
    matches = []
    for pattern in patterns:
        matches.extend(pattern.finditer(text))
    matches.sort(key=lambda m: m.start())
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        funcs.append({
            "name": match.group(1),
            "line": line_number(text, match.start()),
            "sig": " ".join(match.group(0).split())[:220],
            "start": match.start(),
            "body": text[match.start():end],
        })
    return funcs


def nearest_function(item, offset):
    best = {"name": "", "line": 1, "sig": "", "start": 0}
    for fn in item.get("functions", []):
        if fn.get("start", 0) <= offset:
            best = fn
        else:
            break
    return best


def function_body(text, fn):
    start = int(fn.get("start", 0) or 0)
    if start <= 0:
        return text[:1500]
    return text[start:start + 5000]


def state_change_after_call(body):
    call_pos = min_pos(body, (".call", "call{", ".transfer", ".send"))
    if call_pos < 0:
        return False
    tail = body[call_pos:]
    return bool(re.search(r"\b[A-Za-z_][A-Za-z0-9_\]\)]*\s*(?:[+\-*/]?=|\+\+|--)", tail))


def state_change_before_call(body):
    call_pos = min_pos(body, (".call", "call{", ".transfer", ".send"))
    if call_pos < 0:
        return False
    head = body[:call_pos]
    return any(word in head.lower() for word in ("balance", "balances", "shares", "debt", "amount", "claimable"))


def min_pos(text, needles):
    best = -1
    low = text.lower()
    for needle in needles:
        pos = low.find(needle)
        if pos >= 0 and (best < 0 or pos < best):
            best = pos
    return best


def make_finding(title, item, severity, line, function, mechanism, impact, kind):
    unit = item["units"][0] if item.get("units") else os.path.splitext(os.path.basename(item["path"]))[0]
    desc = (
        "In `{}`".format(item["path"])
        + (", `{}`".format(function) if function else "")
        + ". Mechanism: {} Impact: {}".format(mechanism.rstrip(".") + ".", impact.rstrip(".") + ".")
    )
    return {
        "title": title,
        "description": desc,
        "severity": severity,
        "file": item["path"],
        "line": int(line or 1),
        "function": function or "",
        "contract": unit,
        "type": kind,
        "confidence": 0.72,
    }


def enough_time(started, reserve):
    return time.monotonic() - started < RUN_SECONDS - reserve


def remaining_timeout(started):
    left = RUN_SECONDS - (time.monotonic() - started) - 4.0
    return max(8.0, min(52.0, left))


def map_text(files):
    rows = []
    for item in files:
        funcs = ["{}:{}".format(f["line"], f["sig"]) for f in item["functions"][:22]]
        rows.append(json.dumps({
            "file": item["path"],
            "language": item["ext"].lstrip("."),
            "score": item["score"],
            "contracts": item["units"][:6],
            "functions": funcs,
            "risk_lines": item["risks"][:12],
        }, separators=(",", ":")))
    return "\n".join(rows)[:MAP_LIMIT]


def triage_call(api, files, started):
    prompt = (
        "You are ranking a smart-contract repository for an audit. Use the map plus risk scores. "
        "Return strict JSON only with this shape: "
        "{\"target_files\":[\"path\"],\"findings\":[{\"title\":\"issue\",\"description\":\"specific exploit path\","
        "\"severity\":\"high\",\"file\":\"path\",\"line\":1,\"function\":\"name\"}]}.\n"
        "Prefer real high/critical exploit paths in value movement, access control, oracle pricing, signatures, "
        "liquidation, share accounting, upgrades, bridges, and external calls. Do not report style issues.\n\n"
        + map_text(files)
    )
    text = ask_model(api, prompt, MAX_REPLY, started)
    if text is None:
        return [], None
    obj = parse_json_object(text)
    targets = obj.get("target_files") if isinstance(obj, dict) else []
    notes = obj.get("findings") if isinstance(obj, dict) else []
    if not isinstance(targets, list):
        targets = []
    if not isinstance(notes, list):
        notes = obj.get("vulnerabilities") if isinstance(obj, dict) else []
    return [str(x) for x in targets if isinstance(x, str)], [x for x in notes if isinstance(x, dict)] if isinstance(notes, list) else []


def schedule_files(files, target_names):
    ordered = []
    for name in target_names:
        match = find_record(str(name), files)
        if match and match not in ordered:
            ordered.append(match)
    for item in files:
        if item not in ordered:
            ordered.append(item)
    return ordered


def choose_diverse(ordered, first, count):
    picked = []
    used_dirs = {parent_dir(x["path"]) for x in first}
    for item in ordered:
        if item in first:
            continue
        directory = parent_dir(item["path"])
        if directory not in used_dirs:
            picked.append(item)
            used_dirs.add(directory)
        if len(picked) >= count:
            return picked
    for item in ordered:
        if item not in first and item not in picked:
            picked.append(item)
        if len(picked) >= count:
            break
    return picked


def parent_dir(path):
    parent = os.path.dirname(path)
    return parent or "."


def related_snippets(item, by_name):
    chunks = []
    for imp in IMPORT_PATH.findall(item["text"]):
        key = os.path.basename(imp).lower()
        other = by_name.get(key)
        if other and other["path"] != item["path"]:
            chunks.append("\n--- related {} ---\n{}".format(other["path"], other["text"][:2600]))
        if len(chunks) >= 2:
            break
    return "".join(chunks)


def audit_prompt(batch, by_name, focus):
    head = (
        "Deep audit these smart-contract files for exploitable high or critical vulnerabilities. "
        "Focus: {}. Return strict JSON only: ".format(focus)
        + "{\"findings\":[{\"title\":\"bug\",\"description\":\"preconditions, attacker steps, and impact\","
        "\"severity\":\"high|critical\",\"file\":\"path\",\"line\":1,\"function\":\"name\"}]}.\n"
        "Use line numbers from the source. Exclude gas, centralization-only notes, missing events, and harmless style issues. "
        "If uncertain, omit it.\n"
    )
    parts = [head]
    room = AUDIT_LIMIT - len(head)
    for item in batch:
        signatures = ["{}:{}".format(f["line"], f["sig"]) for f in item["functions"][:28]]
        source = item["text"][:FILE_LIMIT]
        block = (
            "\n\n=== {} ===\nContracts: {}\nFunctions: {}\nRisk lines: {}\n{}\n{}\n".format(
                item["path"],
                ", ".join(item["units"][:6]),
                json.dumps(signatures, separators=(",", ":")),
                json.dumps(item["risks"][:14], separators=(",", ":")),
                source,
                related_snippets(item, by_name),
            )
        )
        if len(block) > room:
            block = block[:max(0, room)] + "\n/* truncated */\n"
        parts.append(block)
        room -= len(block)
        if room <= 1000:
            break
    return "".join(parts)


def audit_call(api, batch, by_name, started, focus):
    if not batch:
        return []
    text = ask_model(api, audit_prompt(batch, by_name, focus), MAX_REPLY, started)
    if text is None:
        return None
    obj = parse_json_object(text)
    values = obj.get("findings") if isinstance(obj, dict) else []
    if not isinstance(values, list):
        values = obj.get("vulnerabilities") if isinstance(obj, dict) else []
    return [x for x in values if isinstance(x, dict)] if isinstance(values, list) else []


def ask_model(api, prompt, max_tokens, started):
    endpoint = (api or os.environ.get("INFERENCE_API") or "").rstrip("/")
    if not endpoint or not enough_time(started, 12):
        return None
    payload = json.dumps({
        "messages": [
            {"role": "system", "content": "You are a precise smart-contract security auditor. Return valid JSON only."},
            {"role": "user", "content": prompt},
        ],
        "max_tokens": max_tokens,
        "temperature": 0.1,
    }).encode("utf-8")
    request = urllib.request.Request(
        endpoint + "/inference",
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "x-inference-api-key": os.environ.get("INFERENCE_API_KEY", ""),
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=remaining_timeout(started)) as response:
            data = json.loads(response.read().decode("utf-8", "replace"))
        return response_text(data)
    except (OSError, TimeoutError, urllib.error.URLError, ValueError, KeyError, IndexError, TypeError):
        return ""


def response_text(data):
    choices = data.get("choices") if isinstance(data, dict) else None
    if not choices or not isinstance(choices, list):
        return ""
    first = choices[0] if isinstance(choices[0], dict) else {}
    message = first.get("message") if isinstance(first, dict) else {}
    if isinstance(message, dict):
        content = message.get("content")
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            return "".join(str(part.get("text", "")) for part in content if isinstance(part, dict))
    text = first.get("text") if isinstance(first, dict) else ""
    return text if isinstance(text, str) else ""


def parse_json_object(text):
    cleaned = (text or "").strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```[A-Za-z0-9_-]*\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned).strip()
    try:
        obj = json.loads(cleaned)
        if isinstance(obj, dict):
            return obj
        if isinstance(obj, list):
            return {"findings": obj}
    except ValueError:
        pass
    for start_char, end_char in (("{", "}"), ("[", "]")):
        start = cleaned.find(start_char)
        if start < 0:
            continue
        snippet = balanced_json(cleaned, start, start_char, end_char)
        if not snippet:
            continue
        try:
            obj = json.loads(snippet)
            if isinstance(obj, dict):
                return obj
            if isinstance(obj, list):
                return {"findings": obj}
        except ValueError:
            continue
    return {}


def balanced_json(text, start, open_char, close_char):
    depth = 0
    in_string = False
    escape = False
    for idx in range(start, len(text)):
        ch = text[idx]
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
        elif ch == open_char:
            depth += 1
        elif ch == close_char:
            depth -= 1
            if depth == 0:
                return text[start:idx + 1]
    return ""


def find_record(name, files):
    low = name.strip().strip("`").lower()
    if not low:
        return None
    for item in files:
        path = item["path"].lower()
        if low == path or path.endswith(low) or low.endswith(path):
            return item
    base = os.path.basename(low)
    matches = [item for item in files if os.path.basename(item["path"]).lower() == base]
    return matches[0] if len(matches) == 1 else None


def normalize_line(value, fallback):
    try:
        number = int(value)
        return number if number > 0 else fallback
    except (TypeError, ValueError):
        return fallback


def finalize(raw_items, by_path):
    output = []
    seen = set()
    for raw in sorted(raw_items, key=rank_raw, reverse=True):
        if not isinstance(raw, dict):
            continue
        file_value = str(raw.get("file") or raw.get("path") or "").strip()
        item = by_path.get(file_value) or find_record(file_value, list(by_path.values())) if by_path else None
        file_name = item["path"] if item else file_value.replace("\\", "/")
        if not file_name or file_name.startswith("/"):
            continue
        severity = str(raw.get("severity") or "high").lower().strip()
        if severity not in ("high", "critical"):
            continue
        function = str(raw.get("function") or "").strip().strip("`() ")
        if "." in function:
            function = function.rsplit(".", 1)[-1]
        if item:
            valid_names = {f["name"] for f in item.get("functions", [])}
            if function and function not in valid_names:
                function = ""
        line = normalize_line(raw.get("line"), 1)
        title = clean_text(raw.get("title")) or "High-impact smart contract vulnerability"
        description = clean_text(raw.get("description"))
        mechanism = clean_text(raw.get("mechanism"))
        impact = clean_text(raw.get("impact"))
        if len(description) < 80:
            parts = []
            if mechanism:
                parts.append("Mechanism: " + mechanism.rstrip(".") + ".")
            if impact:
                parts.append("Impact: " + impact.rstrip(".") + ".")
            description = " ".join(parts) or description
        if len(description) < 60:
            continue
        location = "Affected location: `{}`".format(file_name)
        if function:
            location += ", `{}`".format(function)
        if location not in description:
            description = description.rstrip(".") + ". " + location + "."
        key = (file_name.lower(), function.lower(), title.lower()[:110])
        if key in seen:
            continue
        seen.add(key)
        output.append({
            "title": title[:220],
            "description": description[:3000],
            "severity": severity,
            "file": file_name,
            "line": line,
            "function": function,
        })
        if len(output) >= MAX_RETURNED:
            break
    return output


def rank_raw(item):
    if not isinstance(item, dict):
        return (0, 0, 0)
    severity = str(item.get("severity") or "").lower()
    confidence = item.get("confidence")
    try:
        conf = float(confidence)
    except (TypeError, ValueError):
        conf = 0.8 if severity in ("high", "critical") else 0.4
    return (2 if severity == "critical" else 1 if severity == "high" else 0, conf, len(str(item.get("description") or "")))


def clean_text(value):
    return " ".join(str(value or "").strip().split())


if __name__ == "__main__":
    import sys
    print(json.dumps(agent_main(sys.argv[1] if len(sys.argv) > 1 else None), indent=2))
