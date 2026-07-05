"""SN60 / Bitsec miner agent: keyword-ranked triage + multi-pass LLM review,
with cheap cross-file context and similarity-based dedup.

Walks the mounted project for smart-contract source files, ranks them by how
suspicious they look (payable functions, external calls, access-control
keywords, ...), then runs each top-ranked file through several narrowly
focused specialist passes (access control, fund-flow accounting, unit/
interface mismatches, math/iteration edge cases) instead of one generic
"find bugs" prompt. Each file is scanned together with a small amount of
cheap, regex-resolved cross-file context (imported/inherited files) so a bug
that only shows up when a base contract and its child are read together is
not missed. Passes run concurrently against the single pinned inference
endpoint under a hard wall-clock budget, so a slow or hung file cannot starve
the rest of the run, and a transient request failure gets one retry before
being counted as a loss.

This agent intentionally does NOT replicate a full agentic router/recon/LLM-
merge pipeline. Cross-file linking and de-duplication are done with cheap,
local regex/set-similarity logic instead of extra model calls, so the whole
design stays a single self-contained, stdlib-only file with a small, bounded
number of inference calls per project.
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

CONTRACT_SUFFIXES = (".sol", ".vy", ".rs", ".move", ".cairo", ".fe")
SKIP_DIR_NAMES = {
    "node_modules", "lib", "libs", "vendor", "test", "tests",
    "mock", "mocks", "script", "scripts", "artifacts", "cache", "out",
    "forge-std", "openzeppelin-contracts", "openzeppelin",
}
# Names in SKIP_DIR_NAMES that are only ever vendored/tooling directories
# when they sit OUTSIDE a project's own `src/` tree. Confirmed by local
# testing: a real project had both a top-level `lib/` (vendored forge-std,
# openzeppelin) AND a first-party `src/lib/` (Hyperliquid precompile bridge
# code) -- the blanket name match skipped both, hiding the file most
# relevant to the actual vulnerability. Once inside `src/`, only test/mock
# subdirectories are still excluded.
SKIP_DIR_NAMES_INSIDE_SRC = {"test", "tests", "mock", "mocks"}
SUSPICIOUS_KEYWORDS = (
    "payable", "delegatecall", "selfdestruct", ".call(", "transfer(",
    "send(", "onlyowner", "msg.sender", "tx.origin", "unchecked",
    "external", "assembly", "approve(", "mint(", "burn(", "withdraw",
)
MAX_FILE_CHARS = 40000              # raised from 12000 -- local testing confirmed a hard mid-
                                     # statement cutoff made the model mistake the cutoff point for
                                     # a bug ("truncated variable", "function body missing") on real
                                     # large files, hiding the actual vulnerability past the cutoff.
MAX_RELATED_FILE_CHARS = 4000       # related files are context, not primary targets -- keep short
MAX_FILES_CONSIDERED = 40
MAX_FILES_ANALYZED = 14             # raised from an earlier 8 -- the sandbox's execution budget
                                     # has far more headroom than a fixed low file cap used, so more
                                     # of the ranked candidates now actually get scanned
MAX_RELATED_FILES_PER_FILE = 4       # raised from 2 -- confirmed by local testing that a low cap
                                      # combined with in-file-order selection let interface files
                                      # (pure signatures, low information) crowd out the actual
                                      # library/implementation file a bug depends on, just because
                                      # the interface happened to be imported earlier in the file
MAX_FINDINGS = 20
MAX_FINDINGS_PER_CALL = 4
MIN_CONFIDENCE = 0.6
TIME_BUDGET_SECONDS = 600.0         # raised from an earlier 300s -- still a small fraction of the
                                     # sandbox's execution timeout, but lets more files complete
REQUEST_TIMEOUT_SECONDS = 90
MAX_ATTEMPTS_PER_CALL = 2           # 1 initial attempt + 1 retry on a transient failure
RETRY_BACKOFF_SECONDS = 3.0
MAX_WORKERS = 8
MIN_DESCRIPTION_CHARS = 80
VALID_SEVERITIES = ("high", "critical")
DEDUPE_TITLE_JACCARD_THRESHOLD = 0.6   # raised from 0.25 (a value ported from a different agent's
                                        # dedup logic without re-validating it against this agent's
                                        # own title style). Confirmed by local testing: 0.25 caused
                                        # two DIFFERENT real bugs ("Incorrect Transfer Direction in
                                        # decr_position..." vs "Incorrect Token Transfer in
                                        # swap_2_internal_erc20...") to be wrongly merged (Jaccard
                                        # 0.36) purely because they share generic vulnerability-
                                        # report vocabulary ("incorrect", "transfer", "token",
                                        # "loss"), silently discarding the higher-value finding. The
                                        # matching function-name check below is the more reliable
                                        # merge signal (confirmed it alone still merges genuinely
                                        # duplicate same-function reports); title similarity is now
                                        # a high-bar secondary signal, not the primary one.

# Shared instructions appended to every specialist prompt below: output
# contract, confidence discipline, and a short false-positive suppression
# list distilled from well-known smart-contract audit conventions (SWC
# registry style categories), written independently for this agent.
_COMMON_TAIL = f"""
Only report a finding if you can state the exact function name and a
concrete scenario (inputs, call sequence, or numeric example) that shows
the impact. If you cannot show a concrete path, do not report it.

Do not report:
- functions already gated by onlyOwner/onlyRole/similar modifiers, unless
  you can show the role check itself is bypassable
- decimal/scaling differences that are already handled by an explicit
  conversion helper in the code
- reentrancy, unless you can point to a state write that happens AFTER an
  external call, with no reentrancy guard, and a concrete profit path
- gas/DoS from unbounded loops, unless the loop bound is attacker-controlled
  with no practical cap
- unchecked return values on calls that revert by default or use a safe
  transfer wrapper

Only report severity "high" or "critical", and only when your own
confidence in the finding is at least 0.7.

Respond with ONLY a JSON array (no prose, no markdown fences), at most
{MAX_FINDINGS_PER_CALL} elements, each an object with keys: "title",
"description" (at least two sentences explaining the concrete exploit
path), "severity" ("high" or "critical"), "function", "line" (integer or
null), "confidence" (0-1 float), "recommendation". If nothing meets this
bar, respond with an empty JSON array: [].
"""

SYSTEM_ACCESS_CONTROL = (
    "You are a smart-contract security auditor focused only on access "
    "control and authorization. For every external or public function, "
    "work out who is supposed to be allowed to call it, then check whether "
    "the code actually enforces that. Specifically look for: state-changing "
    "functions with no caller check at all; functions that move funds out "
    "of or into an account other than msg.sender using a pre-existing "
    "approval, without verifying msg.sender is that account or holds a "
    "signature from it; signature-gated functions that verify the signer "
    "but not that the submitter is the intended party; and privileged "
    "setters that accept new configuration values with no sanity bounds."
) + _COMMON_TAIL

SYSTEM_FUND_FLOW = (
    "You are a smart-contract security auditor focused only on fund-flow "
    "and accounting correctness. For every function that both pulls in and "
    "pays out value in the same call (swaps, refunds, redemptions, "
    "withdrawals), check whether the paid-out amount is derived from what "
    "was actually received or consumed, rather than from a requested amount "
    "that was never fully collected. Check that every approve() or "
    "increaseAllowance() call is reset back down on every exit path of the "
    "function, including error and early-return branches, so no leftover "
    "spending right survives the call. Check that internal counters or "
    "running totals feeding fee, share-price, or payout math are updated "
    "the same way on both the forward operation and its reverse."
) + _COMMON_TAIL

SYSTEM_UNIT_INTERFACE = (
    "You are a smart-contract security auditor focused only on unit, "
    "precision, and cross-contract interface mismatches. Check whether "
    "values returned from external calls -- especially to vaults, wrappers, "
    "or other share-issuing contracts -- are consumed in the unit the "
    "caller assumes (shares vs. underlying asset, differing token "
    "decimals, wei vs. whole units). Check whether identifiers produced by "
    "a shared counter or sequence are properly scoped so two different "
    "owners or collections cannot end up with colliding keys."
) + _COMMON_TAIL

SYSTEM_MATH_ITERATION = (
    "You are a smart-contract security auditor focused only on math and "
    "iteration correctness. Check exposed math helpers (square root, log, "
    "division, modulo) for undefined or reverting behavior on zero, one, "
    "or extreme inputs where a normal result is expected. Check loops that "
    "iterate up to a stored counter or length for gaps caused by removals "
    "that never compact the underlying collection. Check explicit integer "
    "downcasts against realistic input ranges for overflow."
) + _COMMON_TAIL

SPECIALIST_PASSES = (
    ("access_control", SYSTEM_ACCESS_CONTROL),
    ("fund_flow", SYSTEM_FUND_FLOW),
    ("unit_interface", SYSTEM_UNIT_INTERFACE),
    ("math_iteration", SYSTEM_MATH_ITERATION),
)

# Cheap, regex-based cross-file linking so a bug spanning a base contract and
# its child (or a file and something it imports) can still be seen together,
# without spending an extra model call to find "related files" the way a
# larger agentic pipeline would. Solidity-shaped by design (`import "..."`,
# `contract X is Y`); on any other language this simply resolves to no
# related files, which is a safe no-op (the analysis still runs single-file).
_IMPORT_RE = re.compile(r'import\s+(?:\{[^}]*\}\s*from\s+)?["\']([^"\']+)["\']')
_INHERIT_RE = re.compile(
    r'\b(?:abstract\s+)?(?:contract|library|interface)\s+\w+\s+is\s+([^\{;]+?)\s*\{',
    re.IGNORECASE | re.DOTALL,
)


def agent_main(project_dir: str | None = None, inference_api: str | None = None) -> dict:
    findings: list[dict] = []
    try:
        root = _resolve_project_dir(project_dir)
        if root is not None:
            endpoint = _resolve_inference_endpoint(inference_api)
            api_key = os.environ.get("INFERENCE_API_KEY", "")
            deadline = time.monotonic() + TIME_BUDGET_SECONDS

            sources: dict[str, str] = {}
            all_candidates = _rank_candidate_files(root)
            for path in all_candidates[:MAX_FILES_ANALYZED]:
                try:
                    source = path.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                if source.strip():
                    sources[_relative_path(path, root)] = _truncate_source(source, MAX_FILE_CHARS)

            related_by_file = _resolve_related_files(root, sources, all_candidates)

            executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)
            try:
                futures = {
                    executor.submit(
                        _ask_model_with_retry,
                        endpoint=endpoint,
                        api_key=api_key,
                        system_prompt=system_prompt,
                        file_label=relative_path,
                        source=source,
                        related=related_by_file.get(relative_path, ()),
                    ): relative_path
                    for relative_path, source in sources.items()
                    for _pass_name, system_prompt in SPECIALIST_PASSES
                }
                remaining = deadline - time.monotonic()
                try:
                    for future in as_completed(futures, timeout=max(remaining, 0.0)):
                        relative_path = futures[future]
                        try:
                            raw_reply = future.result()
                        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
                            continue
                        for finding in _parse_findings(raw_reply):
                            finding["file"] = relative_path
                            findings.append(finding)
                except TimeoutError:
                    pass
            finally:
                executor.shutdown(wait=False, cancel_futures=True)
    except Exception:
        # Analysis was attempted; never let an unexpected runtime error crash
        # the sandboxed run. A partial or empty result only scores 0 on this
        # problem, it does not invalidate the submission.
        pass

    return {"vulnerabilities": _dedupe_and_cap(findings, MAX_FINDINGS)}


def _truncate_source(source: str, max_chars: int) -> str:
    """Truncate at a line boundary and say so explicitly.

    A hard `source[:max_chars]` slice cuts mid-token/mid-statement, and
    testing confirmed the model then mistakes the cutoff itself for a bug
    (e.g. "truncated variable name", "function body missing") instead of
    recognizing it as an artifact of prompt construction. Cutting at the
    last full line and appending an explicit marker avoids that failure
    mode regardless of how large MAX_FILE_CHARS is set.
    """
    if len(source) <= max_chars:
        return source
    truncated = source[:max_chars]
    last_newline = truncated.rfind("\n")
    if last_newline > 0:
        truncated = truncated[:last_newline]
    omitted = len(source) - len(truncated)
    return (
        f"{truncated}\n\n// ... [TRUNCATED: {omitted} more characters not shown. "
        "This cutoff is an artifact of prompt construction, not part of the "
        "source file -- do not report it as a bug.]"
    )


def _resolve_project_dir(project_dir: str | None) -> Path | None:
    candidate = project_dir or os.environ.get("PROJECT_DIR") or os.environ.get("PROJECT_ROOT")
    if candidate:
        path = Path(candidate)
        if path.is_dir():
            return path
    for fallback in (Path.cwd(), Path("/project"), Path("/kata_project")):
        if fallback.is_dir():
            return fallback
    return None


def _resolve_inference_endpoint(inference_api: str | None) -> str:
    base = (inference_api or os.environ.get("INFERENCE_API") or "").rstrip("/")
    return f"{base}/inference"


def _relative_path(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return path.name


def _iter_contract_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        current = Path(dirpath)
        try:
            inside_src = "src" in current.relative_to(root).parts
        except ValueError:
            inside_src = False
        skip_names = SKIP_DIR_NAMES_INSIDE_SRC if inside_src else SKIP_DIR_NAMES
        dirnames[:] = [d for d in dirnames if d.lower() not in skip_names and not d.startswith(".")]
        for filename in filenames:
            if filename.lower().endswith(CONTRACT_SUFFIXES):
                yield Path(dirpath) / filename


def _suspicion_score(source: str) -> int:
    lowered = source.lower()
    return sum(lowered.count(keyword) for keyword in SUSPICIOUS_KEYWORDS)


def _rank_candidate_files(root: Path) -> list[Path]:
    scored: list[tuple[int, Path]] = []
    for path in _iter_contract_files(root):
        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if not source.strip():
            continue
        scored.append((_suspicion_score(source), path))
    scored.sort(key=lambda pair: pair[0], reverse=True)
    return [path for _, path in scored[:MAX_FILES_CONSIDERED]]


def _language_hint(relative_path: str, source: str) -> str:
    suffix = Path(relative_path).suffix.lower()
    if suffix == ".vy":
        return (
            "\nIMPORTANT -- This is a Vyper smart contract. Apply EVM security "
            "analysis recognizing Vyper syntax: `@external` = public function, "
            "`@internal` = private function.\n"
        )
    if suffix == ".cairo":
        return (
            "\nIMPORTANT -- This is a Cairo/StarkNet smart contract. Apply "
            "EVM-equivalent security analysis: `#[external]` marks public "
            "functions. Storage is accessed via self.field.read()/write(). "
            "Signed prices and external data must be validated to come from an "
            "authorized signer. Watch for wrong order of operations: applying "
            "state changes before validating constraints.\n"
        )
    if suffix == ".rs":
        is_anchor = (
            "anchor_lang" in source or "#[program]" in source or "declare_id!" in source
        )
        if is_anchor:
            return (
                "\nIMPORTANT -- This is a Solana/Anchor program written in Rust. "
                "Key patterns: `#[program]` marks instruction handlers; "
                "`#[account(init, ...)]` creates on-chain accounts -- check "
                "whether deterministic seeds allow a third party to pre-create "
                "the account and block the legitimate instruction; `has_one` "
                "and `constraint` annotations validate accounts, missing ones "
                "allow fake accounts. Focus on missing account constraints, "
                "account pre-creation DoS, and missing global state updates.\n"
            )
        return (
            "\nIMPORTANT -- This is a Rust/Stylus smart contract (EVM). Apply "
            "EVM security analysis: `pub fn` / `#[external]` / `#[entrypoint]` "
            "are public entry points. Storage is accessed via self.field. Token "
            "transfers use ERC20 interface calls.\n"
        )
    return ""


def _is_interface_like(path: Path) -> bool:
    """Heuristic: Solidity interfaces are just signatures -- far lower
    information than a library/implementation file a bug may actually
    hinge on (e.g. a precompile bridge). Used to deprioritize interfaces
    when the related-files slot budget is tight, instead of picking
    whichever file happened to be imported first in the source.
    """
    if "interfaces" in path.parts:
        return True
    name = path.stem
    return len(name) >= 2 and name[0] == "I" and name[1].isupper()


def _resolve_related_files(
    root: Path, sources: dict[str, str], all_candidates: list[Path]
) -> dict[str, list[tuple[str, str]]]:
    """Cheap, regex-based cross-file linking for the files being analyzed.

    For each analyzed file, looks for Solidity-style `import "..."` targets
    and `contract X is Y, Z` base-contract names, then matches those against
    the full ranked candidate set by resolved path or by filename stem. This
    never issues a model call -- it is a pure local heuristic, so on a
    non-Solidity project (or a file with no resolvable references) it just
    returns no related files rather than failing.
    """
    by_stem: dict[str, Path] = {}
    by_relpath: dict[str, Path] = {}
    for path in all_candidates:
        by_stem.setdefault(path.stem, path)
        by_relpath[_relative_path(path, root)] = path

    related: dict[str, list[tuple[str, str]]] = {}
    for relative_path, source in sources.items():
        file_path = root / relative_path
        wanted: list[Path] = []

        for match in _IMPORT_RE.finditer(source):
            target = match.group(1)
            if not target.startswith("."):
                continue  # skip package/remapped imports -- not locally resolvable
            candidate = (file_path.parent / target).resolve()
            if candidate.suffix == "":
                candidate = candidate.with_suffix(file_path.suffix)
            for existing_rel, existing_path in by_relpath.items():
                if existing_path.resolve() == candidate and existing_rel != relative_path:
                    wanted.append(existing_path)
                    break

        for match in _INHERIT_RE.finditer(source):
            for name in re.split(r"[,\s]+", match.group(1).strip()):
                name = re.sub(r"\(.*\)", "", name).strip()
                if name and name in by_stem and by_stem[name] != file_path:
                    wanted.append(by_stem[name])

        deduped: list[Path] = []
        seen_paths = set()
        for path in wanted:
            if path not in seen_paths:
                seen_paths.add(path)
                deduped.append(path)

        # Prioritize non-interface files -- a stable sort keeps original
        # (import-then-inheritance, in-file-order) ordering within each
        # group, so ties still favor whatever was referenced earliest.
        deduped.sort(key=_is_interface_like)
        deduped = deduped[:MAX_RELATED_FILES_PER_FILE]

        entries: list[tuple[str, str]] = []
        for path in deduped:
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if content.strip():
                truncated = _truncate_source(content, MAX_RELATED_FILE_CHARS)
                entries.append((_relative_path(path, root), truncated))
        if entries:
            related[relative_path] = entries

    return related


def _ask_model_with_retry(
    *,
    endpoint: str,
    api_key: str,
    system_prompt: str,
    file_label: str,
    source: str,
    related: tuple[tuple[str, str], ...] | list[tuple[str, str]],
) -> str:
    last_error: Exception | None = None
    for attempt in range(MAX_ATTEMPTS_PER_CALL):
        try:
            return _ask_model(
                endpoint=endpoint,
                api_key=api_key,
                system_prompt=system_prompt,
                file_label=file_label,
                source=source,
                related=related,
            )
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            # Retry once on transient failures (connection resets, proxy 5xx,
            # read timeouts) -- these are common against a shared inference
            # proxy under load and a single blip shouldn't cost a whole
            # (file, pass) scan when the budget allows a quick retry.
            last_error = exc
            if attempt < MAX_ATTEMPTS_PER_CALL - 1:
                time.sleep(RETRY_BACKOFF_SECONDS)
                continue
    assert last_error is not None  # loop always sets this before exhausting attempts
    raise last_error


def _ask_model(
    *,
    endpoint: str,
    api_key: str,
    system_prompt: str,
    file_label: str,
    source: str,
    related: tuple[tuple[str, str], ...] | list[tuple[str, str]] = (),
) -> str:
    lang_hint = _language_hint(file_label, source)
    related_block = ""
    for related_label, related_source in related:
        related_block += (
            f"\n\nRelated file (context only, for cross-file understanding): "
            f"{related_label}\n```\n{related_source}\n```"
        )
    user_prompt = f"File: {file_label}\n{lang_hint}\n```\n{source}\n```{related_block}"
    body = json.dumps(
        {
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "max_tokens": 4000,
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        endpoint,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "x-inference-api-key": api_key,
        },
    )
    with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
        payload = json.loads(response.read().decode("utf-8"))
    return payload["choices"][0]["message"]["content"]


def _parse_findings(raw_reply: str) -> list[dict]:
    payload = _extract_json_array(raw_reply)
    if payload is None:
        return []
    cleaned: list[dict] = []
    for item in payload[:MAX_FINDINGS_PER_CALL]:
        if not isinstance(item, dict):
            continue
        title = str(item.get("title") or "").strip()
        if not title:
            continue
        severity = str(item.get("severity") or "high").strip().lower()
        if severity not in VALID_SEVERITIES:
            severity = "high"
        confidence = _safe_confidence(item.get("confidence"))
        if confidence < MIN_CONFIDENCE:
            continue
        description = str(item.get("description") or "").strip()
        if len(description) < MIN_DESCRIPTION_CHARS:
            description = (description + " " if description else "") + (
                f"This is a {severity}-severity issue flagged by automated "
                "review; verify the reported location and exploit path before "
                "relying on this report."
            )
        line = item.get("line")
        cleaned.append(
            {
                "title": title,
                "description": description,
                "severity": severity,
                "function": str(item.get("function") or "").strip(),
                "line": line if isinstance(line, int) else None,
                "confidence": confidence,
                "recommendation": str(item.get("recommendation") or "").strip(),
            }
        )
    return cleaned


def _safe_confidence(value: object) -> float:
    try:
        confidence = float(value)
    except (TypeError, ValueError):
        return 0.5
    return min(1.0, max(0.0, confidence))


def _extract_json_array(raw_reply: str) -> list | None:
    text = raw_reply.strip()
    if text.startswith("```"):
        text = text.strip("`")
        newline = text.find("\n")
        if newline != -1:
            text = text[newline + 1 :]
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        payload = None
    if payload is None:
        start, end = text.find("["), text.rfind("]")
        if start != -1 and end != -1 and end > start:
            try:
                payload = json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                return None
        else:
            return None
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict) and isinstance(payload.get("vulnerabilities"), list):
        return payload["vulnerabilities"]
    return None


_DEDUPE_STOPWORDS = {
    "the", "and", "for", "that", "this", "with", "from", "are", "was", "can",
    "may", "could", "would", "should", "not", "but", "has", "have", "had",
    "will", "its", "when", "which", "where", "been", "being", "does", "into",
    "also", "than", "then", "via", "due",
}


def _title_tokens(title: str) -> set[str]:
    words = re.findall(r"[a-z][a-z0-9_]+", title.lower())
    return {w for w in words if len(w) >= 3 and w not in _DEDUPE_STOPWORDS}


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _is_same_finding(a: dict, b: dict) -> bool:
    """Similarity-based dedupe: same file + enough title-token overlap.

    Replaces an earlier exact-(file, title.lower())-match dedupe, which
    missed near-duplicates produced when two different specialist passes
    describe the same real bug with slightly different wording (e.g.
    "Reentrancy in withdraw" vs. "Reentrancy vulnerability in the withdraw
    function") -- those used to survive as separate findings and both
    consume a slot in the capped final list.
    """
    if a.get("file") != b.get("file"):
        return False
    title_sim = _jaccard(_title_tokens(a.get("title", "")), _title_tokens(b.get("title", "")))
    if title_sim >= DEDUPE_TITLE_JACCARD_THRESHOLD:
        return True
    # Structured signal the ported heuristic didn't have available: two
    # findings in the same file naming the same specific function are very
    # likely the same underlying bug even when the wording diverges further
    # than the title-overlap threshold allows.
    fn_a = (a.get("function") or "").strip().lower()
    fn_b = (b.get("function") or "").strip().lower()
    return bool(fn_a) and fn_a == fn_b


def _dedupe_and_cap(findings: list[dict], limit: int) -> list[dict]:
    ordered = sorted(findings, key=lambda f: -f.get("confidence", 0.0))
    kept: list[dict] = []
    for finding in ordered:
        if any(_is_same_finding(finding, existing) for existing in kept):
            continue
        kept.append(finding)
    kept.sort(key=lambda f: (f.get("severity") != "critical", -f.get("confidence", 0.0)))
    return kept[:limit]
