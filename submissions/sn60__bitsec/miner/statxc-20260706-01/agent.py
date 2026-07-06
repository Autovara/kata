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
    "interfaces", "interface",
}
# Names in SKIP_DIR_NAMES that are only ever vendored/tooling directories
# when they sit OUTSIDE a project's own `src/` tree. Confirmed by local
# testing: a real project had both a top-level `lib/` (vendored forge-std,
# openzeppelin) AND a first-party `src/lib/` (Hyperliquid precompile bridge
# code) -- the blanket name match skipped both, hiding the file most
# relevant to the actual vulnerability. Once inside `src/`, only test/mock/
# interface subdirectories are still excluded -- interfaces are confirmed
# by live verification-pass testing to have no implementation to have a
# real bug in (a real judge/verifier refutes findings reported against
# them), so they're not worth spending a primary scan slot on.
SKIP_DIR_NAMES_INSIDE_SRC = {"test", "tests", "mock", "mocks", "interfaces", "interface"}
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
VERIFY_ENABLED = True    # Hound-inspired: re-examine every surviving finding against the real
                         # source with a skeptical second pass before final output, instead of
                         # trusting first-pass confidence alone. Budget headroom is large (real
                         # runs use well under half of TIME_BUDGET_SECONDS), so this is affordable.
VERIFY_DROP_THRESHOLD = 0.2   # Deliberately much stricter than MIN_CONFIDENCE (0.6): promotion
                              # ranks detection score (recall) ABOVE precision, so wrongly dropping
                              # one true positive costs more than keeping an extra false positive
                              # costs (a lower-priority tiebreaker). Verification mostly demotes
                              # weak findings via confidence (letting the cap prune them if we're
                              # over budget); only near-certain refutations are removed outright.
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
#
# The explicit file/function-in-prose instruction below is scorer-informed,
# not stylistic: the real SN60 scorer (Bitsec-AI/sandbox validator/scorer.py)
# never reads our structured "file"/"function" JSON keys. Its LLM judge only
# sees title + description + regex-extracted "FileHints"/"FunctionHints" --
# and those hints are pulled from the title/description TEXT via regex, not
# from our JSON fields. Naming the file and function in prose is therefore
# load-bearing for matching, not redundant with the structured fields.
_COMMON_TAIL = f"""
Only report a finding if you can state the exact function name and a
concrete scenario (inputs, call sequence, or numeric example) that shows
the impact. If you cannot show a concrete path, do not report it.

Name the exact source file (with its extension, e.g. "StakingManager.sol")
and the exact function (written as `functionName(...)`) directly in the
title or description text -- in addition to, not instead of, the "function"
field below.

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

# Second-pass verifier: re-examines a single already-reported finding against
# the real source, skeptically, before it reaches final output. A finding's
# confidence isn't final the moment a specialist pass proposes it -- it gets
# revisited once more against the evidence before being kept.
SYSTEM_VERIFY = """
You are a skeptical senior smart-contract security reviewer. You will be
shown a previously-reported finding and the full source file it refers to.
Your job is to challenge the finding, not confirm it by default.

Check specifically:
- Does the named function actually exist and match the described location?
- Does the code actually behave as described? Re-read the relevant lines
  directly rather than trusting the summary.
- Is there a guard, check, or invariant elsewhere in the file that the
  original finding missed and that prevents the claimed impact?
- Is the claimed impact concrete and reachable, or vague/speculative?

Respond with ONLY a JSON object (no prose, no markdown fences):
{"verdict": "confirmed" | "refuted" | "uncertain",
 "confidence": 0-1 float,
 "reason": "one or two sentences"}

"confidence" always means how confident you are that the ORIGINAL FINDING
describes a real, exploitable vulnerability -- 0.0 means definitely not
real, 1.0 means definitely real. It is never your confidence in the verdict
label itself: a "refuted" verdict should carry a LOW confidence (the finding
is probably not real), not a high one.

Lower the confidence if the original claim is wrong, exaggerated, or already
handled elsewhere in the code. Raise it only if you can point to the exact
lines that prove the issue is real and reachable. When in doubt, lean
toward a lower confidence rather than a higher one.
"""

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

            findings = _dedupe_findings(findings)
            if VERIFY_ENABLED and findings:
                findings = _run_verification_pass(findings, sources, endpoint, api_key, deadline)
    except Exception:
        # Analysis was attempted; never let an unexpected runtime error crash
        # the sandboxed run. A partial or empty result only scores 0 on this
        # problem, it does not invalidate the submission.
        pass

    return {"vulnerabilities": _cap_findings(findings, MAX_FINDINGS)}


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


def _with_retry(call):
    """Retry a zero-arg inference call once on a transient failure.

    Connection resets, proxy 5xx, and read timeouts are common against a
    shared inference proxy under load, and a single blip shouldn't cost a
    whole (file, pass) scan or verification call when the budget allows a
    quick retry.
    """
    last_error: Exception | None = None
    for attempt in range(MAX_ATTEMPTS_PER_CALL):
        try:
            return call()
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_error = exc
            if attempt < MAX_ATTEMPTS_PER_CALL - 1:
                time.sleep(RETRY_BACKOFF_SECONDS)
                continue
    assert last_error is not None  # loop always sets this before exhausting attempts
    raise last_error


def _post_inference(*, endpoint: str, api_key: str, system_prompt: str, user_prompt: str) -> str:
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


def _ask_model_with_retry(
    *,
    endpoint: str,
    api_key: str,
    system_prompt: str,
    file_label: str,
    source: str,
    related: tuple[tuple[str, str], ...] | list[tuple[str, str]],
) -> str:
    return _with_retry(
        lambda: _ask_model(
            endpoint=endpoint,
            api_key=api_key,
            system_prompt=system_prompt,
            file_label=file_label,
            source=source,
            related=related,
        )
    )


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
    return _post_inference(
        endpoint=endpoint, api_key=api_key, system_prompt=system_prompt, user_prompt=user_prompt
    )


def _build_verify_prompt(finding: dict, source: str) -> str:
    return (
        f"File: {finding.get('file', 'unknown')}\n"
        f"Reported function: {finding.get('function', 'unknown')}\n"
        f"Reported title: {finding.get('title', '')}\n"
        f"Reported description: {finding.get('description', '')}\n"
        f"Reported severity: {finding.get('severity', '')}\n"
        f"Reported confidence: {finding.get('confidence', 0)}\n\n"
        f"Full source file for verification:\n```\n{source}\n```"
    )


def _verify_finding_with_retry(*, endpoint: str, api_key: str, finding: dict, source: str) -> str:
    user_prompt = _build_verify_prompt(finding, source)
    return _with_retry(
        lambda: _post_inference(
            endpoint=endpoint, api_key=api_key, system_prompt=SYSTEM_VERIFY, user_prompt=user_prompt
        )
    )


def _parse_verify_reply(raw_reply: str) -> dict | None:
    text = raw_reply.strip()
    if text.startswith("```"):
        text = text.strip("`")
        newline = text.find("\n")
        if newline != -1:
            text = text[newline + 1 :]
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if start != -1 and end != -1 and end > start:
            try:
                payload = json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                return None
        else:
            return None
    return payload if isinstance(payload, dict) else None


def _run_verification_pass(
    findings: list[dict], sources: dict[str, str], endpoint: str, api_key: str, deadline: float
) -> list[dict]:
    """Re-examine each surviving finding against its real source once more.

    Findings the verifier can't reach in time keep their original
    confidence unchanged -- a verification call we didn't get to is never
    treated as a strike against a finding, matching this agent's existing
    graceful-degradation philosophy for every other inference call.
    """
    if not findings:
        return findings

    executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)
    verdicts: dict[int, dict] = {}
    try:
        futures = {}
        for finding in findings:
            source = sources.get(finding.get("file", ""))
            if source is None:
                continue
            futures[
                executor.submit(
                    _verify_finding_with_retry,
                    endpoint=endpoint,
                    api_key=api_key,
                    finding=finding,
                    source=source,
                )
            ] = finding
        remaining = deadline - time.monotonic()
        try:
            for future in as_completed(futures, timeout=max(remaining, 0.0)):
                finding = futures[future]
                try:
                    raw_reply = future.result()
                except (urllib.error.URLError, TimeoutError, OSError, ValueError):
                    continue
                verdict = _parse_verify_reply(raw_reply)
                if verdict is not None:
                    verdicts[id(finding)] = verdict
        except TimeoutError:
            pass
    finally:
        executor.shutdown(wait=False, cancel_futures=True)

    kept: list[dict] = []
    for finding in findings:
        verdict = verdicts.get(id(finding))
        if verdict is None:
            kept.append(finding)  # never verified in time -- keep as originally scored
            continue
        new_confidence = _safe_confidence(verdict.get("confidence"))
        # Drop only on a near-certain refutation (see VERIFY_DROP_THRESHOLD).
        # The "verdict" label itself is not used as a drop trigger: testing
        # showed a model can return verdict=refuted with a HIGH confidence
        # value (reading "confidence" as confidence-in-its-own-verdict rather
        # than confidence-the-bug-is-real, despite the prompt saying
        # otherwise) -- the numeric floor is the single, robust source of
        # truth regardless of how the label and number relate for a given
        # reply. Anything above the floor is demoted via confidence and left
        # for the final cap to prune if findings exceed MAX_FINDINGS.
        if new_confidence < VERIFY_DROP_THRESHOLD:
            continue
        finding["confidence"] = new_confidence
        kept.append(finding)
    return kept


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


def _dedupe_findings(findings: list[dict]) -> list[dict]:
    ordered = sorted(findings, key=lambda f: -f.get("confidence", 0.0))
    kept: list[dict] = []
    for finding in ordered:
        if any(_is_same_finding(finding, existing) for existing in kept):
            continue
        kept.append(finding)
    return kept


def _cap_findings(findings: list[dict], limit: int) -> list[dict]:
    ordered = sorted(
        findings, key=lambda f: (f.get("severity") != "critical", -f.get("confidence", 0.0))
    )
    return ordered[:limit]
