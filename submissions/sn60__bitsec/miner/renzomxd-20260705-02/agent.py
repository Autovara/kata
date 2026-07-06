"""SN60 / Bitsec miner agent: ranked file scope + heuristic multi-tool scan + merge.

Adapted from a larger multi-model agentic pipeline the same author built and ran
independently against Bitsec's own platform, trimmed to Kata's SN60 sandbox
contract: one self-contained file, stdlib only, one pinned model reachable only
through `inference_api`, no internet, no helper files.

Pipeline:
  Phase 1 -- rank files by import-graph centrality + entry-point density, then
             pull in parent/shared-infra files referenced by the top files.
  Phase 2 -- pick a subset of specialist prompts per file via cheap keyword
             heuristics, instead of running every prompt on every file or
             paying for an LLM router call.
  Phase 3 -- run the picked (file, prompt) pairs concurrently against the
             single pinned inference endpoint under a hard wall-clock budget.
  Phase 4 -- cluster + merge near-duplicate findings (Jaccard similarity),
             run a second adversarial "skeptic" pass that tries to refute each
             merged finding, then rank with a rule-based scorer and cap.
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# ---- CONFIG ----
CONTRACT_SUFFIXES = (".sol", ".vy", ".rs", ".move", ".cairo", ".fe")
SKIP_DIR_NAMES = {
    "node_modules", "lib", "libs", "vendor", "test", "tests",
    "mock", "mocks", "script", "scripts", "artifacts", "cache", "out",
    "forge-std", "openzeppelin-contracts", "openzeppelin",
}
MAX_FILES_CONSIDERED = 60
MAX_FILES_ANALYZED = 8
PARENT_CLASS_MAX_ADD = 3
MAX_FILE_CHARS = 12000
MIN_PICKS_PER_FILE = 6
MAX_FINDINGS = 30
MIN_CONFIDENCE = 0.7
MIN_DESCRIPTION_CHARS = 80
VALID_SEVERITIES = ("high", "critical")
TIME_BUDGET_SECONDS = 1200.0
REQUEST_TIMEOUT_SECONDS = 120
MAX_WORKERS = 10

# Skeptic review: adversarial second pass, carved from remaining time budget.
# Fails open on any failure (timeout/bad reply/no budget) -- never loses work.
SKEPTIC_TIME_BUDGET_SECONDS = 240.0
SKEPTIC_MIN_BUDGET_SECONDS = 20.0
SKEPTIC_MAX_WORKERS = 8
SKEPTIC_REQUEST_TIMEOUT_SECONDS = 90
SKEPTIC_MAX_TOKENS = 4000

FORMAT_INSTRUCTIONS = (
    "Return ONLY raw JSON in exactly this shape:\n"
    '{"vulnerabilities": [{"title": "...", "description": "...", '
    '"vulnerability_type": "...", "severity": "high"|"critical", '
    '"confidence": <0-1 float>, "location": "...", '
    '"line": <int line number in the file, or null if unknown>, '
    '"vulnerable_code_snippet": "the exact vulnerable line(s) of code, verbatim from the file, '
    'or empty string if not applicable"}]}\n'
    'If nothing meets the bar above, return {"vulnerabilities": []}.'
)

# Shared false-positive suppression list used by the fund-flow family and the
# access-control / unit-interface / math-iteration / execution-context passes.
_DO_NOT_REPORT = """
<do_not_report>
Do NOT report findings in these categories -- they are consistently false positives:

1. ADMIN/ROLE-GATED FUNCTIONS: functions behind onlyRole()/onlyOwner()/onlyAdmin/requiresAuth
   are not "missing access control" -- assume the role assignment is correct unless you can
   prove otherwise.
2. DECIMAL SCALING: not a bug if the code has explicit conversion functions for it.
3. GAS DoS / UNBOUNDED LOOPS: only if the bound is attacker-controlled, uncapped, AND realistic
   usage exceeds block gas limits.
4. GENERIC REENTRANCY: only with a state write AFTER an external call, no guard, AND a concrete
   profit path.
5. ERC20 PERMIT FRONTRUNNING: never report.
6. UNSAFE INTEGER CASTING: only if a realistic input value exceeds the target type's bounds.
7. UNCHECKED RETURN VALUES: not a bug on calls that revert by default, or SafeERC20 transfers.
8. RECEIVE/FALLBACK FUND MIXING: only if funds can be concretely stolen or permanently locked.
9. ORACLE STALENESS: only if it bypasses an existing staleness/freshness check in the code.
10. SLIPPAGE: not missing if the function accepts slippage parameters the caller controls.
11. PAUSE MECHANISM: only with a concrete bypass that doesn't require admin keys.
12. TOKEN APPROVAL PERSISTENCE: only with a specific drain path via the remaining allowance.
</do_not_report>
"""

_FUND_FLOW_HEADER = """
<role>
You are a world-class Smart Contract Security Auditor specializing in fund-flow accounting,
state-variable synchronization, and economic state manipulation. You produce only high-confidence,
exploit-ready findings with concrete proof.
You may be auditing contracts written in ANY EVM-compatible language -- Solidity, Rust/Stylus,
Vyper, Huff, or others. The same EVM vulnerabilities exist regardless of source language.
Treat any helper that pulls, debits, transfers, burns, or escrows tokens as a value-moving operation.
</role>

<scope>
Audit ONLY the provided file. Use related files only when explicitly referenced (imports,
inheritance, delegatecall). First identify what type of contract this is (vault, router,
staking, factory, exchange, pool, strategy, library, token) and focus your analysis accordingly.
</scope>
"""

_FUND_FLOW_TAIL = """
<dedup>
Before reporting, check if you are reporting the same root cause from different angles.
Report each unique root cause ONLY ONCE. Combine related symptoms into a single finding.
Report at most 4 findings per analysis -- only the most impactful ones for this pass's focus.
</dedup>

<evidence_requirements>
For each vulnerability:
- Exact function name(s) and variables involved
- Concrete numerical example showing the issue
- Step-by-step failure/attack path
- Direct impact: who loses funds, how much, or what breaks
If you cannot prove the path with specifics, DO NOT report.
</evidence_requirements>

<confidence>
Very High (0.95-1.0): Internal variable not updated after operation; concrete before/after showing
divergence; or provable debit/credit mismatch with numeric proof.
High (0.85-0.94): State ordering issue with specific scenario; missing slippage with clear path.
Medium-High (0.75-0.84): Complex multi-step flow with conditional exploitation.
Below 0.70: Do not report as HIGH/CRITICAL. For HIGH/CRITICAL severity: confidence >= 0.70 required.
</confidence>
""" + _DO_NOT_REPORT + """
<output>
IMPORTANT: Each finding's "description" field MUST be at most 800 characters. Be concise: state
(1) the root cause, (2) the EXACT affected function name, (3) the impact from the VICTIM's
perspective, and (4) whether a third party can use this to permanently block a legitimate
operation (DoS). Do not pad with generic advice.
""" + FORMAT_INSTRUCTIONS + "\n</output>\n"

SYSTEM_A1 = _FUND_FLOW_HEADER + """
<primary_targets>
In this pass, prioritise scrutiny of how the contract returns or refunds value to a caller and the
relationship between the headline asked-for amount and what was actually moved. Treat unrelated
concerns lightly.

For any function that both takes assets in and sends assets back out in the same call, trace what
each transfer's amount actually represents -- not what the variable is named. A particular failure
shape: the pull side is sized to what will actually be used, and a second transfer back to the user
re-uses the input quantity to compute its amount -- the second transfer hands back funds that the
first transfer never took.

This pattern is especially hidden in routing / aggregator helpers that attempt one or more downstream
venues and then return unused input to the caller: each attempt has its own "tried" amount and
"actually executed" amount, and the helper's final refund must be the headline minus the SUM of all
actually-executed amounts, never the headline minus the last attempt's tried amount. Also check
whether the refund's source is the caller's own unused input (not the contract's own balance, pool
reserve, or fee accumulator computed as stated-minus-consumed while the contract only ever pulled the
consumed amount).

Report concrete, proven cases with numerical evidence.
</primary_targets>
""" + _FUND_FLOW_TAIL

SYSTEM_A2 = _FUND_FLOW_HEADER + """
<primary_targets>
In this pass, prioritise scrutiny of how the contract grants and clears spending rights it issues to
other contracts. Treat unrelated concerns lightly.

For each allowance the contract issues to another contract, trace both the issuance and the cleanup;
allowances that outlive the call that issued them become standing claims on the contract's balance
and can be exercised by the grantee long after the original work finished. Apply this check
exhaustively: every code path that performs an approve() or increaseAllowance() must end with the
matching allowance brought back to a known value (zero, or the original) on BOTH the success branch
and every early-return / error branch.

If you see a function performing an approve / increaseAllowance to a fixed downstream address as part
of normal bookkeeping -- without a matching reset to zero on the same code path -- assume that
allowance survives the function return and ask which functions on the approved address can move funds
from the granting contract.

Report concrete, proven cases with numerical evidence.
</primary_targets>
""" + _FUND_FLOW_TAIL

SYSTEM_A3 = _FUND_FLOW_HEADER + """
<primary_targets>
In this pass, prioritise scrutiny of the authority that backs each value-moving pull the contract
performs. Treat unrelated concerns lightly.

For every place the contract pulls assets from another account, trace what authorizes the pull:
confirm the source either matches msg.sender or has explicitly authorized THIS specific operation --
a signed permit whose digest binds to the exact call, or a single-use per-operation approval recorded
in storage. A pre-existing ERC20 allowance is NOT per-operation authorisation. A function that uses
that blanket allowance to move funds from any caller-named source becomes a drain primitive against
every user who has approved the contract.

For dispatch / multicall / execute helpers that take a sequence of caller-supplied subcommands and one
of those subcommands moves tokens with an explicit source field, verify the source is bound to the
outer caller before the subcommand executes.

Report concrete, proven cases with numerical evidence.
</primary_targets>
""" + _FUND_FLOW_TAIL

SYSTEM_A4 = _FUND_FLOW_HEADER + """
<primary_targets>
In this pass, prioritise scrutiny of counters and running totals that feed downstream calculations,
native-value reception, and reads of externally-influenced helpers used in privileged decisions.
Treat unrelated concerns lightly.

Counters and running totals that feed downstream calculations (fees, share prices, ratios, payouts)
drift proportionally to unbalanced traffic: when one set of operations moves a counter and the inverse
operations do not, every formula that consumes the counter inherits the error. Trace each forward
operation (deposit, stake, lock, register) to its inverse and record whether every storage field the
forward writes is also reverted by the inverse.

Whenever a mint / unlock / borrow / payout decision reads a balance / total-assets / lp-value helper,
check whether another party can spike or deflate that helper momentarily (flash-loan, donate, external
pool manipulation) between the read and the consumption.

Report concrete, proven cases with numerical evidence.
</primary_targets>
""" + _FUND_FLOW_TAIL

SYSTEM_B = """
<role>
You are a world-class Smart Contract Security Auditor specializing in access control,
authorization, permit/allowance exploitation, and signature security. You produce only
high-confidence, exploit-ready findings with concrete proof.
</role>

<scope>
Audit ONLY the provided file. Use related files only when explicitly referenced (imports,
inheritance, delegatecall). First identify what type of contract this is and focus accordingly.
</scope>

<primary_targets>
Look for access-control and authorization bugs: places where the wrong party can make the contract
do something on someone else's behalf. For every external entry-point determine the correct caller
and verify the contract enforces it; for every signature-gated entry-point check whether the
submitter is bound by the signed digest, not only the signer.

Build this as an explicit enumeration: list every externally-callable function that writes any
storage variable, and beside each note the access-control mechanism gating it. A function whose
access-control column reads NONE and that writes a storage variable downstream code uses for
authorisation, accounting, or value-routing is a finding regardless of how obvious the omission
looks. For helpers forwarding execution to a (target, calldata) supplied by the caller, check
whether target is whitelisted / restricted.

Report concrete exploit sequences with direct economic impact.
</primary_targets>

<dedup>
Report each unique root cause ONLY ONCE. If the same missing access control affects multiple
functions, report it once listing all affected functions. Report at most 8 findings per analysis.
</dedup>

<evidence_requirements>
- Exact function and parameter names
- Concrete exploit sequence (front-run, drain, or sabotage)
- Impact: who loses funds and how much
If you cannot show the exploit path, DO NOT report.
</evidence_requirements>

<confidence>
Very High (0.95-1.0): Function moves user funds with zero access control; clear drain path.
High (0.85-0.94): Approval persists after operation with exploitable execute(); front-runnable permit.
Medium-High (0.75-0.84): Access control gap requiring specific timing or cooperation.
Below 0.70: Do not report as HIGH/CRITICAL. For HIGH/CRITICAL severity: confidence >= 0.70 required.
</confidence>
""" + _DO_NOT_REPORT + """
<output>
IMPORTANT: Each finding's "description" field MUST be at most 800 characters. Be concise: state
(1) root cause, (2) EXACT affected function name, (3) impact from the victim's perspective, and
(4) whether a third party can permanently prevent the operation (DoS).
""" + FORMAT_INSTRUCTIONS + "\n</output>\n"

SYSTEM_C = """
<role>
You are a world-class Smart Contract Security Auditor specializing in unit/decimal mismatches,
return-value confusion, interface incompatibilities, and deterministic resource DoS. You produce
only high-confidence, exploit-ready findings with concrete proof.
</role>

<scope>
Audit ONLY the provided file. Use related files only when explicitly referenced (imports,
inheritance, delegatecall). First identify what type of contract this is and focus accordingly.
</scope>

<primary_targets>
Look for unit/precision and external-dependency bugs. For every cross-contract boundary verify the
unit / decimal / encoding contract actually matches the consumer's assumption. A specific shape worth
a focused check: helpers that wrap another vault, lending protocol, or share-issuing contract often
expose return values whose naming suggests one unit (the underlying asset) while the body actually
returns the wrapper's internal unit (shares, debt-units, lp-units). If the caller treats the returned
figure as if it were the underlying asset for any subsequent calculation, the protocol records and
distributes the wrong quantity for every user that touches the wrapper.

External integration code must be validated against the actual deployed ABI on every chain it
targets, not against the imported header alone. When two pieces of code compute keys for the same
shared lookup using the same recipe, the recipe must include something unique to each producer.

Report concrete numerical proofs.
</primary_targets>

<dedup>
If multiple functions share the same unit mismatch root cause, report once and list all affected
functions. Report at most 8 findings per analysis.
</dedup>

<evidence_requirements>
- Exact function names showing: what is returned, what unit, what caller expects
- Concrete numerical example
- Impact: fund loss, locked assets, or permanent DoS
If you cannot show the concrete mismatch with numbers, DO NOT report.
</evidence_requirements>

<confidence>
Very High (0.95-1.0): Provable unit/precision mismatch with concrete arithmetic showing the wrong
result.
High (0.85-0.94): Boundary conversion omits the required scaling factor, demonstrated numerically.
Medium-High (0.75-0.84): Ordering/convention assumption contradicts the actual venue convention.
Below 0.70: Do not report as HIGH/CRITICAL. For HIGH/CRITICAL severity: confidence >= 0.70 required.
</confidence>
""" + _DO_NOT_REPORT + """
<output>
IMPORTANT: Each finding's "description" field MUST be at most 800 characters. State the root cause,
the EXACT affected function name (including internal helpers), and the impact in <=800 chars.
""" + FORMAT_INSTRUCTIONS + "\n</output>\n"

SYSTEM_D = """
<role>
You are a world-class Smart Contract Security Auditor specializing in math-library integrity,
data-structure iteration correctness, and type-system edge cases. You produce only high-confidence,
exploit-ready findings with concrete proof.
</role>

<scope>
Audit ONLY the provided file. Use related files only when explicitly referenced (imports,
inheritance, delegatecall). First identify what type of contract this is and focus accordingly.
</scope>

<primary_targets>
Look for math, precision, iteration and type-casting bugs. For every exposed math primitive (sqrt,
log, exp, division, modulo, equality helpers) explicitly walk through what happens when the input is
zero, negative, one, or max-uint. Also check downcasts against realistic inputs and trace iteration
loops for off-by-one or gap-handling issues.

A specific shape to detect explicitly: a loop iterates from one to the running supply / count /
length variable, intending to visit every member of a collection that variable summarises. If the
running variable was last mutated when a member was removed without compacting the surviving
members' identifiers, the loop's terminating bound can fall out of sync with the actual live id-set.

Report concrete inputs producing the wrong output.
</primary_targets>

<dedup>
If the same root cause manifests in multiple callers, report once and list affected callers.
Report at most 8 findings per analysis.
</dedup>

<evidence_requirements>
- Concrete numerical example: specific input value that produces wrong output
- Expected vs actual output with arithmetic proof
If you cannot show a concrete breaking input, DO NOT report.
</evidence_requirements>

<confidence>
Very High (0.95-1.0): Concrete input produces provably wrong output; a domain error halts execution
for a valid edge case.
High (0.85-0.94): Specific ID gap scenario showing missed items; downcast with demonstrable overflow
for realistic values.
Medium-High (0.75-0.84): Precision loss at specific boundary requiring unusual but possible inputs.
Below 0.70: Do not report as HIGH/CRITICAL. For HIGH/CRITICAL severity: confidence >= 0.70 required.
</confidence>
""" + _DO_NOT_REPORT + """
<output>
IMPORTANT: Each finding's "description" field MUST be at most 800 characters. State the root cause,
the EXACT affected function name (including internal helpers), and the impact in <=800 chars.
""" + FORMAT_INSTRUCTIONS + "\n</output>\n"

SYSTEM_SV = """
<role>
You are a world-class Smart Contract Security Auditor specializing in state variable
completeness. Your job is to verify that every storage variable modified in one
direction has a corresponding reverse modification. You produce only high-confidence
findings about missing state updates.
</role>

<scope>
Audit ONLY the provided file. Focus on storage variable writes.
</scope>

<methodology>
Enumerate storage writes. For each variable, identify the functions that mutate it. Report
variables that drift because one path mutates them and another does not.
Do NOT report return-value issues, access control, or reentrancy. ONLY report missing state
variable updates in paired operations.
</methodology>

<primary_targets>
Report storage variables that are written in one path without a corresponding write in the
paired/reverse path. Also flag tracker variables: when a loop's body uses a variable to
remember the last item it processed but never writes the new item back at the end of each
iteration, every subsequent pass compares against the original starting value instead of the
actual previous item. Pair counter-style state variables with the IDs they are meant to
enumerate: a state variable that measures population size does not also tell you the assigned
ID range, so any code that uses the count as the upper limit of an enumeration may stop short
of the actual data once entries can be removed. Back each finding with the exact variable, both
function names, and a concrete numerical example.
</primary_targets>

<dedup>
Report at most 8 findings per analysis -- only missing state updates.
</dedup>

<evidence_requirements>
- Exact variable name, the function that WRITES it, and the paired function that doesn't
- What calculation breaks as a result
- Concrete numerical example
</evidence_requirements>

<confidence>
Very High (0.95-1.0): Variable clearly written in forward function, absent from reverse.
Below 0.70: Do not report.
For HIGH/CRITICAL severity: confidence >= 0.70 required.
</confidence>

<output>
IMPORTANT: Each finding's "description" field MUST be at most 800 characters.
""" + FORMAT_INSTRUCTIONS + "\n</output>\n"

PROMPT_LIFECYCLE = """
<role>
You are a smart contract security analyst focused on state machine correctness.
</role>

<scope>
Analyse ONLY the provided file.
</scope>

<method>
CHECK 1 -- STATE TRANSITION GUARDS: for each resource with a defined lifecycle (orders,
  positions, loans, locks, claims, migrations, pools), verify every function checks the
  required precondition state before acting. When the lifecycle has a TERMINAL state
  (cancelled, closed, settled, claimed, refunded), check EVERY mutator -- not just execute /
  fill, but modify / update / edit / resize / reschedule too. Build this as an explicit
  per-resource enumeration: (a) the storage field recording terminal status, (b) every
  external/public function writing ANY storage of an existing instance, (c) whether that
  field is read BEFORE the first storage write in each. An absent read with a reachable
  storage write is a finding regardless of what else the function validates first.

CHECK 2 -- OPERATION ORDERING: for functions that both update state AND validate
  post-conditions, verify security-critical checks read pre-mutation values, not the
  already-updated state.
</method>

<do_not_report>
- Protection already visibly correct in the code
- Reentrancy when a nonReentrant guard is present
- State transitions requiring admin-only privileged action
</do_not_report>

<output_requirements>
Each finding: (1) function name, (2) the guard or ordering issue, (3) concrete exploit path,
(4) whether a third party can PERMANENTLY block this operation for legitimate users (DoS).
Report at most 4 findings, confidence >= 0.75.
</output_requirements>

<output>
""" + FORMAT_INSTRUCTIONS + "\n</output>\n"

PROMPT_AUTHORIZED_SOURCE = """
<role>
You are a smart contract security analyst focused on whether the caller is authorised
for the source / beneficiary they name.
</role>

<scope>
Analyse ONLY the provided file.
</scope>

<method>
CHECK 1 -- CALLER-NAMED SOURCE OF FUNDS: for calls with a "from"/"owner"/"source"/"holder"
  argument (transferFrom, permit2.transferFrom, pullToken, withdrawOnBehalf), verify the named
  source is msg.sender OR has authorised THIS specific operation (digest-bound permit or
  single-use approval). A pre-existing ERC20 allowance is NOT per-operation authorisation.

CHECK 2 -- CALLER-NAMED BENEFICIARY OF STATE: for functions letting the caller name another
  account AND wire a downstream attribute onto it (delegate, operator, minted-token owner),
  verify the caller is that account or has its explicit consent.

CHECK 3 -- COMMAND-DISPATCH SOURCE BINDING: for execute()/dispatch()/multicall entries whose
  subcommands move tokens with an explicit source field, verify the source is bound to the
  outer caller before the subcommand executes.

CHECK 4 -- PERMISSIONLESS FEE / ACCOUNTING ROLLOVER: for anyone-can-trigger fee/mint/payout
  bookkeeping steps, check whether the trigger has timing-controllable accounting side effects.
</method>

<do_not_report>
- Functions where the source argument is fixed to msg.sender or address(this).
- Permit / signature paths that fully validate the digest against the call.
- Internal helpers not callable from outside.
- Plain transfer() -- the caller is implicitly the source.
</do_not_report>

<output_requirements>
Each finding: (1) function name, (2) the caller-controlled parameter, (3) the exact pre-condition
the attacker exploits, (4) the victim and the concrete loss.
Report at most 4 findings, confidence >= 0.75.
</output_requirements>

<output>
""" + FORMAT_INSTRUCTIONS + "\n</output>\n"

# name -> (system_prompt, max findings accepted from a single call to that prompt)
TOOL_PROMPTS = {
    "SYSTEM_A1": (SYSTEM_A1, 4),
    "SYSTEM_A2": (SYSTEM_A2, 4),
    "SYSTEM_A3": (SYSTEM_A3, 4),
    "SYSTEM_A4": (SYSTEM_A4, 4),
    "SYSTEM_B": (SYSTEM_B, 8),
    "SYSTEM_C": (SYSTEM_C, 8),
    "SYSTEM_D": (SYSTEM_D, 8),
    "SYSTEM_SV": (SYSTEM_SV, 8),
    "PROMPT_LIFECYCLE": (PROMPT_LIFECYCLE, 4),
    "PROMPT_AUTHORIZED_SOURCE": (PROMPT_AUTHORIZED_SOURCE, 4),
}


def _heuristic_picks(source: str) -> list[str]:
    """Cheap keyword-triggered tool selection, trimmed from an 18-tool bank +
    LLM router down to this file's 11 tools + pure-Python keyword matching --
    no router call needed at our scale (a handful of files, not 22)."""
    low = source.lower()
    picks: set[str] = {"SYSTEM_SV", "PROMPT_AUTHORIZED_SOURCE", "PROMPT_LIFECYCLE"}
    if any(k in low for k in ("transfer", "msg.value", "call{value", "withdraw", "deposit", "safetransfer")):
        picks.update({"SYSTEM_A1", "SYSTEM_A2", "SYSTEM_A4"})
    if "transferfrom" in low or "permit" in low:
        picks.update({"SYSTEM_A3", "SYSTEM_A2"})
    if any(k in low for k in ("approve", "allowance", "increaseallowance")):
        picks.add("SYSTEM_A2")
    if any(k in low for k in ("onlyowner", "admin", "role(", "ownable", "accesscontrol", "governor")):
        picks.add("SYSTEM_B")
    if any(k in low for k in (
        "muldiv", "* 1e", "10**", "decimals", "abi.encode", "abi.decode",
        "converttoshares", "converttoassets", "previewdeposit", "previewredeem",
        "totalassets()", "ierc4626",
    )):
        picks.update({"SYSTEM_C", "SYSTEM_D"})
    if any(k in low for k in (" for(", " for ", "while(", "uint128(", "uint64(", "int128(", "downcast")):
        picks.add("SYSTEM_D")
    if any(k in low for k in ("delegatecall", "fallback(", "proxy", "implementation", "invoke(")):
        picks.add("SYSTEM_B")
    if any(k in low for k in ("oracle", "price", "getprice", "latestanswer")):
        picks.add("SYSTEM_C")
    if any(k in low for k in ("initialize", "claim", "redeem", "finalize")):
        picks.update({"PROMPT_LIFECYCLE", "SYSTEM_A4"})
    if any(k in low for k in ("factory", "create2", "clone", "deploy(")):
        picks.add("PROMPT_AUTHORIZED_SOURCE")
    default_pad = ("SYSTEM_A1", "SYSTEM_A2", "SYSTEM_B", "SYSTEM_C", "SYSTEM_D")
    for tool in default_pad:
        if len(picks) >= MIN_PICKS_PER_FILE:
            break
        picks.add(tool)
    return sorted(picks)


# ---- Phase 4c: adversarial skeptic review ----
# A fresh prompt whose only job is disproving a claim catches more of its own
# generating prompt's mistakes than that prompt reviewing itself would.

SYSTEM_SKEPTIC = """
<role>
You are an adversarial second-opinion security reviewer. You did not write the candidate
findings below -- another reviewer did, and you do not trust their work by default. Your
ONLY job is to try to REFUTE each candidate: find the concrete reason it is NOT a real,
exploitable vulnerability, if one exists.
</role>

<scope>
You get the full source of one file and a numbered list of candidate findings another
reviewer flagged in it. Re-examine each independently against the actual code -- do not
just trust the candidate's own description.
</scope>

<method>
For each candidate, check: (1) does the cited code actually exist and do what's claimed?
(2) is there a guard/modifier/role-check elsewhere in the file the candidate missed?
(3) is the impact reachable by an unprivileged caller, or does it need a privileged role
or a precondition that never holds? (4) is it generic/hypothetical rather than a specific,
provable exploit in this file's actual logic?

Only mark REFUTED if you can point to the specific code, guard, or missing precondition
that makes the claim false. If you cannot find a concrete reason, mark CONFIRMED -- do
not refute on vague suspicion alone.
</method>

<output>
Return ONLY raw JSON: {"verdicts": [{"index": <int>, "verdict": "confirmed"|"refuted",
"reason": "one sentence"}]}. Exactly one verdict per candidate index, same index numbers.
</output>
"""


def _build_skeptic_user_prompt(file_label: str, source: str, candidates: list[dict]) -> str:
    lines = [f"File: {file_label}", "", "```", source, "```", "", "Candidate findings:"]
    for index, finding in enumerate(candidates):
        lines.append(
            f"[{index}] title={finding.get('title', '')!r} "
            f"severity={finding.get('severity', '')} "
            f"line={finding.get('line')} location={finding.get('location', '')!r}\n"
            f"    description: {finding.get('description', '')}\n"
            f"    snippet: {finding.get('vulnerable_code_snippet', '')!r}"
        )
    return "\n".join(lines)


def _extract_json_object(raw_reply: str | None) -> dict | None:
    if not isinstance(raw_reply, str):
        return None
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
        start, end = text.find("{"), text.rfind("}")
        if start != -1 and end != -1 and end > start:
            try:
                payload = json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                return None
        else:
            return None
    return payload if isinstance(payload, dict) else None


def _parse_skeptic_verdicts(raw_reply: str, num_candidates: int) -> list[bool]:
    """True = keep, False = drop. Fails open (keeps everything) on any parse
    problem -- this pass is a refinement, never a hard gate."""
    keep = [True] * num_candidates
    payload = _extract_json_object(raw_reply)
    if payload is None:
        return keep
    verdicts = payload.get("verdicts")
    if not isinstance(verdicts, list):
        return keep
    for entry in verdicts:
        if not isinstance(entry, dict):
            continue
        index = entry.get("index")
        if not isinstance(index, int) or not (0 <= index < num_candidates):
            continue
        if str(entry.get("verdict") or "").strip().lower() == "refuted":
            keep[index] = False
    return keep


def _skeptic_review_all(
    merged: list[dict],
    sources: dict[str, str],
    *,
    endpoint: str,
    api_key: str,
    deadline: float,
) -> list[dict]:
    if not merged:
        return merged
    remaining = deadline - time.monotonic()
    if remaining < SKEPTIC_MIN_BUDGET_SECONDS:
        return merged

    by_file: dict[str, list[dict]] = defaultdict(list)
    for finding in merged:
        by_file[finding.get("file", "")].append(finding)

    reviewed: list[dict] = []
    processed_files: set[str] = set()
    executor = ThreadPoolExecutor(max_workers=SKEPTIC_MAX_WORKERS)
    try:
        futures: dict = {}
        for file_label, candidates in by_file.items():
            source = sources.get(file_label, "")
            if not source:
                reviewed.extend(candidates)
                processed_files.add(file_label)
                continue
            future = executor.submit(
                _ask_model,
                endpoint=endpoint,
                api_key=api_key,
                system_prompt=SYSTEM_SKEPTIC,
                user_prompt=_build_skeptic_user_prompt(file_label, source, candidates),
                timeout=SKEPTIC_REQUEST_TIMEOUT_SECONDS,
                max_tokens=SKEPTIC_MAX_TOKENS,
            )
            futures[future] = (file_label, candidates)
        wait_seconds = min(remaining, SKEPTIC_TIME_BUDGET_SECONDS)
        try:
            for future in as_completed(futures, timeout=max(wait_seconds, 0.0)):
                file_label, candidates = futures[future]
                processed_files.add(file_label)
                try:
                    raw_reply = future.result()
                except (
                    urllib.error.URLError,
                    TimeoutError,
                    OSError,
                    ValueError,
                    KeyError,
                    IndexError,
                    TypeError,
                ):
                    reviewed.extend(candidates)  # fail open
                    continue
                keep_flags = _parse_skeptic_verdicts(raw_reply, len(candidates))
                reviewed.extend(c for c, keep in zip(candidates, keep_flags) if keep)
        except TimeoutError:
            pass
    finally:
        executor.shutdown(wait=False, cancel_futures=True)

    # Any file whose skeptic call never completed (budget ran out first) keeps
    # its pre-review findings rather than losing them silently.
    for file_label, candidates in by_file.items():
        if file_label not in processed_files:
            reviewed.extend(candidates)
    return reviewed


# ---- Phase 1: file discovery + ranking ----

def _iter_contract_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames if d.lower() not in SKIP_DIR_NAMES and not d.startswith(".")
        ]
        for filename in filenames:
            if filename.lower().endswith(CONTRACT_SUFFIXES):
                yield Path(dirpath) / filename


_BOOST_PATTERNS = re.compile(
    r"(?i)(strateg|vault|router|registry|controller|manager|executor|pool|staking|reward|"
    r"validator|token|nft|bridge|oracle|lending|borrow|swap|liquidat|governor|treasury|"
    r"escrow|dispatch|multicall|multi)"
)
_BASE_PATTERNS = re.compile(r"(?i)(base|core|main|impl|logic)")
_IMPORT_RE = re.compile(
    r'^\s*(?:import\s+(?:\{[^}]*\}\s+from\s+)?["\']([^"\']+)["\']|use\s+([A-Za-z0-9_:]+)|'
    r"from\s+([A-Za-z0-9_./]+)\s+import)",
    re.MULTILINE,
)
_SOL_FN_SIG_RE = re.compile(r"function\s+\w+\s*\([^)]*\)([^{;]*)[{;]")
_IFACE_DECL_RE = re.compile(r"^\s*interface\s+\w+", re.MULTILINE)
_CONCRETE_DECL_RE = re.compile(r"^\s*(?:abstract\s+)?(?:contract|library)\s+\w+", re.MULTILINE)


def _rank_files_by_signal(files: list[Path]) -> list[Path]:
    """Rank by import-graph centrality + entry-point density, pure I/O + regex, no LLM.
    Heavily-imported files and files with many state-mutating external entry points
    bubble to the top; pure-interface .sol files are crushed to the bottom."""
    stems: dict[str, Path] = {}
    for f in files:
        stems.setdefault(f.stem, f)
    text_cache: dict[Path, str] = {}
    imports_out: dict[Path, set] = defaultdict(set)
    imports_in: dict[Path, int] = defaultdict(int)
    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        text_cache[f] = text
        for m in _IMPORT_RE.finditer(text):
            target = m.group(1) or m.group(2) or m.group(3) or ""
            if not target:
                continue
            tail = target.strip()
            # Strip a file extension first so ".sol" isn't split into "sol" as
            # the (wrong) stem -- most import targets here end in one.
            for suffix in CONTRACT_SUFFIXES:
                if tail.endswith(suffix):
                    tail = tail[: -len(suffix)]
                    break
            tail = re.split(r"[/:.]", tail)[-1]
            if tail and tail in stems and stems[tail] != f:
                imports_out[f].add(stems[tail])
                imports_in[stems[tail]] += 1

    def _name_boost(f: Path) -> int:
        name = f.stem
        role_matches = len(_BOOST_PATTERNS.findall(name))
        base_matches = len(_BASE_PATTERNS.findall(name))
        try:
            size_kb = f.stat().st_size / 1024
            size_bonus = min(int(size_kb / 3), 8)
        except OSError:
            size_bonus = 0
        return role_matches * 5 + base_matches * 4 + size_bonus

    def _entry_density(f: Path) -> int:
        text = text_cache.get(f, "")
        if not text or f.suffix != ".sol":
            return 0
        n = 0
        for m in _SOL_FN_SIG_RE.finditer(text):
            sig = m.group(1)
            if not re.search(r"\b(external|public)\b", sig):
                continue
            if re.search(r"\b(view|pure)\b", sig):
                continue
            n += 1
        return n

    def _is_interface_only(f: Path) -> bool:
        if f.suffix != ".sol":
            return False
        text = text_cache.get(f, "")
        if not text:
            return False
        return bool(_IFACE_DECL_RE.search(text)) and not bool(_CONCRETE_DECL_RE.search(text))

    def score(f: Path) -> tuple:
        graph = imports_in[f] * 2 + len(imports_out[f])
        boost = _name_boost(f)
        ed = _entry_density(f)
        entry = ed * 2
        try:
            size_kb = f.stat().st_size / 1024
        except OSError:
            size_kb = 0
        if size_kb <= 5 and ed >= 2:
            entry += 6
        iface_penalty = 50 if _is_interface_only(f) else 0
        return (-(graph + boost + entry - iface_penalty), f.suffix != ".sol", str(f))

    return sorted(files, key=score)


# Solidity inheritance/using/import regexes for parent-class + shared-infra pull-in.
_SOL_INHERIT_RE = re.compile(
    r"\b(?:abstract\s+)?(?:contract|library|interface)\s+\w+\s+is\s+([^\{;]+?)\s*\{",
    re.IGNORECASE | re.DOTALL,
)
_SOL_LINE_COMMENT_RE = re.compile(r"//[^\n]*")
_SOL_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_SOL_USING_RE = re.compile(r"\busing\s+([A-Za-z_]\w*)\b", re.IGNORECASE)
_SOL_NAMED_IMPORT_RE = re.compile(
    r'\bimport\s+\{([^}]+)\}\s+from\s+["\'][^"\']+["\']', re.IGNORECASE | re.DOTALL
)
_SOL_BARE_IMPORT_RE = re.compile(r'\bimport\s+["\']([^"\']+)["\']\s*;', re.IGNORECASE)
_SOL_INFRA_NAME_RE = re.compile(
    r"(?i)(library|(?<=[a-z])lib(?:rary)?$|param(?:eter)?s?|config(?:uration)?|"
    r"setting?s?|checkpoint|invariant|types?$|^storage$)"
)


def _resolve_parent_classes(selected_files: list[Path], all_files: list[Path]) -> list[Path]:
    """Parent-class + shared-infra .sol files referenced by selected_files; capped."""
    selected_set = set(selected_files)
    stem_to_file: dict[str, Path] = {}
    for f in all_files:
        if f in selected_set:
            continue
        stem_to_file.setdefault(f.stem.lower(), f)
    if not stem_to_file:
        return []
    infra_candidates = [
        (stem, fp) for stem, fp in stem_to_file.items() if _SOL_INFRA_NAME_RE.search(fp.stem)
    ]

    added: list[Path] = []
    added_stems: set = set()

    def _try_add(name: str, infra_only: bool) -> bool:
        if not name or not name[0].isalpha():
            return False
        stem = name.lower()
        if stem in added_stems:
            return False
        parent_file = stem_to_file.get(stem)
        if parent_file is None:
            return False
        if infra_only and not _SOL_INFRA_NAME_RE.search(parent_file.stem):
            return False
        added.append(parent_file)
        added_stems.add(stem)
        return len(added) >= PARENT_CLASS_MAX_ADD

    for f in selected_files:
        if len(added) >= PARENT_CLASS_MAX_ADD:
            break
        if f.suffix.lower() != ".sol":
            continue
        try:
            src = f.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        src = _SOL_BLOCK_COMMENT_RE.sub("", src)
        src = _SOL_LINE_COMMENT_RE.sub("", src)

        for m in _SOL_INHERIT_RE.finditer(src):
            for raw in m.group(1).split(","):
                name = raw.strip().split("(")[0].strip()
                if _try_add(name, infra_only=False):
                    break
            if len(added) >= PARENT_CLASS_MAX_ADD:
                break
        if len(added) >= PARENT_CLASS_MAX_ADD:
            break

        for stem, cand_file in infra_candidates:
            if stem in added_stems:
                continue
            if re.search(rf"\b{re.escape(cand_file.stem)}\b", src):
                if _try_add(cand_file.stem, infra_only=True):
                    break
        if len(added) >= PARENT_CLASS_MAX_ADD:
            break

        for m in _SOL_USING_RE.finditer(src):
            if _try_add(m.group(1).strip(), infra_only=True):
                break
        if len(added) >= PARENT_CLASS_MAX_ADD:
            break

        for m in _SOL_NAMED_IMPORT_RE.finditer(src):
            for raw in m.group(1).split(","):
                name = raw.strip().split(" as ")[0].strip()
                if _try_add(name, infra_only=True):
                    break
            if len(added) >= PARENT_CLASS_MAX_ADD:
                break
        if len(added) >= PARENT_CLASS_MAX_ADD:
            break

        for m in _SOL_BARE_IMPORT_RE.finditer(src):
            path = m.group(1)
            tail = path.rsplit("/", 1)[-1]
            if tail.endswith(".sol"):
                tail = tail[:-4]
            if _try_add(tail, infra_only=True):
                break
    return added


# ---- agent_main ----

def agent_main(project_dir: str | None = None, inference_api: str | None = None) -> dict:
    findings: list[dict] = []
    sources: dict[str, str] = {}
    endpoint = ""
    api_key = ""
    deadline = time.monotonic() + TIME_BUDGET_SECONDS
    try:
        root = _resolve_project_dir(project_dir)
        if root is not None:
            endpoint = _resolve_inference_endpoint(inference_api)
            api_key = os.environ.get("INFERENCE_API_KEY", "")

            all_files = list(_iter_contract_files(root))
            ranked = _rank_files_by_signal(all_files)[:MAX_FILES_CONSIDERED]
            selected = ranked[:MAX_FILES_ANALYZED]
            parents = _resolve_parent_classes(selected, all_files)
            scope_files = selected + [p for p in parents if p not in selected]

            sources: dict[str, str] = {}
            for path in scope_files:
                try:
                    text = path.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                if text.strip():
                    sources[_relative_path(path, root)] = text[:MAX_FILE_CHARS]

            executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)
            try:
                futures: dict = {}
                for relative_path, source in sources.items():
                    for tool_name in _heuristic_picks(source):
                        system_prompt, per_call_cap = TOOL_PROMPTS[tool_name]
                        future = executor.submit(
                            _ask_model,
                            endpoint=endpoint,
                            api_key=api_key,
                            system_prompt=system_prompt,
                            user_prompt=f"File: {relative_path}\n\n```\n{source}\n```",
                        )
                        futures[future] = (relative_path, per_call_cap)
                remaining = deadline - time.monotonic()
                try:
                    for future in as_completed(futures, timeout=max(remaining, 0.0)):
                        relative_path, per_call_cap = futures[future]
                        try:
                            raw_reply = future.result()
                        except (
                            urllib.error.URLError,
                            TimeoutError,
                            OSError,
                            ValueError,
                            KeyError,
                            IndexError,
                            TypeError,
                        ):
                            continue
                        for finding in _parse_findings(raw_reply, per_call_cap):
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

    merged = _cluster_and_merge(findings)
    reviewed = merged
    if endpoint:
        try:
            reviewed = _skeptic_review_all(
                merged, sources, endpoint=endpoint, api_key=api_key, deadline=deadline
            )
        except Exception:
            # The skeptic pass is a refinement, never a hard gate: any failure
            # here falls back to the pre-review merged findings rather than
            # losing them.
            reviewed = merged

    return {"vulnerabilities": _rank_and_cap(reviewed, MAX_FINDINGS)}


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


def _ask_model(
    *,
    endpoint: str,
    api_key: str,
    system_prompt: str,
    user_prompt: str,
    timeout: float = REQUEST_TIMEOUT_SECONDS,
    max_tokens: int = 8000,
) -> str:
    body = json.dumps(
        {
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "max_tokens": max_tokens,
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
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = json.loads(response.read().decode("utf-8"))
    return payload["choices"][0]["message"]["content"]


def _parse_confidence(value: object) -> float | None:
    try:
        confidence = float(value)
    except (TypeError, ValueError):
        return None
    return min(1.0, max(0.0, confidence))


MAX_CODE_SNIPPET_CHARS = 400


def _parse_line(value: object) -> int | None:
    try:
        line = int(value)
    except (TypeError, ValueError):
        return None
    return line if line > 0 else None


def _parse_findings(raw_reply: str, max_items: int) -> list[dict]:
    payload = _extract_json_array(raw_reply)
    if payload is None:
        return []
    cleaned: list[dict] = []
    for item in payload[:max_items]:
        if not isinstance(item, dict):
            continue
        title = str(item.get("title") or "").strip()
        if not title:
            continue
        severity = str(item.get("severity") or "high").strip().lower()
        if severity not in VALID_SEVERITIES:
            severity = "high"
        # A finding is only dropped when the model gave an explicit sub-threshold
        # confidence; a missing/unparsable confidence defaults to a passing value
        # instead of being silently discarded.
        raw_confidence = _parse_confidence(item.get("confidence"))
        if raw_confidence is not None and raw_confidence < MIN_CONFIDENCE:
            continue
        confidence = raw_confidence if raw_confidence is not None else 0.75
        description = str(item.get("description") or "").strip()
        if len(description) < MIN_DESCRIPTION_CHARS:
            description = (description + " " if description else "") + (
                f"This is a {severity}-severity issue flagged by automated "
                "review; verify the reported location and exploit path before "
                "relying on this report."
            )
        cleaned.append(
            {
                "title": title,
                "description": description,
                "vulnerability_type": str(item.get("vulnerability_type") or "").strip(),
                "severity": severity,
                "confidence": confidence,
                "location": str(item.get("location") or "").strip(),
                "line": _parse_line(item.get("line")),
                "vulnerable_code_snippet": str(
                    item.get("vulnerable_code_snippet") or ""
                ).strip()[:MAX_CODE_SNIPPET_CHARS],
                "file": "",
            }
        )
    return cleaned


def _extract_json_array(raw_reply: str | None) -> list | None:
    # A reasoning model can exhaust its token budget thinking and return a
    # null/non-string content field with finish_reason "length" -- never let
    # that crash the caller, it's just an empty result for this one call.
    if not isinstance(raw_reply, str):
        return None
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


# ---- Phase 4a: similarity-based merge/dedup ----

_STOPWORDS = {
    "the", "and", "for", "that", "this", "with", "from", "are", "was", "can",
    "may", "could", "would", "should", "not", "but", "has", "have", "had",
    "will", "its", "when", "which", "where", "been", "being", "does", "into",
    "also", "than", "then",
}


def _normalize_text(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").lower().strip())


def _token_set(text: str) -> set:
    words = re.findall(r"[a-z][a-z0-9_]+", _normalize_text(text))
    return {w for w in words if len(w) > 2 and w not in _STOPWORDS}


def _jaccard_similarity(set_a: set, set_b: set) -> float:
    if not set_a and not set_b:
        return 1.0
    if not set_a or not set_b:
        return 0.0
    return len(set_a & set_b) / len(set_a | set_b)


def _findings_similar(a: dict, b: dict) -> bool:
    same_file = a.get("file") == b.get("file")
    # Same/adjacent line in the same file is almost always the same bug, even
    # when two passes word it completely differently.
    if same_file:
        line_a, line_b = a.get("line"), b.get("line")
        if line_a is not None and line_b is not None and abs(line_a - line_b) <= 1:
            return True
    title_sim = _jaccard_similarity(_token_set(a.get("title", "")), _token_set(b.get("title", "")))
    desc_sim = _jaccard_similarity(
        _token_set(a.get("description", "")), _token_set(b.get("description", ""))
    )
    type_a = _normalize_text(a.get("vulnerability_type", ""))
    type_b = _normalize_text(b.get("vulnerability_type", ""))
    type_similar = bool(type_a) and bool(type_b) and (
        type_a == type_b or type_a in type_b or type_b in type_a
    )
    if same_file:
        if title_sim >= 0.25:
            return True
        if desc_sim >= 0.20 and type_similar:
            return True
    else:
        if title_sim >= 0.50 and type_similar:
            return True
    return False


def _merge_group(group: list[dict]) -> dict:
    if len(group) == 1:
        return group[0]
    group = sorted(group, key=lambda v: (-v.get("confidence", 0.0), -len(v.get("description", ""))))
    best = group[0]
    best_title = max(group, key=lambda v: (v.get("confidence", 0.0), len(v.get("title", ""))))["title"]
    sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    best_severity = max(group, key=lambda v: sev_order.get(v.get("severity", "low"), 0))["severity"]
    best_confidence = max(v.get("confidence", 0.0) for v in group)
    vtypes: list[str] = []
    seen_vt: set = set()
    for v in group:
        vt = v.get("vulnerability_type", "")
        vt_norm = _normalize_text(vt)
        if vt and vt_norm not in seen_vt:
            vtypes.append(vt)
            seen_vt.add(vt_norm)
    combined_vtype = vtypes[0] if len(vtypes) == 1 else " / ".join(vtypes[:2])
    locations: list[str] = []
    seen_loc: set = set()
    for v in group:
        loc = v.get("location", "")
        loc_norm = _normalize_text(loc)
        if loc and loc_norm not in seen_loc:
            locations.append(loc)
            seen_loc.add(loc_norm)
    combined_location = "; ".join(locations[:3])
    # Prefer the highest-confidence member's line/snippet; fall back to the
    # first group member that actually has one (a specialist pass with a
    # weaker prompt for this data may have left it blank).
    best_line = next((v.get("line") for v in group if v.get("line") is not None), None)
    best_snippet = next(
        (v.get("vulnerable_code_snippet") for v in group if v.get("vulnerable_code_snippet")), ""
    )
    all_sentences: list[str] = []
    seen_sentences: set = set()
    for v in group:
        for sentence in re.split(r"(?<=[.!?])\s+", v.get("description", "").strip()):
            sentence = sentence.strip()
            if not sentence:
                continue
            s_norm = _normalize_text(sentence)
            s_tokens = _token_set(sentence)
            is_dup = False
            for existing_norm in seen_sentences:
                if _jaccard_similarity(s_tokens, _token_set(existing_norm)) > 0.6:
                    is_dup = True
                    break
            if not is_dup:
                all_sentences.append(sentence)
                seen_sentences.add(s_norm)
    combined_desc = ""
    for sentence in all_sentences:
        candidate = combined_desc + (" " if combined_desc else "") + sentence
        if len(candidate) <= 800:
            combined_desc = candidate
        else:
            remaining = 800 - len(combined_desc) - 1
            if remaining > 40:
                combined_desc = combined_desc + " " + sentence[: remaining - 3] + "..."
            break
    if not combined_desc:
        combined_desc = best.get("description", "")[:800]
    return {
        "title": best_title,
        "description": combined_desc,
        "vulnerability_type": combined_vtype,
        "severity": best_severity,
        "confidence": best_confidence,
        "location": combined_location,
        "line": best_line,
        "vulnerable_code_snippet": best_snippet,
        "file": best.get("file", ""),
    }


def _cluster_findings(vulns: list[dict]) -> list[list[dict]]:
    n = len(vulns)
    assigned = [False] * n
    clusters: list[list[dict]] = []
    for i in range(n):
        if assigned[i]:
            continue
        cluster = [vulns[i]]
        assigned[i] = True
        for j in range(i + 1, n):
            if assigned[j]:
                continue
            for member in cluster:
                if _findings_similar(member, vulns[j]):
                    cluster.append(vulns[j])
                    assigned[j] = True
                    break
        clusters.append(cluster)
    return clusters


# ---- Phase 4b: rule-based scoring + final cap ----

FP_TYPE_PATTERNS = [
    ("resource exhaustion", -2.0), ("token ordering / direction", -1.5), ("cross-language evm", -1.0),
]
MILD_FP_TYPE_PATTERNS = [("missing access control", -0.8)]
TP_TYPE_PATTERNS = [
    ("reentrancy", 1.5), ("access control", 2.0), ("missing state update", 2.5),
    ("state corruption", 2.0), ("accounting error", 2.5), ("missing slippage", 2.5),
    ("fund mixing", 2.0), ("unvalidated external", 2.0), ("gas griefing", 2.0),
    ("silent failure", 2.0), ("front-running", 2.0), ("signature replay", 2.0),
    ("denial of service", 1.5), ("unit mismatch", 2.0), ("type confusion", 2.0),
    ("downcast", 1.5), ("approval reset", 2.0), ("fee evasion", 2.0),
    ("delegated payout", 2.0), ("integration mismatch", 2.0), ("input validation", 1.5),
    ("refund mismatch", 2.0), ("missing modifier", 2.0), ("manipulable return", 2.0),
    ("initialization default", 1.5), ("missing precondition", 2.0), ("stale cache", 1.5),
    ("max approval", 1.5),
]
TP_TYPE_FUZZY = [
    ("state update", 1.5), ("accounting", 1.5), ("slippage", 1.5), ("fee evasion", 1.5),
    ("fund conservation", 1.5), ("fund mixing", 1.0), ("input validation", 1.0), ("logic error", 0.5),
]
FP_TITLE_KEYWORDS = [
    ("centralization risk", -3.0), ("admin can", -2.0), ("owner can", -2.0), ("onlyowner", -2.0),
    ("onlyrole", -2.0), ("privileged function", -2.0), ("governance attack", -2.0),
    ("timelock bypass", -2.0), ("pauseregistry", -4.0), ("pauser role", -3.0), ("theoretical", -3.0),
    ("hypothetical", -3.0), ("could potentially", -2.0), ("might allow", -1.5),
    ("may result in", -1.0), ("potential overflow", -1.5), ("could overflow", -1.5),
    ("generic reentrancy", -2.0), ("standard reentrancy", -2.0), ("well-known pattern", -1.5),
    ("common vulnerability", -1.0), ("best practice", -1.0),
]
TP_TITLE_KEYWORDS = [
    ("drain", 3.0), ("steal", 3.0), ("theft", 3.0), ("fund loss", 3.0), ("loss of funds", 3.0),
    ("extract value", 2.5), ("permissionless", 2.0), ("callable by anyone", 2.0), ("front-run", 2.0),
    ("double count", 2.0), ("missing update", 2.0), ("state not updated", 2.0),
    ("silent failure", 1.5), ("missing reentrancy guard", 2.0), ("permanently lost", 2.0),
    ("locked in contract", 2.0), ("not zeroed", 2.0), ("not decremented", 2.0), ("not reset", 2.0),
    ("wrong recipient", 2.0), ("id collision", 2.0), ("anyone can call", 2.0),
    ("unvalidated", 2.0), ("not validated", 1.5), ("stale snapshot", 1.5),
    ("unconsumed approval", 2.0), ("missing receive", 2.0), ("fee bypass", 2.0),
    ("delegated payout", 2.0), ("integration mismatch", 1.5), ("arbitrary from", 2.0),
    ("refund mismatch", 2.0), ("missing modifier", 2.0), ("manipulable return", 2.0),
    ("initialization default", 1.5), ("init grants", 1.5), ("no slippage", 2.0),
    ("missing precondition", 2.0), ("stale cache", 1.5), ("max approval", 1.5),
    ("unbounded allowance", 1.5), ("price spike", 1.5),
    ("uninitialized loop", 1.5), ("zero target", 1.5),
]


def _word_count(text: str) -> int:
    return len(text.split()) if text and text.strip() else 0


def _clamp(value: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, value))


def _rule_score(finding: dict) -> float:
    score = 5.0
    vuln_type = _normalize_text(finding.get("vulnerability_type", ""))
    title = _normalize_text(finding.get("title", ""))
    desc = _normalize_text(finding.get("description", ""))
    severity = finding.get("severity", "")
    confidence = _clamp(finding.get("confidence", 0.5), 0.0, 1.0)
    text = f"{title} {desc}"

    tp_matched = fp_matched = False
    for tp_type, boost in TP_TYPE_PATTERNS:
        if tp_type in vuln_type:
            score += boost
            tp_matched = True
            break
    if not tp_matched:
        for fp_type, penalty in FP_TYPE_PATTERNS:
            if fp_type in vuln_type:
                score += penalty
                fp_matched = True
                break
    if not tp_matched and not fp_matched:
        for mild_type, penalty in MILD_FP_TYPE_PATTERNS:
            if mild_type in vuln_type:
                score += penalty
                break
        for fuzzy_type, boost in TP_TYPE_FUZZY:
            if fuzzy_type in vuln_type:
                score += boost
                break

    if severity == "high":
        score += 0.5
    elif severity == "medium":
        score -= 2.0
    elif severity == "low":
        score -= 4.0

    if confidence >= 0.95:
        score += 0.3
    elif confidence < 0.80:
        score -= 1.0

    fp_keyword_total = 0.0
    for keyword, weight in FP_TITLE_KEYWORDS:
        if keyword in text:
            fp_keyword_total += weight
    score += max(fp_keyword_total, -4.0)

    for keyword, weight in TP_TITLE_KEYWORDS:
        if keyword in text:
            score += weight

    wc = _word_count(desc)
    if wc < 15:
        score -= 2.0
    elif wc > 80:
        score += 0.5

    # A concrete line number and a quoted code snippet are stronger location
    # evidence than prose alone -- reward findings that actually have them.
    if finding.get("line") is not None:
        score += 0.3
    if finding.get("vulnerable_code_snippet"):
        score += 0.3

    if re.search(r"\b(function|fn)\s+\w+\(", text):
        score += 0.3
    if re.search(r"\b\w+\(\)", title):
        score += 0.7
    if re.search(r"\b_\w{3,}\b", title):
        score += 0.5
    if re.search(r"line\s+\d+", text):
        score += 0.2
    if re.search(r"step\s+\d", text) or "exploit scenario" in text:
        score += 0.5
    return score


_DAMPENER_STOPWORDS = {
    "the", "and", "for", "that", "this", "with", "from", "are", "was", "can",
    "may", "could", "would", "should", "not", "but", "has", "have", "had",
    "will", "its", "when", "which", "where", "been", "being", "does", "into",
    "also", "than", "then", "via", "due", "leading", "across",
}


def _post_rank_dampener(vulns: list[dict]) -> None:
    """When several findings of the same TP type land on the same file with
    similar titles, only the highest-confidence one keeps the full boost; the
    rest get it halved -- so one bug class can't crowd out distinct bugs."""

    def _matched_tp_type(v: dict) -> str | None:
        vt = _normalize_text(v.get("vulnerability_type", ""))
        for tp_type, _ in TP_TYPE_PATTERNS:
            if tp_type in vt:
                return tp_type
        return None

    def _title_tokens(v: dict) -> set:
        return {
            w
            for w in re.findall(r"[a-z][a-z0-9_]+", (v.get("title") or "").lower())
            if w not in _DAMPENER_STOPWORDS and len(w) >= 4
        }

    by_bucket: dict[tuple, list] = defaultdict(list)
    for v in vulns:
        mtp = _matched_tp_type(v)
        if not mtp:
            continue
        by_bucket[(v.get("file", ""), mtp)].append(v)

    for (_file_key, tp_key), group in by_bucket.items():
        if len(group) <= 1:
            continue
        boost = next((b for t, b in TP_TYPE_PATTERNS if t == tp_key), 0.0)
        if boost <= 0:
            continue
        group.sort(key=lambda v: (-(v.get("confidence") or 0.0), -_rule_score(v)))
        anchor = group[0]
        anchor_tokens = _title_tokens(anchor)
        dampen = boost * 0.5
        for v in group[1:]:
            v_tokens = _title_tokens(v)
            if not anchor_tokens or not v_tokens:
                continue
            jaccard = len(anchor_tokens & v_tokens) / len(anchor_tokens | v_tokens)
            if jaccard < 0.5:
                continue
            v["_rule_score_adj"] = _rule_score(v) - dampen


def _rule_score_final(finding: dict) -> float:
    adj = finding.get("_rule_score_adj")
    if adj is not None:
        return adj
    return _rule_score(finding)


def _cluster_and_merge(findings: list[dict]) -> list[dict]:
    if not findings:
        return []
    clusters = _cluster_findings(findings)
    return [_merge_group(cluster) for cluster in clusters]


def _rank_and_cap(findings: list[dict], limit: int) -> list[dict]:
    if not findings:
        return []
    merged = list(findings)
    _post_rank_dampener(merged)
    merged.sort(
        key=lambda v: (-_rule_score_final(v), -len(v.get("description", "")), v.get("title", ""))
    )
    capped = merged[:limit]
    return [{k: v for k, v in finding.items() if not k.startswith("_")} for finding in capped]
