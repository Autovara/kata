from __future__ import annotations

import ast
import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from kata.screening_system.models import ScreeningFinding, dedupe_findings
from kata.screening_system.mutation_canary import SOLIDITY_RESERVED

SN60_SANDBOX_ROOT_ENV = "KATA_SN60_SANDBOX_ROOT"
SN60_BENCHMARK_FILE_ENV = "KATA_SN60_BENCHMARK_FILE"
DEFAULT_SN60_BENCHMARK_FILENAME = "curated-highs-only-2025-08-08.json"

BENCHMARK_PROJECT_ID_PATTERN = re.compile(
    r"\bcode4rena_[a-z0-9]+(?:-[a-z0-9]+)*_\d{4}_\d{2}\b",
    re.IGNORECASE,
)
BENCHMARK_FINDING_ID_PATTERN = re.compile(
    r"\b20\d{2}-\d{2}-[a-z0-9-]+_[HMS]-\d{2}\b",
    re.IGNORECASE,
)
IDENTIFIER_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9_]{5,}")
WORD_PATTERN = re.compile(r"[a-z0-9_]+")
VULNERABILITY_KEYS = {"title", "description", "severity", "file", "contract", "function"}
CONCRETE_REPLAY_RULE_IDS = frozenset(
    {
        "benchmark_replay.project_id",
        "benchmark_replay.finding_id",
        "benchmark_replay.title_text",
        "benchmark_replay.long_answer_text",
        "benchmark_replay.source_line_probe",
    }
)
MIN_LONG_ANSWER_WORDS = 24
PROJECT_FINGERPRINT_BRANCH_THRESHOLD = 3
EARLY_RETURN_FINGERPRINT_THRESHOLD = 2
# A long ALL-lowercase identifier is still a distinctive fingerprint. Capturing it
# defeats the case-folding evasion: an agent that lowercases the source before
# matching hardcoded benchmark identifiers (e.g. "redelegatewithdrawnhype") strips the
# camelCase the tokenizer used to key on, hiding the fingerprint from the branch check.
LONG_LOWERCASE_FINGERPRINT_MIN_CHARS = 12
# An identifier is a benchmark fingerprint only if it is specific to a few projects.
# Tokens common across many projects (shared library names, generic vocabulary) are not
# fingerprints; this keeps the long-lowercase capture precise and avoids false positives.
MAX_PROJECTS_FOR_DISTINCTIVE_TOKEN = 2
STATIC_REPORT_BANK_MIN_FINDINGS = 3
STATIC_REPORT_BANK_MIN_TEXT_CHARS = 1000

# A branch that ANDs together several verbatim, identifier-shaped literals (e.g.
# `_contains_all(low, ("amountclaimed", "totalamount", "releaserate", "stepsclaimed"))`)
# to gate a canned finding is a project-specific answer bank keyed on the *candidate
# project's own* source identifiers -- it needs no match against the curated benchmark
# signature file to be suspicious, unlike find_project_fingerprint_branches. Kept
# separate from that check because it fires on the shape of the gate alone.
IDENTIFIER_GATE_MIN_TOKENS = 3
IDENTIFIER_GATE_TOKEN_MIN_CHARS = 6
IDENTIFIER_GATE_TOKEN_MAX_CHARS = 40
IDENTIFIER_GATE_TOKEN_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# A "source-line probe" is a long, verbatim, code-like string literal that the
# agent matches against project source (via `in`, str.find/index/..., or a
# helper such as `_line_for(text, "<literal>")`). No honest analyzer hardcodes
# the exact source line it is looking for, so a cluster of these is a reliable
# tell of a benchmark-specific answer bank -- and, unlike known-answer-text
# hashing, it survives paraphrasing and routing findings through a factory call.
SOURCE_LINE_PROBE_MIN_CHARS = 35
SOURCE_LINE_PROBE_MIN_COUNT = 3
# Exact-substring string methods (regex methods are intentionally excluded --
# fuzzy structural regexes are a weaker, separate signal and prone to false
# positives against legitimate generic detectors).
EXACT_MATCH_STR_METHODS = frozenset(
    {"find", "index", "rfind", "count", "startswith", "endswith"}
)
REGEX_CALL_ATTRS = frozenset(
    {"search", "match", "fullmatch", "findall", "finditer", "sub", "subn", "split", "compile"}
)
# Identifier immediately followed by a call/member/index operator -- the shape
# of real source code, as opposed to a natural-language sentence.
SOURCE_LINE_CALL_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\s*[\(.\[]")
# Regex metacharacter sequences used to exclude regex-pattern literals (which
# are a legitimate way to match code structurally) from the exact-line signal.
REGEX_METACHAR_PATTERN = re.compile(
    r"\\[sSdDwWbBAZ]"
    r"|\(\?:"
    r"|\(\?P<"
    r"|\[\^"
    r"|\[[A-Za-z0-9]-[A-Za-z0-9]"
    r"|\.\*|\.\+"
    r"|\{\d+,\d*\}"
    r"|\\[.(){}\[\]|+*?]"
)
FINGERPRINT_STOP_WORDS = {
    "account",
    "accounts",
    "address",
    "addresses",
    "admin",
    "amount",
    "asset",
    "assets",
    "attacker",
    "balance",
    "balances",
    "because",
    "borrow",
    "buyer",
    "claim",
    "contract",
    "contracts",
    "create",
    "critical",
    "delete",
    "deposit",
    "external",
    "factory",
    "function",
    "governance",
    "incorrect",
    "internal",
    "lender",
    "liquidity",
    "manager",
    "market",
    "medium",
    "operator",
    "oracle",
    "order",
    "orders",
    "owner",
    "position",
    "positions",
    "price",
    "private",
    "protocol",
    "public",
    "router",
    "seller",
    "severity",
    "shares",
    "state",
    "strategy",
    "system",
    "token",
    "tokens",
    "transfer",
    "transfers",
    "update",
    "users",
    "value",
    "validator",
    "vault",
    "withdraw",
}


@dataclass(frozen=True)
class BenchmarkReplaySignatures:
    title_hashes: frozenset[str] = frozenset()
    title_word_counts: frozenset[int] = frozenset()
    long_answer_hashes_by_word_count: dict[int, frozenset[str]] = field(default_factory=dict)
    fingerprint_hashes_by_project: dict[str, frozenset[str]] = field(default_factory=dict)


@dataclass(frozen=True)
class WordWindowMatch:
    digest: str
    start_offset: int


def analyze_benchmark_replay(bundle_files: dict[str, str]) -> tuple[list[ScreeningFinding], int]:
    """Return concrete replay and ambiguous replay-review signals."""
    findings: list[ScreeningFinding] = []
    findings.extend(
        find_pattern_signals(
            bundle_files,
            pattern=BENCHMARK_PROJECT_ID_PATTERN,
            rule_id="benchmark_replay.project_id",
            reason_prefix="SN60 screening found a hardcoded benchmark-style project id",
            points=6,
        )
    )
    findings.extend(
        find_pattern_signals(
            bundle_files,
            pattern=BENCHMARK_FINDING_ID_PATTERN,
            rule_id="benchmark_replay.finding_id",
            reason_prefix="SN60 screening found a hardcoded benchmark finding id",
            points=6,
        )
    )
    signatures = load_benchmark_replay_signatures()
    findings.extend(find_known_answer_text_signals(bundle_files, signatures))
    findings.extend(find_ambiguous_replay_review_signals(bundle_files, signatures))
    return findings, sum(finding_points(finding) for finding in findings)


def is_concrete_replay_finding(finding: ScreeningFinding) -> bool:
    return finding.rule_id in CONCRETE_REPLAY_RULE_IDS


def find_pattern_signals(
    bundle_files: dict[str, str],
    *,
    pattern: re.Pattern[str],
    rule_id: str,
    reason_prefix: str,
    points: int,
) -> list[ScreeningFinding]:
    findings: list[ScreeningFinding] = []
    seen: set[tuple[str, str]] = set()
    for relative_path, content in python_sources(bundle_files):
        for match in pattern.finditer(content):
            matched = match.group(0)
            key = (relative_path, matched.lower())
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                ScreeningFinding(
                    rule_id=rule_id,
                    severity="review",
                    path=relative_path,
                    line=line_for_offset(content, match.start()),
                    reason=f"{reason_prefix}: `{matched}`.",
                    evidence=f"matched={matched}; points={points}",
                )
            )
    return findings


def find_known_answer_text_signals(
    bundle_files: dict[str, str],
    signatures: BenchmarkReplaySignatures,
) -> list[ScreeningFinding]:
    if not signatures.title_hashes and not signatures.long_answer_hashes_by_word_count:
        return []
    findings: list[ScreeningFinding] = []
    seen: set[tuple[str, str]] = set()
    for relative_path, content in python_sources(bundle_files):
        word_matches = normalize_word_matches(content)
        source_words = [word for word, _offset in word_matches]
        title_match = first_matching_window_match(
            source_words,
            signatures.title_word_counts,
            signatures.title_hashes,
            word_matches,
        )
        if title_match is not None and (relative_path, "title") not in seen:
            seen.add((relative_path, "title"))
            findings.append(
                ScreeningFinding(
                    rule_id="benchmark_replay.title_text",
                    severity="review",
                    path=relative_path,
                    line=line_for_offset(content, title_match.start_offset),
                    reason="SN60 screening found exact known benchmark finding title text.",
                    evidence=f"hash={title_match.digest[:16]}; points=6",
                )
            )
        for word_count, hashes in sorted(signatures.long_answer_hashes_by_word_count.items()):
            answer_match = first_matching_window_match(
                source_words, {word_count}, hashes, word_matches
            )
            if answer_match is None or (relative_path, "answer") in seen:
                continue
            seen.add((relative_path, "answer"))
            findings.append(
                ScreeningFinding(
                    rule_id="benchmark_replay.long_answer_text",
                    severity="review",
                    path=relative_path,
                    line=line_for_offset(content, answer_match.start_offset),
                    reason="SN60 screening found exact known benchmark answer text.",
                    evidence=f"hash={answer_match.digest[:16]}; points=6",
                )
            )
    return findings


def find_ambiguous_replay_review_signals(
    bundle_files: dict[str, str],
    signatures: BenchmarkReplaySignatures,
) -> list[ScreeningFinding]:
    findings: list[ScreeningFinding] = []
    for relative_path, content in python_sources(bundle_files):
        findings.extend(find_static_report_bank(relative_path, content))
        findings.extend(find_hardcoded_source_line_probes(relative_path, content))
        findings.extend(find_project_fingerprint_branches(relative_path, content, signatures))
        findings.extend(find_identifier_gate_branches(relative_path, content))
    return findings


def find_static_report_bank(relative_path: str, content: str) -> list[ScreeningFinding]:
    try:
        tree = ast.parse(content, filename=relative_path)
    except SyntaxError:
        return []
    # Count hardcoded findings whether they are inline dict literals or routed
    # through a factory call such as `_make_finding(title="...", ...)`. Matching
    # only `ast.Dict` literals is trivially evaded by the factory-call form.
    hardcoded_findings: list[ast.AST] = []
    report_text_chars = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict) and is_vulnerability_like_dict(node):
            hardcoded_findings.append(node)
            report_text_chars += vulnerability_dict_text_chars(node)
        elif isinstance(node, ast.Call) and finding_shaped_constant_call(node):
            hardcoded_findings.append(node)
            report_text_chars += finding_call_text_chars(node)
    if (
        len(hardcoded_findings) < STATIC_REPORT_BANK_MIN_FINDINGS
        and report_text_chars < STATIC_REPORT_BANK_MIN_TEXT_CHARS
    ):
        return []
    first = hardcoded_findings[0]
    return [
        ScreeningFinding(
            rule_id="benchmark_replay.static_report_bank",
            severity="review",
            path=relative_path,
            line=getattr(first, "lineno", None),
            reason=(
                "SN60 screening found a large static vulnerability report bank; "
                "manual review is required to confirm it is not benchmark replay."
            ),
            evidence=(
                f"hardcoded_findings={len(hardcoded_findings)}; "
                f"text_chars={report_text_chars}; points=4"
            ),
        )
    ]


def finding_shaped_constant_call(node: ast.Call) -> bool:
    """A call that builds a finding (>=2 vulnerability-key kwargs) with at least
    one hardcoded string title/description -- i.e. a prewritten finding, not one
    assembled from analysis of the project."""
    keyword_names = {keyword.arg for keyword in node.keywords if keyword.arg}
    if len(keyword_names & VULNERABILITY_KEYS) < 2:
        return False
    return any(
        keyword.arg in {"title", "description"}
        and isinstance(keyword.value, ast.Constant)
        and isinstance(keyword.value.value, str)
        for keyword in node.keywords
    )


def finding_call_text_chars(node: ast.Call) -> int:
    total = 0
    for keyword in node.keywords:
        if (
            keyword.arg in {"title", "description"}
            and isinstance(keyword.value, ast.Constant)
            and isinstance(keyword.value.value, str)
        ):
            total += len(keyword.value.value)
    return total


def find_hardcoded_source_line_probes(
    relative_path: str, content: str
) -> list[ScreeningFinding]:
    try:
        tree = ast.parse(content, filename=relative_path)
    except SyntaxError:
        return []
    probes: list[tuple[int | None, str]] = []
    seen_literals: set[str] = set()
    for node in ast.walk(tree):
        for literal, line in source_line_probe_sites(node):
            key = literal.strip()
            if key in seen_literals:
                continue
            seen_literals.add(key)
            probes.append((line, literal))
    if len(probes) < SOURCE_LINE_PROBE_MIN_COUNT:
        return []
    first_line = next((line for line, _ in probes if line is not None), None)
    sample = probes[0][1].strip()
    return [
        ScreeningFinding(
            rule_id="benchmark_replay.source_line_probe",
            severity="review",
            path=relative_path,
            line=first_line,
            reason=(
                "SN60 screening found hardcoded verbatim source-line probes: the "
                "agent gates output on exact known source lines instead of "
                "analyzing the project, which is a benchmark-specific answer bank."
            ),
            evidence=f"source_line_probes={len(probes)}; sample={sample[:80]!r}; points=6",
        )
    ]


def source_line_probe_sites(node: ast.AST):
    """Yield (literal, line) for each site where a long, code-like literal is
    matched against a variable by exact substring: `"<lit>" in x`,
    `x.find("<lit>")`, or `helper(x, "<lit>")` (e.g. `_line_for`)."""
    if isinstance(node, ast.Compare) and any(
        isinstance(op, (ast.In, ast.NotIn)) for op in node.ops
    ):
        left = node.left
        if (
            isinstance(left, ast.Constant)
            and isinstance(left.value, str)
            and looks_like_source_line_literal(left.value)
        ):
            yield left.value, getattr(node, "lineno", None)
        return
    if not isinstance(node, ast.Call):
        return
    func = node.func
    if isinstance(func, ast.Attribute) and func.attr in EXACT_MATCH_STR_METHODS:
        for arg in node.args:
            if (
                isinstance(arg, ast.Constant)
                and isinstance(arg.value, str)
                and looks_like_source_line_literal(arg.value)
            ):
                yield arg.value, getattr(node, "lineno", None)
        return
    if is_regex_call(func):
        return
    # A generic call that pairs a source-text variable with a verbatim source
    # literal -- the shape of a `_line_for(text, "<exact line>")` locator.
    if not any(isinstance(arg, (ast.Name, ast.Attribute, ast.Subscript)) for arg in node.args):
        return
    for arg in node.args:
        if (
            isinstance(arg, ast.Constant)
            and isinstance(arg.value, str)
            and looks_like_source_line_literal(arg.value)
        ):
            yield arg.value, getattr(node, "lineno", None)


def is_regex_call(func: ast.AST) -> bool:
    if isinstance(func, ast.Attribute):
        if isinstance(func.value, ast.Name) and func.value.id == "re":
            return True
        if func.attr in REGEX_CALL_ATTRS:
            return True
    if isinstance(func, ast.Name) and func.id in {"search", "match", "fullmatch", "compile", "sub"}:
        return True
    return False


def looks_like_source_line_literal(value: str) -> bool:
    text = value.strip()
    if len(text) < SOURCE_LINE_PROBE_MIN_CHARS:
        return False
    if REGEX_METACHAR_PATTERN.search(text):
        return False
    if not SOURCE_LINE_CALL_PATTERN.search(text):
        return False
    return any(character in text for character in "();={}")


def find_identifier_gate_branches(relative_path: str, content: str) -> list[ScreeningFinding]:
    try:
        tree = ast.parse(content, filename=relative_path)
    except SyntaxError:
        return []
    findings: list[ScreeningFinding] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.If, ast.IfExp, ast.While)):
            continue
        tokens = {
            child.value
            for child in ast.walk(node.test)
            if isinstance(child, ast.Constant)
            and isinstance(child.value, str)
            and looks_like_identifier_gate_token(child.value)
        }
        if len(tokens) < IDENTIFIER_GATE_MIN_TOKENS:
            continue
        if not branch_returns_report(node):
            continue
        findings.append(
            ScreeningFinding(
                rule_id="benchmark_replay.identifier_gate_branch",
                severity="review",
                path=relative_path,
                line=getattr(node, "lineno", None),
                reason=(
                    "SN60 screening found a branch gated on multiple verbatim "
                    "identifier-shaped literals that returns a canned finding; manual "
                    "review is required to confirm it is not a source-specific answer "
                    "bank."
                ),
                evidence=f"identifier_tokens={len(tokens)}; points=4",
            )
        )
    return dedupe_findings(findings, by_reason=False)


def looks_like_identifier_gate_token(value: str) -> bool:
    text = value.strip()
    if not (IDENTIFIER_GATE_TOKEN_MIN_CHARS <= len(text) <= IDENTIFIER_GATE_TOKEN_MAX_CHARS):
        return False
    if not IDENTIFIER_GATE_TOKEN_PATTERN.match(text):
        return False
    lowered = text.lower()
    if lowered in FINGERPRINT_STOP_WORDS or lowered in SOLIDITY_RESERVED:
        return False
    return True


def find_project_fingerprint_branches(
    relative_path: str,
    content: str,
    signatures: BenchmarkReplaySignatures,
) -> list[ScreeningFinding]:
    if not signatures.fingerprint_hashes_by_project:
        return []
    try:
        tree = ast.parse(content, filename=relative_path)
    except SyntaxError:
        return []
    findings: list[ScreeningFinding] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.If, ast.IfExp, ast.While)):
            continue
        condition_hashes = fingerprint_hashes_from_node(node.test)
        if not condition_hashes:
            continue
        matches = project_fingerprint_matches(condition_hashes, signatures)
        if not matches:
            continue
        best_count = max(matches.values())
        if best_count >= PROJECT_FINGERPRINT_BRANCH_THRESHOLD:
            findings.append(
                ScreeningFinding(
                    rule_id="benchmark_replay.project_fingerprint_branch",
                    severity="review",
                    path=relative_path,
                    line=getattr(node, "lineno", None),
                    reason=(
                        "SN60 screening found multiple known benchmark-specific "
                        "fingerprints in branch conditions."
                    ),
                    evidence=f"matched_tokens={best_count}; points=4",
                )
            )
        if best_count >= EARLY_RETURN_FINGERPRINT_THRESHOLD and branch_returns_report(node):
            findings.append(
                ScreeningFinding(
                    rule_id="benchmark_replay.early_return_fingerprint",
                    severity="review",
                    path=relative_path,
                    line=getattr(node, "lineno", None),
                    reason=(
                        "SN60 screening found an early report return gated by known "
                        "benchmark-specific fingerprints."
                    ),
                    evidence=f"matched_tokens={best_count}; points=4",
                )
            )
    return dedupe_findings(findings, by_reason=False)


def project_fingerprint_matches(
    condition_hashes: set[str],
    signatures: BenchmarkReplaySignatures,
) -> dict[str, int]:
    matches: dict[str, int] = {}
    for project_key, project_hashes in signatures.fingerprint_hashes_by_project.items():
        count = len(condition_hashes & project_hashes)
        if count:
            matches[project_key] = count
    return matches


def branch_returns_report(node: ast.If | ast.IfExp | ast.While) -> bool:
    body = node.body if isinstance(node, (ast.If, ast.While)) else [node.body]
    for child in body:
        for descendant in ast.walk(child):
            if isinstance(descendant, ast.Return):
                if descendant.value is None:
                    return True
                if return_value_looks_like_report(descendant.value):
                    return True
            if isinstance(descendant, ast.Assign) and value_looks_like_report(descendant.value):
                return True
            if isinstance(descendant, ast.Call) and finding_shaped_constant_call(descendant):
                return True
    return False


def return_value_looks_like_report(node: ast.AST) -> bool:
    return value_looks_like_report(node) or contains_vulnerability_like_dict(node)


def value_looks_like_report(node: ast.AST) -> bool:
    if isinstance(node, ast.Dict):
        return dict_has_key(node, "vulnerabilities") or is_vulnerability_like_dict(node)
    if isinstance(node, (ast.List, ast.Tuple)):
        return any(contains_vulnerability_like_dict(child) for child in node.elts)
    if isinstance(node, ast.Name):
        return True
    return False


def contains_vulnerability_like_dict(node: ast.AST) -> bool:
    return any(
        isinstance(child, ast.Dict) and is_vulnerability_like_dict(child)
        for child in ast.walk(node)
    )


def is_vulnerability_like_dict(node: ast.Dict) -> bool:
    keys = {
        key.value
        for key in node.keys
        if isinstance(key, ast.Constant) and isinstance(key.value, str)
    }
    return len(keys & VULNERABILITY_KEYS) >= 2


def vulnerability_dict_text_chars(node: ast.Dict) -> int:
    total = 0
    for key, value in zip(node.keys, node.values, strict=False):
        if not (
            isinstance(key, ast.Constant)
            and isinstance(key.value, str)
            and key.value in {"title", "description"}
            and isinstance(value, ast.Constant)
            and isinstance(value.value, str)
        ):
            continue
        total += len(value.value)
    return total


def dict_has_key(node: ast.Dict, key_name: str) -> bool:
    return any(
        isinstance(key, ast.Constant) and key.value == key_name for key in node.keys
    )


def fingerprint_hashes_from_node(node: ast.AST) -> set[str]:
    hashes: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            hashes.update(
                hash_fingerprint_token(token)
                for token in fingerprint_tokens(child.value)
            )
    return hashes


def load_benchmark_replay_signatures() -> BenchmarkReplaySignatures:
    benchmark_path = resolve_benchmark_file()
    if benchmark_path is None:
        return BenchmarkReplaySignatures()
    return load_benchmark_replay_signatures_from_path(str(benchmark_path))


@lru_cache(maxsize=8)
def load_benchmark_replay_signatures_from_path(path: str) -> BenchmarkReplaySignatures:
    benchmark_path = Path(path).expanduser().resolve()
    try:
        payload = json.loads(benchmark_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return BenchmarkReplaySignatures()
    if not isinstance(payload, list):
        return BenchmarkReplaySignatures()

    title_hashes: set[str] = set()
    title_word_counts: set[int] = set()
    long_answer_hashes_by_word_count: dict[int, set[str]] = {}
    fingerprint_hashes_by_project: dict[str, set[str]] = {}
    for index, project in enumerate(payload):
        if not isinstance(project, dict):
            continue
        project_key = str(project.get("project_id") or f"project-{index}")
        fingerprint_text_parts = [
            str(project.get("project_id") or ""),
            str(project.get("name") or ""),
        ]
        for codebase in project.get("codebases") or []:
            if not isinstance(codebase, dict):
                continue
            fingerprint_text_parts.extend(
                [
                    str(codebase.get("codebase_id") or ""),
                    str(codebase.get("repo_url") or ""),
                ]
            )
        for finding in project.get("vulnerabilities") or []:
            if not isinstance(finding, dict):
                continue
            title = str(finding.get("title") or "")
            description = str(finding.get("description") or "")
            add_text_signature(title, title_hashes, title_word_counts)
            add_long_answer_signatures(description, long_answer_hashes_by_word_count)
            fingerprint_text_parts.extend([title, description])
        token_hashes = {
            hash_fingerprint_token(token)
            for token in fingerprint_tokens(" ".join(fingerprint_text_parts))
        }
        if token_hashes:
            fingerprint_hashes_by_project[project_key] = token_hashes

    # Rarity filter: keep only tokens specific to a few projects, so a hardcoded
    # identifier unique to one benchmark project counts as a fingerprint while shared
    # library names and generic words (present in many projects) do not.
    project_count: dict[str, int] = {}
    for hashes in fingerprint_hashes_by_project.values():
        for token_hash in hashes:
            project_count[token_hash] = project_count.get(token_hash, 0) + 1
    distinctive_hashes = {
        token_hash
        for token_hash, count in project_count.items()
        if count <= MAX_PROJECTS_FOR_DISTINCTIVE_TOKEN
    }
    fingerprint_hashes_by_project = {
        project_key: (hashes & distinctive_hashes)
        for project_key, hashes in fingerprint_hashes_by_project.items()
    }
    fingerprint_hashes_by_project = {
        project_key: hashes
        for project_key, hashes in fingerprint_hashes_by_project.items()
        if hashes
    }
    return BenchmarkReplaySignatures(
        title_hashes=frozenset(title_hashes),
        title_word_counts=frozenset(title_word_counts),
        long_answer_hashes_by_word_count={
            word_count: frozenset(hashes)
            for word_count, hashes in long_answer_hashes_by_word_count.items()
        },
        fingerprint_hashes_by_project={
            project_key: frozenset(hashes)
            for project_key, hashes in fingerprint_hashes_by_project.items()
        },
    )


def resolve_benchmark_file() -> Path | None:
    env_file = os.environ.get(SN60_BENCHMARK_FILE_ENV)
    if env_file and env_file.strip():
        path = Path(env_file).expanduser().resolve()
        return path if path.exists() else None
    env_root = os.environ.get(SN60_SANDBOX_ROOT_ENV)
    if env_root and env_root.strip():
        path = (
            Path(env_root).expanduser().resolve()
            / "validator"
            / DEFAULT_SN60_BENCHMARK_FILENAME
        )
        return path if path.exists() else None
    workspace_sandbox = (
        Path(__file__).resolve().parents[3]
        / "sandbox"
        / "validator"
        / DEFAULT_SN60_BENCHMARK_FILENAME
    )
    return workspace_sandbox if workspace_sandbox.exists() else None


def add_text_signature(text: str, hashes: set[str], word_counts: set[int]) -> None:
    words = normalize_words(text)
    if not words:
        return
    hashes.add(hash_words(words))
    word_counts.add(len(words))


def add_long_answer_signatures(text: str, hashes_by_word_count: dict[int, set[str]]) -> None:
    words = normalize_words(text)
    if len(words) < MIN_LONG_ANSWER_WORDS:
        return
    starts = {
        0,
        max(0, (len(words) - MIN_LONG_ANSWER_WORDS) // 2),
        len(words) - MIN_LONG_ANSWER_WORDS,
    }
    bucket = hashes_by_word_count.setdefault(MIN_LONG_ANSWER_WORDS, set())
    for start in starts:
        bucket.add(hash_words(words[start : start + MIN_LONG_ANSWER_WORDS]))


def first_matching_window_hash(
    words: list[str],
    word_counts: set[int] | frozenset[int],
    signatures: set[str] | frozenset[str],
) -> str | None:
    match = first_matching_window_match(
        words,
        word_counts,
        signatures,
        [(word, 0) for word in words],
    )
    return match.digest if match is not None else None


def first_matching_window_match(
    words: list[str],
    word_counts: set[int] | frozenset[int],
    signatures: set[str] | frozenset[str],
    word_matches: list[tuple[str, int]],
) -> WordWindowMatch | None:
    for word_count in sorted(word_counts):
        if word_count <= 0 or len(words) < word_count:
            continue
        for start in range(0, len(words) - word_count + 1):
            digest = hash_words(words[start : start + word_count])
            if digest in signatures:
                return WordWindowMatch(digest=digest, start_offset=word_matches[start][1])
    return None


def normalize_words(text: str) -> list[str]:
    return WORD_PATTERN.findall(text.lower())


def normalize_word_matches(text: str) -> list[tuple[str, int]]:
    return [(match.group(0), match.start()) for match in WORD_PATTERN.finditer(text.lower())]


def hash_words(words: list[str]) -> str:
    return hashlib.sha256(" ".join(words).encode("utf-8")).hexdigest()


def fingerprint_tokens(text: str) -> set[str]:
    tokens: set[str] = set()
    for token in IDENTIFIER_PATTERN.findall(text):
        lowered = token.lower()
        if lowered in FINGERPRINT_STOP_WORDS:
            continue
        if lowered.startswith("code4rena"):
            continue
        distinctive = (
            "_" in token
            or any(char.isupper() for char in token[1:])
            or any(char.isdigit() for char in token)
            or len(lowered) >= LONG_LOWERCASE_FINGERPRINT_MIN_CHARS
        )
        if distinctive:
            tokens.add(lowered)
    return tokens


def hash_fingerprint_token(token: str) -> str:
    return hashlib.sha256(token.lower().encode("utf-8")).hexdigest()


def finding_points(finding: ScreeningFinding) -> int:
    try:
        return int(finding.evidence.rsplit("points=", 1)[-1])
    except (IndexError, ValueError):
        return 0


def python_sources(bundle_files: dict[str, str]):
    for relative_path, content in sorted(bundle_files.items()):
        if relative_path.endswith(".py"):
            yield relative_path, content


def line_for_offset(content: str, offset: int) -> int:
    return content.count("\n", 0, offset) + 1
