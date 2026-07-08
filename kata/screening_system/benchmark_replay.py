from __future__ import annotations

import ast
import re

from kata.screening_system.models import ScreeningFinding

BENCHMARK_PROJECT_ID_PATTERN = re.compile(
    r"\bcode4rena_[a-z0-9]+(?:-[a-z0-9]+)*_\d{4}_\d{2}\b",
    re.IGNORECASE,
)
BENCHMARK_FINDING_ID_PATTERN = re.compile(
    r"\b20\d{2}-\d{2}-[a-z0-9-]+_[HMS]-\d{2}\b",
    re.IGNORECASE,
)
FINDING_DICT_KEYS = {
    "title",
    "description",
    "severity",
    "file",
    "path",
    "contract",
    "function",
    "mechanism",
    "impact",
}
SOURCE_FINGERPRINT_MIN_TESTS = 3
HARDCODED_FINDING_MIN_DICTS = 2


def analyze_benchmark_replay(bundle_files: dict[str, str]) -> tuple[list[ScreeningFinding], int]:
    """Return static signals for hardcoded benchmark replay."""
    findings: list[ScreeningFinding] = []
    findings.extend(
        find_pattern_signals(
            bundle_files,
            pattern=BENCHMARK_PROJECT_ID_PATTERN,
            rule_id="benchmark_replay.project_id",
            reason_prefix="SN60 screening rejected a hardcoded benchmark-style project id",
            points=6,
        )
    )
    findings.extend(
        find_pattern_signals(
            bundle_files,
            pattern=BENCHMARK_FINDING_ID_PATTERN,
            rule_id="benchmark_replay.finding_id",
            reason_prefix="SN60 screening rejected a hardcoded benchmark finding id",
            points=6,
        )
    )
    findings.extend(find_source_fingerprint_replay(bundle_files))
    return findings, sum(int(finding.evidence.rsplit("points=", 1)[-1]) for finding in findings)


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
    for relative_path, content in sorted(bundle_files.items()):
        if not relative_path.endswith(".py"):
            continue
        for match in pattern.finditer(content):
            matched = match.group(0)
            key = (relative_path, matched.lower())
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                ScreeningFinding(
                    rule_id=rule_id,
                    severity="reject",
                    path=relative_path,
                    line=line_for_offset(content, match.start()),
                    reason=f"{reason_prefix}: `{matched}`.",
                    evidence=f"matched={matched}; points={points}",
                )
            )
    return findings


def find_source_fingerprint_replay(bundle_files: dict[str, str]) -> list[ScreeningFinding]:
    findings: list[ScreeningFinding] = []
    for relative_path, content in sorted(bundle_files.items()):
        if not relative_path.endswith(".py"):
            continue
        try:
            tree = ast.parse(content, filename=relative_path)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            fingerprint_tests = source_fingerprint_membership_tests(node)
            hardcoded_findings = hardcoded_finding_dicts(node)
            if (
                len(fingerprint_tests) >= SOURCE_FINGERPRINT_MIN_TESTS
                and len(hardcoded_findings) >= HARDCODED_FINDING_MIN_DICTS
            ):
                findings.append(
                    ScreeningFinding(
                        rule_id="benchmark_replay.source_fingerprint",
                        severity="reject",
                        path=relative_path,
                        line=node.lineno,
                        reason=(
                            "SN60 screening rejected benchmark-specific answer replay: "
                            f"`{node.name}` matches source fingerprints and emits "
                            "hardcoded findings."
                        ),
                        evidence=(
                            f"source_fingerprint_tests={len(fingerprint_tests)}; "
                            f"hardcoded_finding_dicts={len(hardcoded_findings)}; points=10"
                        ),
                    )
                )
    return findings


def source_fingerprint_membership_tests(function_node: ast.AST) -> list[str]:
    tests: list[str] = []
    for node in ast.walk(function_node):
        if not isinstance(node, ast.Compare):
            continue
        for operator, comparator in zip(node.ops, node.comparators, strict=False):
            if not isinstance(operator, (ast.In, ast.NotIn)):
                continue
            probe = string_constant(node.left)
            haystack = comparator
            if probe is None:
                probe = string_constant(comparator)
                haystack = node.left
            if probe is None or not looks_like_source_fingerprint(probe):
                continue
            if not references_scanned_source(haystack):
                continue
            tests.append(probe)
    return tests


def hardcoded_finding_dicts(function_node: ast.AST) -> list[ast.Dict]:
    findings: list[ast.Dict] = []
    for node in ast.walk(function_node):
        if not isinstance(node, ast.Dict):
            continue
        keys = {
            str(key.value)
            for key in node.keys
            if isinstance(key, ast.Constant) and isinstance(key.value, str)
        }
        if len(keys & FINDING_DICT_KEYS) < 4:
            continue
        location_keys = {"severity", "function", "contract", "file", "path"}
        if {"title", "description"} & keys and location_keys & keys:
            findings.append(node)
    return findings


def references_scanned_source(node: ast.AST) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id in {"text", "compact", "source", "src", "code"}:
            return True
        if isinstance(child, ast.Attribute) and child.attr in {"text", "source", "code"}:
            return True
    return False


def string_constant(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def looks_like_source_fingerprint(value: str) -> bool:
    stripped = value.strip()
    if len(stripped) < 8:
        return False
    source_markers = (
        "function",
        "def ",
        "self.",
        ".balances",
        "msg.sender",
        "require(",
        "assert ",
        ": constant",
    )
    code_punctuation = ("(", ")", "[", "]", ".", "_", "=", "+=", "-=", "=>")
    punctuation_count = sum(1 for marker in code_punctuation if marker in stripped)
    if any(marker in stripped for marker in source_markers) and punctuation_count >= 1:
        return True
    if re.search(r"\b[A-Za-z_]\w*\.[A-Za-z_]\w*\b", stripped):
        return True
    return bool(re.search(r"\b_?[A-Za-z_]\w*\([^)]*", stripped) and punctuation_count >= 2)


def line_for_offset(content: str, offset: int) -> int:
    return content.count("\n", 0, offset) + 1
