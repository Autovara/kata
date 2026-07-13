from __future__ import annotations

import ast
import py_compile
import re
import tempfile
from pathlib import Path

from kata.ast_utils import (
    count_module_function_defs,
    find_module_async_function_def,
    find_module_function_def,
    function_supports_no_arg_invocation,
)
from kata.provenance import sha256_directory
from kata.screening_system.models import ScreeningFinding, dedupe_findings
from kata.screening_system.python_ast import (
    agent_main_returns_direct_constant_report,
    agent_main_returns_direct_empty_report,
    dict_contains_string_key,
    iter_direct_function_returns,
)
from kata.submission_system.bundle import (
    AGENT_ENTRY_FILENAME,
    find_unexpected_bundle_paths,
    is_allowed_bundle_relative_path,
)
from kata.util import dedupe

MAX_SUBMISSION_BUNDLE_FILES = 16
MAX_SUBMISSION_FILE_KIB = 128
MAX_SUBMISSION_BUNDLE_KIB = 256
MAX_SUBMISSION_FILE_BYTES = MAX_SUBMISSION_FILE_KIB * 1024
MAX_SUBMISSION_BUNDLE_BYTES = MAX_SUBMISSION_BUNDLE_KIB * 1024

BENCHMARK_LEAK_TOKENS = (
    "curated-highs-only",
    "known_solution",
    "known solution",
    "expected_findings",
    "expected findings",
    "expected_vulnerabilities",
    "expected vulnerabilities",
    "ground_truth",
    "ground truth",
    "answer_key",
    "answer key",
    "scabench",
    "hardsteer",
)
VALIDATOR_SECRET_ENV_TOKENS = (
    "CHUTES_API_KEY",
    "KATA_VALIDATOR_API_KEY",
)
FORBIDDEN_ENV_REFERENCE_TOKENS = (
    "KATA_VALIDATOR_API_KEY",
    "KATA_VALIDATOR_API_BASE",
    "KATA_VALIDATOR_MODEL",
    "CHUTES_API_KEY",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GOOGLE_API_KEY",
    "OPENROUTER_API_KEY",
)
FORBIDDEN_PROVIDER_SUBSTRINGS = (
    "api.openai.com",
    "openrouter.ai",
    "anthropic.com",
    "generativelanguage.googleapis.com",
    "api.groq.com",
    "api.together.xyz",
    "api.fireworks.ai",
    "api.mistral.ai",
    "api.deepseek.com",
    "deepinfra.com",
    "cohere.ai",
)
FORBIDDEN_SAMPLING_NAMES = {
    "temperature",
    "top_p",
    "top_k",
    "min_p",
    "top_a",
    "frequency_penalty",
    "presence_penalty",
    "repetition_penalty",
    "seed",
    "logit_bias",
    "logprobs",
    "top_logprobs",
}
SECRET_PATTERN = re.compile(
    r"(sk-[A-Za-z0-9]{10,}|ghp_[A-Za-z0-9]{10,}|hf_[A-Za-z0-9]{10,}|cpk_[A-Za-z0-9]{10,})"
)
AGENT_MAIN_PATTERN = re.compile(r"(?m)^(?:async\s+)?def\s+agent_main\s*\(")


def format_size_limit(byte_count: int) -> str:
    if byte_count % 1024 == 0:
        return f"{byte_count // 1024} KiB ({byte_count} bytes)"
    return f"{byte_count} bytes"


def screen_submission_bundle_files(submission_root: Path) -> list[ScreeningFinding]:
    findings: list[ScreeningFinding] = []
    unexpected_paths = find_unexpected_bundle_paths(submission_root)
    if unexpected_paths:
        findings.append(
            reject_finding(
                "bundle.unsupported_files",
                "Submission bundle contains unsupported files: "
                + ", ".join(unexpected_paths),
            )
        )

    symlink_paths = find_bundle_symlink_paths(submission_root)
    if symlink_paths:
        findings.append(
            reject_finding(
                "bundle.symlink",
                "Submission bundle must not contain symlinks: " + ", ".join(symlink_paths),
            )
        )

    bundle_paths = find_bundle_relative_paths(submission_root)
    if len(bundle_paths) > MAX_SUBMISSION_BUNDLE_FILES:
        findings.append(
            reject_finding(
                "bundle.file_count",
                "Submission bundle is too large. "
                f"Found {len(bundle_paths)} files; limit is {MAX_SUBMISSION_BUNDLE_FILES}.",
            )
        )

    total_bytes = 0
    for relative_path in bundle_paths:
        file_path = submission_root / relative_path
        file_bytes = file_path.stat().st_size
        total_bytes += file_bytes
        if file_bytes > MAX_SUBMISSION_FILE_BYTES:
            findings.append(
                reject_finding(
                    "bundle.file_size",
                    f"Submission bundle file is too large: {relative_path} "
                    f"({file_bytes} bytes; limit is "
                    f"{format_size_limit(MAX_SUBMISSION_FILE_BYTES)}).",
                    path=relative_path,
                )
            )
    if total_bytes > MAX_SUBMISSION_BUNDLE_BYTES:
        findings.append(
            reject_finding(
                "bundle.total_size",
                "Submission bundle total size is too large. "
                f"Found {total_bytes} bytes; limit is "
                f"{format_size_limit(MAX_SUBMISSION_BUNDLE_BYTES)}.",
            )
        )
    return findings


def screen_bundle_python_sources(bundle_files: dict[str, str]) -> list[ScreeningFinding]:
    findings: list[ScreeningFinding] = []
    for relative_path, content in sorted(bundle_files.items()):
        try:
            ast.parse(content, filename=relative_path)
        except SyntaxError as exc:
            line_number = exc.lineno or 1
            findings.append(
                reject_finding(
                    "bundle.python_syntax",
                    "Submission bundle contains invalid Python syntax in "
                    f"{relative_path}:{line_number}.",
                    path=relative_path,
                    line=line_number,
                )
            )
            continue
        temp_path: Path | None = None
        bytecode_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                "w",
                suffix=".py",
                encoding="utf-8",
                delete=False,
            ) as handle:
                handle.write(content)
                temp_path = Path(handle.name)
            bytecode_path = temp_path.with_suffix(".pyc")
            py_compile.compile(str(temp_path), cfile=str(bytecode_path), doraise=True)
        except (OSError, py_compile.PyCompileError):
            findings.append(
                reject_finding(
                    "bundle.python_compile",
                    "Submission bundle failed Python compile smoke check in "
                    f"{relative_path}.",
                    path=relative_path,
                )
            )
        finally:
            if bytecode_path is not None:
                bytecode_path.unlink(missing_ok=True)
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)
    agent_source = bundle_files.get(AGENT_ENTRY_FILENAME, "")
    if agent_source and not agent_defines_required_entrypoint(agent_source):
        findings.append(
            reject_finding(
                "bundle.entrypoint",
                required_submission_entrypoint_reason(),
                path=AGENT_ENTRY_FILENAME,
            )
        )
    return findings


def screen_bundle_static_policy(bundle_files: dict[str, str]) -> list[ScreeningFinding]:
    findings: list[ScreeningFinding] = []
    parsed_trees: dict[str, ast.AST] = {}
    for relative_path, content in sorted(bundle_files.items()):
        try:
            parsed_trees[relative_path] = ast.parse(content, filename=relative_path)
        except SyntaxError:
            continue
        for token in FORBIDDEN_ENV_REFERENCE_TOKENS:
            if token in content:
                findings.append(
                    reject_finding(
                        "bundle.secret_env",
                        "Submission bundle must not read validator/provider secret env "
                        f"vars directly: {relative_path} references `{token}`.",
                        path=relative_path,
                    )
                )
        lowered = content.lower()
        for token in FORBIDDEN_PROVIDER_SUBSTRINGS:
            if token in lowered:
                findings.append(
                    reject_finding(
                        "bundle.provider_endpoint",
                        "Submission bundle must not hardcode provider endpoints directly: "
                        f"{relative_path} references `{token}`.",
                        path=relative_path,
                    )
                )
        if SECRET_PATTERN.search(content):
            findings.append(
                reject_finding(
                    "bundle.hardcoded_secret",
                    "Submission bundle appears to contain a hardcoded secret token: "
                    f"{relative_path}.",
                    path=relative_path,
                )
            )
    findings.extend(screen_bundle_miner_contract(parsed_trees))
    return findings


def screen_sn60_static_bundle(bundle_files: dict[str, str]) -> list[ScreeningFinding]:
    findings: list[ScreeningFinding] = []
    for relative_path, content in sorted(bundle_files.items()):
        if not relative_path.endswith(".py"):
            continue
        for token in VALIDATOR_SECRET_ENV_TOKENS:
            if token in content:
                findings.append(
                    reject_finding(
                        "sn60.validator_secret",
                        "SN60 screening rejected a validator secret reference: "
                        f"{relative_path} references `{token}`.",
                        path=relative_path,
                    )
                )
        if SECRET_PATTERN.search(content):
            findings.append(
                reject_finding(
                    "sn60.hardcoded_secret",
                    f"SN60 screening rejected a hardcoded secret token in {relative_path}.",
                    path=relative_path,
                )
            )

    agent_source = bundle_files.get(AGENT_ENTRY_FILENAME)
    if agent_source is None:
        return findings + [
            reject_finding(
                "sn60.agent_main_missing",
                "Submission agent must define agent_main(...).",
                path=AGENT_ENTRY_FILENAME,
            )
        ]

    try:
        tree = ast.parse(agent_source, filename=AGENT_ENTRY_FILENAME)
    except SyntaxError as exc:
        line_number = exc.lineno or 1
        return findings + [
            reject_finding(
                "sn60.python_syntax",
                f"Submission bundle contains invalid Python syntax in agent.py:{line_number}.",
                path=AGENT_ENTRY_FILENAME,
                line=line_number,
            )
        ]

    agent_main_def_count = count_module_function_defs(tree, "agent_main")
    if agent_main_def_count > 1:
        # Python binds the LAST top-level agent_main, but the structural checks
        # below inspect the FIRST (find_module_function_def). A submission could
        # otherwise pass a clean decoy definition through screening while the
        # sandbox executes a cheating/no-op one defined later. Reject the
        # ambiguity outright so the screened function is the executed function.
        findings.append(
            reject_finding(
                "sn60.agent_main_duplicate",
                "SN60 screening rejected an ambiguous agent: agent.py defines "
                f"agent_main {agent_main_def_count} times at module level. Python "
                "runs the last definition, so the anti-cheat checks cannot verify "
                "the function the sandbox actually executes. Define agent_main "
                "exactly once.",
                path=AGENT_ENTRY_FILENAME,
            )
        )
    else:
        agent_main = find_module_function_def(tree, "agent_main")
        if agent_main is None:
            if find_module_async_function_def(tree, "agent_main") is not None:
                findings.append(
                    reject_finding(
                        "sn60.agent_main_async",
                        "Submission agent_main must be a synchronous function; the SN60 "
                        "sandbox runner calls agent_main() directly and does not await "
                        "coroutines.",
                        path=AGENT_ENTRY_FILENAME,
                    )
                )
            else:
                findings.append(
                    reject_finding(
                        "sn60.agent_main_missing",
                        "Submission agent must define agent_main(...).",
                        path=AGENT_ENTRY_FILENAME,
                    )
                )
        elif not function_supports_no_arg_invocation(agent_main):
            findings.append(
                reject_finding(
                    "sn60.agent_main_args",
                    "Submission agent must support no-argument invocation: agent_main().",
                    path=AGENT_ENTRY_FILENAME,
                    line=agent_main.lineno,
                )
            )
        elif agent_main_returns_direct_empty_report(agent_main):
            findings.append(
                reject_finding(
                    "sn60.direct_empty_report",
                    "SN60 screening rejected a no-op agent: agent_main returns an empty "
                    "`vulnerabilities` list without doing any analysis.",
                    path=AGENT_ENTRY_FILENAME,
                    line=agent_main.lineno,
                )
            )
        elif agent_main_returns_direct_constant_report(agent_main):
            findings.append(
                reject_finding(
                    "sn60.direct_constant_report",
                    "SN60 screening rejected a fake agent: agent_main returns a constant "
                    "canned vulnerability report without reading project input.",
                    path=AGENT_ENTRY_FILENAME,
                    line=agent_main.lineno,
                )
            )

    lowered_source = agent_source.lower()
    for token in BENCHMARK_LEAK_TOKENS:
        if token in lowered_source:
            findings.append(
                reject_finding(
                    "sn60.answer_key_token",
                    "SN60 screening rejected benchmark-answer leakage token: "
                    f"`{token}`.",
                    path=AGENT_ENTRY_FILENAME,
                )
            )
    return dedupe_findings(findings)


def validate_sn60_static_screening(candidate_root: str | Path) -> list[str]:
    from kata.submission_system.bundle import load_bundle_files

    root = Path(candidate_root).expanduser().resolve()
    return finding_reasons(screen_sn60_static_bundle(load_bundle_files(root)))


def validate_bundle_python_sources(bundle_files: dict[str, str]) -> list[str]:
    return finding_reasons(screen_bundle_python_sources(bundle_files))


def validate_bundle_static_policy(bundle_files: dict[str, str]) -> list[str]:
    return finding_reasons(screen_bundle_static_policy(bundle_files))


def hash_submission_bundle(root: Path) -> str:
    bundle_root = root.expanduser().resolve()
    relative_paths = sorted(path for path in find_bundle_relative_paths(bundle_root))
    return sha256_directory(bundle_root, include=relative_paths)


def find_bundle_relative_paths(root: Path) -> list[str]:
    return [
        path.relative_to(root).as_posix()
        for path in sorted(root.rglob("*"))
        if not path.is_symlink()
        and path.is_file()
        and is_allowed_bundle_relative_path(path.relative_to(root).as_posix())
    ]


def find_bundle_symlink_paths(root: Path) -> list[str]:
    return [
        path.relative_to(root).as_posix()
        for path in sorted(root.rglob("*"))
        if path.is_symlink()
    ]


def screen_bundle_miner_contract(parsed_trees: dict[str, ast.AST]) -> list[ScreeningFinding]:
    agent_tree = parsed_trees.get(AGENT_ENTRY_FILENAME)
    if agent_tree is None:
        return []
    agent_main_fn = find_module_function_def(agent_tree, "agent_main")
    if agent_main_fn is None:
        if find_module_async_function_def(agent_tree, "agent_main") is not None:
            return [
                reject_finding(
                    "bundle.agent_main_async",
                    "Submission agent_main must be a synchronous function; the SN60 "
                    "sandbox runner calls agent_main() directly and does not await "
                    "coroutines.",
                    path=AGENT_ENTRY_FILENAME,
                )
            ]
        return [
            reject_finding(
                "bundle.entrypoint",
                required_submission_entrypoint_reason(),
                path=AGENT_ENTRY_FILENAME,
            )
        ]

    if not function_supports_no_arg_invocation(agent_main_fn):
        return [
            reject_finding(
                "bundle.agent_main_args",
                "Submission agent must support no-argument invocation: agent_main().",
                path=AGENT_ENTRY_FILENAME,
                line=agent_main_fn.lineno,
            )
        ]

    for return_node in iter_direct_function_returns(agent_main_fn):
        if return_node.value is None or not isinstance(return_node.value, ast.Dict):
            continue
        if not dict_contains_string_key(return_node.value, "vulnerabilities"):
            return [
                reject_finding(
                    "bundle.report_shape",
                    "Submission agent must return a Bitsec-compatible report with "
                    "top-level `vulnerabilities`.",
                    path=AGENT_ENTRY_FILENAME,
                    line=return_node.lineno,
                )
            ]
    return []


def screen_bundle_sampling_policy(parsed_trees: dict[str, ast.AST]) -> list[ScreeningFinding]:
    findings: list[ScreeningFinding] = []
    for relative_path, tree in sorted(parsed_trees.items()):
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            for keyword in node.keywords:
                if keyword.arg in FORBIDDEN_SAMPLING_NAMES:
                    findings.append(
                        reject_finding(
                            "bundle.sampling_parameter",
                            "Submission bundle must not control model sampling parameters "
                            f"directly: {relative_path} uses `{keyword.arg}`.",
                            path=relative_path,
                            line=getattr(keyword, "lineno", None),
                        )
                    )
                if keyword.arg is None and isinstance(keyword.value, ast.Dict):
                    for key_node in keyword.value.keys:
                        if (
                            isinstance(key_node, ast.Constant)
                            and isinstance(key_node.value, str)
                            and key_node.value in FORBIDDEN_SAMPLING_NAMES
                        ):
                            findings.append(
                                reject_finding(
                                    "bundle.sampling_parameter",
                                    "Submission bundle must not control model sampling "
                                    f"parameters directly: {relative_path} uses "
                                    f"`{key_node.value}`.",
                                    path=relative_path,
                                    line=getattr(key_node, "lineno", None),
                                )
                            )
    return findings


def reject_finding(
    rule_id: str,
    reason: str,
    *,
    path: str | None = None,
    line: int | None = None,
) -> ScreeningFinding:
    return ScreeningFinding(
        rule_id=rule_id,
        severity="reject",
        path=path,
        line=line,
        reason=reason,
        evidence=reason,
    )


def finding_reasons(findings: list[ScreeningFinding]) -> list[str]:
    return dedupe([finding.reason for finding in findings])


def required_submission_entrypoint_reason() -> str:
    return "Submission agent must define agent_main(...)."


def agent_defines_required_entrypoint(agent_source: str) -> bool:
    return AGENT_MAIN_PATTERN.search(agent_source) is not None
