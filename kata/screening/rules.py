from __future__ import annotations

import ast
import py_compile
import re
import tempfile
from pathlib import Path

from kata.ast_utils import (
    count_module_function_defs,
    count_module_scope_name_bindings,
    declares_global_binding,
    find_module_async_function_def,
    find_module_function_def,
    function_supports_no_arg_invocation,
    has_module_scope_star_import,
    rebinds_name_dynamically,
    unbinds_module_scope_name,
)
from kata.provenance import sha256_directory
from kata.screening.models import ScreeningFinding
from kata.screening.python_ast import (
    dict_contains_string_key,
    iter_direct_function_returns,
)
from kata.submissions.bundle import (
    AGENT_ENTRY_FILENAME,
    find_unexpected_bundle_paths,
    is_allowed_bundle_relative_path,
)
from kata.submissions.layout import (
    agent_defines_required_entrypoint,
    required_submission_entrypoint_reason,
)
from kata.util import dedupe

MAX_SUBMISSION_BUNDLE_FILES = 16
MAX_SUBMISSION_FILE_KIB = 128
MAX_SUBMISSION_BUNDLE_KIB = 256
MAX_SUBMISSION_FILE_BYTES = MAX_SUBMISSION_FILE_KIB * 1024
MAX_SUBMISSION_BUNDLE_BYTES = MAX_SUBMISSION_BUNDLE_KIB * 1024

FORBIDDEN_PLATFORM_SECRET_ENV_TOKENS = (
    "KATA_VALIDATOR_API_KEY",
    "KATA_VALIDATOR_API_BASE",
    "KATA_VALIDATOR_MODEL",
)
SECRET_PATTERN = re.compile(
    r"(sk-[A-Za-z0-9]{10,}|ghp_[A-Za-z0-9]{10,}|hf_[A-Za-z0-9]{10,}|cpk_[A-Za-z0-9]{10,})"
)


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
                "Submission bundle contains unsupported files: " + ", ".join(unexpected_paths),
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
        if not relative_path.endswith(".py"):
            continue  # non-Python bundle data (e.g. sealed_inference_key) is not code
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
                    f"Submission bundle failed Python compile smoke check in {relative_path}.",
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
        if not relative_path.endswith(".py"):
            continue  # non-Python bundle data (e.g. sealed_inference_key) is not code
        try:
            parsed_trees[relative_path] = ast.parse(content, filename=relative_path)
        except SyntaxError:
            continue
        for token in FORBIDDEN_PLATFORM_SECRET_ENV_TOKENS:
            if token in content:
                findings.append(
                    reject_finding(
                        "bundle.secret_env",
                        "Submission bundle must not read Kata platform secret env "
                        f"vars directly: {relative_path} references `{token}`.",
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
        path.relative_to(root).as_posix() for path in sorted(root.rglob("*")) if path.is_symlink()
    ]


def screen_bundle_miner_contract(parsed_trees: dict[str, ast.AST]) -> list[ScreeningFinding]:
    agent_tree = parsed_trees.get(AGENT_ENTRY_FILENAME)
    if agent_tree is None:
        return []
    # Reject a duplicate entrypoint before any single-definition check: screening
    # inspects the first agent_main, but Python runs the last binding, so a
    # decoy-first + shadow-last pair could otherwise clear anti-cheat while the
    # runner executes a function that was never validated.
    if count_module_function_defs(agent_tree, "agent_main") > 1:
        return [
            reject_finding(
                "bundle.agent_main_duplicate",
                "Submission defines agent_main more than once; define it exactly "
                "once. Python executes the last definition, which screening cannot "
                "validate.",
                path=AGENT_ENTRY_FILENAME,
            )
        ]
    # The duplicate-`def` rule above answers only "how many top-level defs?". Screening validates
    # ONE ast node while the runner calls whatever the module global holds after import, so those
    # agree only if the inspected `def` is the only thing that ever binds the name. Every other
    # binding form -- assignment, `import ... as`, a loop/`with`/`except` target, a `def` nested in
    # module-level control flow, a walrus, a `class` of the same name -- was invisible here, and a
    # decoy-plus-rebind submission passed every check tied to the inspected function.
    if count_module_scope_name_bindings(agent_tree, "agent_main") > 1:
        return [
            reject_finding(
                "bundle.agent_main_rebound",
                "Submission binds agent_main more than once in module scope. Define it exactly "
                "once, with a plain `def`: screening validates that definition, and Python "
                "executes whatever the name is bound to last.",
                path=AGENT_ENTRY_FILENAME,
            )
        ]
    if unbinds_module_scope_name(agent_tree, "agent_main"):
        return [
            reject_finding(
                "bundle.agent_main_deleted",
                "Submission deletes agent_main after defining it. Whatever answers for the name "
                "afterwards -- a module __getattr__, for instance -- is not the definition "
                "screening validated.",
                path=AGENT_ENTRY_FILENAME,
            )
        ]
    if has_module_scope_star_import(agent_tree):
        return [
            reject_finding(
                "bundle.agent_main_star_import",
                "Submission uses `from ... import *` at module scope, which can rebind agent_main "
                "invisibly. Import the names you need explicitly.",
                path=AGENT_ENTRY_FILENAME,
            )
        ]
    if declares_global_binding(agent_tree, "agent_main"):
        return [
            reject_finding(
                "bundle.agent_main_rebound",
                "Submission assigns agent_main through a `global` declaration, which replaces the "
                "entrypoint at import time with a function screening never inspected.",
                path=AGENT_ENTRY_FILENAME,
            )
        ]
    if rebinds_name_dynamically(agent_tree, "agent_main"):
        return [
            reject_finding(
                "bundle.agent_main_namespace_mutation",
                "Submission writes the module namespace in a way that could replace agent_main "
                "(globals()/vars()/setattr/exec). Bind the entrypoint with a plain `def`.",
                path=AGENT_ENTRY_FILENAME,
            )
        ]

    agent_main_fn = find_module_function_def(agent_tree, "agent_main")
    if agent_main_fn is None:
        if find_module_async_function_def(agent_tree, "agent_main") is not None:
            return [
                reject_finding(
                    "bundle.agent_main_async",
                    "Submission agent_main must be a synchronous function; the "
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

    if agent_main_fn.decorator_list:
        # A decorator's return value is by definition not the body screening just read. Static
        # analysis cannot tell an identity-preserving wrapper from a replacement, so this fails
        # closed: an honest submission inlines the wrapper.
        return [
            reject_finding(
                "bundle.agent_main_decorated",
                "Submission decorates agent_main. A decorator returns a different object from the "
                "function screening validated, so the entrypoint must be undecorated.",
                path=AGENT_ENTRY_FILENAME,
                line=agent_main_fn.lineno,
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
                    "Submission agent must return a report with top-level `vulnerabilities`.",
                    path=AGENT_ENTRY_FILENAME,
                    line=return_node.lineno,
                )
            ]
    return []


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
