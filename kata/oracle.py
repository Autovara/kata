from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ORACLE_FILENAME = "oracle.json"


@dataclass(frozen=True)
class OracleCheck:
    path: str
    value: str


@dataclass(frozen=True)
class OracleResult:
    passed: bool
    score: float
    failures: list[str]


def verify_oracle(
    *,
    workspace: Path,
    task_dir: Path,
) -> OracleResult:
    oracle_path = task_dir / ORACLE_FILENAME
    if not oracle_path.exists():
        return OracleResult(
            passed=False,
            score=0.0,
            failures=[f"Missing task oracle: {ORACLE_FILENAME}"],
        )

    payload = load_oracle_payload(oracle_path)
    validate_oracle_payload(payload)
    failures: list[str] = []
    target_files = read_string_list(payload, "target_files")
    for relative_path in target_files:
        if not safe_workspace_path(workspace, relative_path).is_file():
            failures.append(f"Target file does not exist: {relative_path}")

    failures.extend(
        check_contains(
            workspace,
            read_check_list(payload, "required_contains", value_key="text"),
            should_contain=True,
        )
    )
    failures.extend(
        check_contains(
            workspace,
            read_check_list(payload, "forbidden_contains", value_key="text"),
            should_contain=False,
        )
    )
    failures.extend(
        check_regex(
            workspace,
            read_check_list(payload, "required_regex", value_key="pattern"),
            should_match=True,
        )
    )
    failures.extend(
        check_regex(
            workspace,
            read_check_list(payload, "forbidden_regex", value_key="pattern"),
            should_match=False,
        )
    )

    if failures:
        return OracleResult(passed=False, score=0.0, failures=failures)
    return OracleResult(passed=True, score=1.0, failures=[])


def load_oracle_payload(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid oracle JSON at {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"Oracle must be a JSON object: {path}")
    schema_version = payload.get("schema_version", 1)
    if schema_version != 1:
        raise ValueError(f"Unsupported oracle schema_version: {schema_version}")
    return payload


def validate_oracle_payload(payload: dict[str, Any]) -> None:
    read_string_list(payload, "target_files")
    for key, value_key in (
        ("required_contains", "text"),
        ("forbidden_contains", "text"),
        ("required_regex", "pattern"),
        ("forbidden_regex", "pattern"),
    ):
        checks = read_check_list(payload, key, value_key=value_key)
        if value_key == "pattern":
            for check in checks:
                try:
                    re.compile(check.value)
                except re.error as exc:
                    raise ValueError(
                        f"Oracle `{key}` contains invalid regex for {check.path}: {exc}"
                    ) from exc


def read_string_list(payload: dict[str, Any], key: str) -> list[str]:
    raw = payload.get(key, [])
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ValueError(f"Oracle `{key}` must be a list.")
    values: list[str] = []
    for item in raw:
        if not isinstance(item, str) or not item.strip():
            raise ValueError(f"Oracle `{key}` entries must be non-empty strings.")
        values.append(item.strip())
    return values


def read_check_list(
    payload: dict[str, Any],
    key: str,
    *,
    value_key: str,
) -> list[OracleCheck]:
    raw = payload.get(key, [])
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ValueError(f"Oracle `{key}` must be a list.")
    checks: list[OracleCheck] = []
    for item in raw:
        if not isinstance(item, dict):
            raise ValueError(f"Oracle `{key}` entries must be objects.")
        path = item.get("path")
        value = item.get(value_key)
        if not isinstance(path, str) or not path.strip():
            raise ValueError(f"Oracle `{key}` entries require a non-empty path.")
        if not isinstance(value, str) or not value:
            raise ValueError(f"Oracle `{key}` entries require a non-empty {value_key}.")
        checks.append(OracleCheck(path=path.strip(), value=value))
    return checks


def check_contains(
    workspace: Path,
    checks: list[OracleCheck],
    *,
    should_contain: bool,
) -> list[str]:
    failures: list[str] = []
    for check in checks:
        content = read_workspace_text(workspace, check.path)
        found = check.value in content
        if should_contain and not found:
            failures.append(f"Required text not found in {check.path}: {check.value!r}")
        if not should_contain and found:
            failures.append(f"Forbidden text found in {check.path}: {check.value!r}")
    return failures


def check_regex(
    workspace: Path,
    checks: list[OracleCheck],
    *,
    should_match: bool,
) -> list[str]:
    failures: list[str] = []
    for check in checks:
        content = read_workspace_text(workspace, check.path)
        matched = re.search(check.value, content, flags=re.MULTILINE) is not None
        if should_match and not matched:
            failures.append(f"Required pattern not found in {check.path}: {check.value!r}")
        if not should_match and matched:
            failures.append(f"Forbidden pattern found in {check.path}: {check.value!r}")
    return failures


def read_workspace_text(workspace: Path, relative_path: str) -> str:
    path = safe_workspace_path(workspace, relative_path)
    if not path.is_file():
        raise ValueError(f"Oracle file does not exist: {relative_path}")
    return path.read_text(encoding="utf-8")


def safe_workspace_path(workspace: Path, relative_path: str) -> Path:
    if Path(relative_path).is_absolute():
        raise ValueError(f"Oracle paths must be relative: {relative_path}")
    root = workspace.resolve()
    path = (root / relative_path).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"Oracle path escapes workspace: {relative_path}") from exc
    return path


def write_score(path: str | None, score: float) -> None:
    if not path:
        return
    Path(path).expanduser().resolve().write_text(f"{score:.6f}\n", encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m kata.oracle")
    subparsers = parser.add_subparsers(dest="command", required=True)
    verify = subparsers.add_parser("verify", help="Run a task oracle against a workspace.")
    verify.add_argument("--workspace", required=True)
    verify.add_argument("--task-dir", required=True)
    verify.add_argument("--score-file", default=None)
    verify.set_defaults(handler=handle_verify)
    return parser


def handle_verify(args: argparse.Namespace) -> int:
    result = verify_oracle(
        workspace=Path(args.workspace).expanduser().resolve(),
        task_dir=Path(args.task_dir).expanduser().resolve(),
    )
    write_score(args.score_file, result.score)
    if result.passed:
        print("Kata oracle passed.")
        return 0
    print("Kata oracle failed:", file=sys.stderr)
    for failure in result.failures:
        print(f"- {failure}", file=sys.stderr)
    return 1


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
