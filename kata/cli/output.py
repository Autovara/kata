"""Stdout helpers shared by every command handler.

``print_json`` is imported by kata-sn60, which is packaged and deployed separately, so it is public
surface rather than a local convenience.
"""

from __future__ import annotations

import json

from kata.submissions.layout import read_changed_paths_file


def collect_changed_paths(
    inline_paths: list[str] | None,
    file_path: str | None,
) -> list[str]:
    changed_paths = list(inline_paths or [])
    if file_path:
        changed_paths.extend(read_changed_paths_file(file_path))
    return changed_paths


def print_json(payload: dict[str, object]) -> None:
    print(json.dumps(payload, indent=2))
