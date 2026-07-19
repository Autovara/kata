from __future__ import annotations

import json
import os
from pathlib import Path


def dedupe(values: list[str]) -> list[str]:
    unique: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value in seen:
            continue
        unique.append(value)
        seen.add(value)
    return unique


def write_json(path: Path, payload: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Write atomically (temp in the same directory + os.replace) so a crash or full
    # disk can never leave a half-written / corrupt JSON file behind. Lane king
    # state, benchmark snapshots and promotion records all flow through here, and a
    # torn write of any of them would freeze the competition.
    text = json.dumps(payload, indent=2) + "\n"
    tmp_path = path.parent / f".{path.name}.tmp.{os.getpid()}"
    try:
        tmp_path.write_text(text, encoding="utf-8")
        os.replace(tmp_path, path)
    finally:
        if tmp_path.exists():
            tmp_path.unlink()
    return path
