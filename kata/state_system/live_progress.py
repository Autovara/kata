"""Live round status persistence helpers."""

from __future__ import annotations

import json
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

LIVE_STATUS_ENV = "KATA_LIVE_STATUS_PATH"


def live_status_path() -> Path | None:
    raw_path = os.environ.get(LIVE_STATUS_ENV, "").strip()
    if not raw_path:
        return None
    return Path(raw_path).expanduser().resolve()


def update_live_status(update: dict[str, Any]) -> None:
    path = live_status_path()
    if path is None:
        return
    current = read_status(path)
    merged = merge_status(current, update)
    merged["schema_version"] = int(merged.get("schema_version") or 1)
    merged["updated_at"] = timestamp_now()
    write_status(path, merged)


def read_status(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def write_status(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=str(path.parent),
        delete=False,
    ) as handle:
        temp_path = Path(handle.name)
        handle.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    temp_path.chmod(0o644)
    os.replace(temp_path, path)
    path.chmod(0o644)


def merge_status(current: dict[str, Any], update: dict[str, Any]) -> dict[str, Any]:
    merged = dict(current)
    for key, value in update.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            nested = dict(merged[key])
            nested.update(value)
            merged[key] = nested
        else:
            merged[key] = value
    return merged



def timestamp_now() -> str:
    return datetime.now(UTC).isoformat()
