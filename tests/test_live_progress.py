from __future__ import annotations

import json
import os
import stat
from pathlib import Path

from kata.live_progress import update_live_status


def test_update_live_status_merges_flat_and_nested_keys(
    monkeypatch,
    tmp_path: Path,
) -> None:
    status_path = tmp_path / "live-status.json"
    monkeypatch.setenv("KATA_LIVE_STATUS_PATH", str(status_path))

    update_live_status(
        {"state": "screening", "phase": "sn60-screening", "lane_id": "sn60__bitsec"}
    )
    update_live_status(
        {
            "state": "evaluating",
            "phase": "sn60-duel",
            "project_keys": ["project-a", "project-b"],
            "replicas_per_project": 3,
        }
    )

    payload = json.loads(status_path.read_text(encoding="utf-8"))
    assert payload["state"] == "evaluating"
    assert payload["phase"] == "sn60-duel"
    assert payload["lane_id"] == "sn60__bitsec"
    assert payload["project_keys"] == ["project-a", "project-b"]
    assert payload["schema_version"] == 1
    assert payload["updated_at"]
    if os.name != "nt":
        assert stat.S_IMODE(status_path.stat().st_mode) == 0o644


def test_update_live_status_is_noop_without_env(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.delenv("KATA_LIVE_STATUS_PATH", raising=False)
    # Should not raise or write anything when the env var is unset.
    update_live_status({"state": "screening"})
    assert not list(tmp_path.iterdir())
