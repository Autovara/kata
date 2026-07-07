from __future__ import annotations

import json
from pathlib import Path

from kata.evaluators.king_cache import (
    KingScoreboard,
    benchmark_version_key,
    load_king_scoreboard,
    save_king_scoreboard,
)


def test_benchmark_version_key_combines_scorer_and_benchmark_hash() -> None:
    assert benchmark_version_key("ScaBenchScorerV2", "abc123") == "ScaBenchScorerV2@abc123"


def test_record_and_read_runs_by_replica_index() -> None:
    board = KingScoreboard(king_hash="k1", benchmark_version="v1")
    assert board.cached_run("proj", 1) is None

    board.record_run("proj", 1, {"success": True}, {"status": "success"})
    board.record_run("proj", 2, {"success": False}, {"status": "error"})

    assert board.cached_run("proj", 1) == {
        "report": {"success": True},
        "evaluation": {"status": "success"},
    }
    assert board.cached_run("proj", 2)["evaluation"] == {"status": "error"}
    assert board.cached_run("proj", 3) is None
    assert board.cached_run("other", 1) is None


def test_scoreboard_roundtrips_through_disk(tmp_path: Path) -> None:
    path = tmp_path / "king_scoreboard.json"
    board = KingScoreboard(king_hash="k1", benchmark_version="v1")
    board.record_run("proj", 1, {"success": True}, {"status": "success"})
    save_king_scoreboard(path, board)

    loaded = load_king_scoreboard(path, king_hash="k1", benchmark_version="v1")
    assert loaded.cached_run("proj", 1) == {
        "report": {"success": True},
        "evaluation": {"status": "success"},
    }


def test_stale_king_hash_is_ignored(tmp_path: Path) -> None:
    path = tmp_path / "king_scoreboard.json"
    board = KingScoreboard(king_hash="old-king", benchmark_version="v1")
    board.record_run("proj", 1, {"success": True}, {"status": "success"})
    save_king_scoreboard(path, board)

    fresh = load_king_scoreboard(path, king_hash="new-king", benchmark_version="v1")
    assert fresh.king_hash == "new-king"
    assert fresh.scores == {}


def test_stale_benchmark_version_is_ignored(tmp_path: Path) -> None:
    path = tmp_path / "king_scoreboard.json"
    board = KingScoreboard(king_hash="k1", benchmark_version="old-benchmark")
    board.record_run("proj", 1, {"success": True}, {"status": "success"})
    save_king_scoreboard(path, board)

    fresh = load_king_scoreboard(path, king_hash="k1", benchmark_version="new-benchmark")
    assert fresh.scores == {}


def test_corrupt_scoreboard_file_falls_back_to_empty(tmp_path: Path) -> None:
    path = tmp_path / "king_scoreboard.json"
    path.write_text("{ not json", encoding="utf-8")
    board = load_king_scoreboard(path, king_hash="k1", benchmark_version="v1")
    assert board.scores == {}


def test_save_is_atomic_and_leaves_no_temp_file(tmp_path: Path) -> None:
    path = tmp_path / "king_scoreboard.json"
    board = KingScoreboard(king_hash="k1", benchmark_version="v1")
    board.record_run("proj", 1, {"success": True}, {"status": "success"})
    save_king_scoreboard(path, board)
    assert path.exists()
    assert not path.with_name(path.name + ".tmp").exists()
    on_disk = json.loads(path.read_text(encoding="utf-8"))
    assert on_disk["king_hash"] == "k1"
    assert on_disk["benchmark_version"] == "v1"
