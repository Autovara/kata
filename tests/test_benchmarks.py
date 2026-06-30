from __future__ import annotations

import json
from pathlib import Path

from kata.benchmarks import (
    BENCHMARKS_ROOT_ENV,
    REGISTRY_MARKER_FILENAME,
    ensure_active_repo_pack,
    resolve_benchmark_registry,
    resolve_benchmarks_root,
    resolve_eval_pack_path,
)
from kata.eval_pack import discover_eval_pack_tasks, init_eval_pack


def write_registry_marker(
    root: Path,
    *,
    benchmarks_dir: str = "benchmarks",
    active_repo_packs: list[str] | None = None,
    default_repo_pack: str | None = None,
) -> None:
    root.mkdir(parents=True, exist_ok=True)
    payload: dict[str, object] = {
        "schema_version": 1,
        "registry_name": "test-registry",
        "benchmarks_dir": benchmarks_dir,
    }
    if active_repo_packs is not None:
        payload["active_repo_packs"] = active_repo_packs
    if default_repo_pack is not None:
        payload["default_repo_pack"] = default_repo_pack
    (root / REGISTRY_MARKER_FILENAME).write_text(
        json.dumps(payload) + "\n",
        encoding="utf-8",
    )
    (root / benchmarks_dir).mkdir(parents=True, exist_ok=True)


def write_task(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "task.md").write_text("# Task\n\nReal task text.\n", encoding="utf-8")
    (root / "repo_ref.txt").write_text(
        "https://github.com/example/repo.git@main\n",
        encoding="utf-8",
    )
    (root / "checks.sh").write_text(
        "#!/usr/bin/env bash\nset -euo pipefail\ntrue\n",
        encoding="utf-8",
    )
    (root / "checks.sh").chmod(0o755)
    (root / "rubric.md").write_text(
        "# Rubric\n\n## Pass Conditions\n- Real pass condition.\n",
        encoding="utf-8",
    )
    (root / "allowed_paths.txt").write_text("src/\n", encoding="utf-8")
    (root / "forbidden_paths.txt").write_text("docs/\n", encoding="utf-8")


def test_resolve_benchmark_registry_from_env_repo_root(
    tmp_path: Path,
    monkeypatch,
) -> None:
    registry_root = tmp_path / "registry"
    write_registry_marker(registry_root)
    monkeypatch.setenv(BENCHMARKS_ROOT_ENV, str(registry_root))

    registry = resolve_benchmark_registry()

    assert registry.root == registry_root.resolve()
    assert registry.benchmarks_dir == (registry_root / "benchmarks").resolve()
    assert registry.registry_name == "test-registry"
    assert registry.active_repo_packs == ()
    assert registry.default_repo_pack is None


def test_resolve_benchmark_registry_reads_active_repo_packs(
    tmp_path: Path,
) -> None:
    registry_root = tmp_path / "registry"
    write_registry_marker(
        registry_root,
        active_repo_packs=["e35ventura__taopedia-articles"],
        default_repo_pack="e35ventura__taopedia-articles",
    )

    registry = resolve_benchmark_registry(str(registry_root))

    assert registry.active_repo_packs == ("e35ventura__taopedia-articles",)
    assert registry.default_repo_pack == "e35ventura__taopedia-articles"


def test_ensure_active_repo_pack_rejects_inactive_repo_pack(
    tmp_path: Path,
    monkeypatch,
) -> None:
    registry_root = tmp_path / "registry"
    write_registry_marker(
        registry_root,
        active_repo_packs=["e35ventura__taopedia-articles"],
        default_repo_pack="e35ventura__taopedia-articles",
    )
    monkeypatch.setenv(BENCHMARKS_ROOT_ENV, str(registry_root))

    try:
        ensure_active_repo_pack("other__repo")
    except ValueError as exc:
        assert "Repo pack is not active" in str(exc)
        assert "e35ventura__taopedia-articles" in str(exc)
    else:
        raise AssertionError("Expected inactive repo pack to be rejected.")


def test_resolve_benchmarks_root_from_explicit_benchmarks_dir(
    tmp_path: Path,
) -> None:
    registry_root = tmp_path / "registry"
    write_registry_marker(registry_root)

    resolved = resolve_benchmarks_root(str(registry_root / "benchmarks"))

    assert resolved == (registry_root / "benchmarks").resolve()


def test_resolve_eval_pack_path_accepts_pack_id_from_registry_root(
    tmp_path: Path,
    monkeypatch,
) -> None:
    registry_root = tmp_path / "registry"
    write_registry_marker(registry_root)
    pack_root = registry_root / "benchmarks" / "example__repo"
    pack_root.mkdir(parents=True)
    monkeypatch.setenv(BENCHMARKS_ROOT_ENV, str(registry_root))

    resolved = resolve_eval_pack_path("example__repo")

    assert resolved == pack_root.resolve()


def test_init_eval_pack_defaults_to_registry_benchmarks_dir(
    tmp_path: Path,
    monkeypatch,
) -> None:
    registry_root = tmp_path / "registry"
    write_registry_marker(registry_root)
    monkeypatch.setenv(BENCHMARKS_ROOT_ENV, str(registry_root))

    pack_dir = init_eval_pack("https://github.com/example/repo.git", "fix-cli-flag")

    assert pack_dir == (
        registry_root / "benchmarks" / "example__repo" / "fix-cli-flag"
    ).resolve()


def test_init_eval_pack_accepts_explicit_benchmarks_dir_without_marker(
    tmp_path: Path,
) -> None:
    benchmarks_dir = tmp_path / "benchmarks"
    benchmarks_dir.mkdir(parents=True)

    pack_dir = init_eval_pack(
        "https://github.com/example/repo.git",
        "fix-cli-flag",
        str(benchmarks_dir),
    )

    assert pack_dir == (benchmarks_dir / "example__repo" / "fix-cli-flag").resolve()


def test_discover_eval_pack_tasks_accepts_pack_id_from_registry(
    tmp_path: Path,
    monkeypatch,
) -> None:
    registry_root = tmp_path / "registry"
    write_registry_marker(registry_root)
    monkeypatch.setenv(BENCHMARKS_ROOT_ENV, str(registry_root))
    task_root = registry_root / "benchmarks" / "example__repo" / "task-a"
    write_task(task_root)

    results = discover_eval_pack_tasks("example__repo")

    assert len(results) == 1
    assert results[0].root == task_root.resolve()
    assert results[0].is_valid


def test_resolve_benchmark_registry_discovers_marker_from_workspace(
    tmp_path: Path,
    monkeypatch,
) -> None:
    workspace_root = tmp_path / "workspace"
    kata_root = workspace_root / "Kata"
    registry_root = workspace_root / "bench-any-name"
    kata_root.mkdir(parents=True)
    write_registry_marker(registry_root)
    monkeypatch.delenv(BENCHMARKS_ROOT_ENV, raising=False)
    monkeypatch.chdir(kata_root)

    registry = resolve_benchmark_registry()

    assert registry.root == registry_root.resolve()
