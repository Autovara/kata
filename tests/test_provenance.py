from __future__ import annotations

from pathlib import Path

from kata.provenance import pool_fingerprint


def write_task_file(root: Path, name: str, content: str) -> None:
    path = root / name
    path.write_text(content, encoding="utf-8")
    if name == "checks.sh":
        path.chmod(0o755)


def create_task(root: Path, task_id: str, task_body: str) -> Path:
    task_root = root / task_id
    task_root.mkdir()
    write_task_file(task_root, "task.md", task_body)
    write_task_file(task_root, "repo_ref.txt", "https://github.com/example/repo.git@main\n")
    write_task_file(task_root, "checks.sh", "#!/usr/bin/env bash\nset -euo pipefail\nexit 0\n")
    write_task_file(task_root, "rubric.md", "# Rubric\n\n- Pass.\n")
    write_task_file(task_root, "allowed_paths.txt", "src/\n")
    write_task_file(task_root, "forbidden_paths.txt", "eval/\n")
    return task_root


def test_pool_fingerprint_changes_when_task_content_changes(tmp_path: Path) -> None:
    task_a = create_task(tmp_path, "task-a", "# Eval Task: task-a\n\nFirst version.\n")
    initial = pool_fingerprint([task_a])

    write_task_file(task_a, "task.md", "# Eval Task: task-a\n\nSecond version.\n")

    assert pool_fingerprint([task_a]) != initial


def test_pool_fingerprint_is_stable_across_task_order(tmp_path: Path) -> None:
    task_a = create_task(tmp_path, "task-a", "# Eval Task: task-a\n\nBody A.\n")
    task_b = create_task(tmp_path, "task-b", "# Eval Task: task-b\n\nBody B.\n")

    assert pool_fingerprint([task_a, task_b]) == pool_fingerprint([task_b, task_a])
