from __future__ import annotations

import json
from pathlib import Path

from kata.oracle import main, verify_oracle


def test_verify_oracle_passes_required_and_forbidden_checks(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    task_dir = tmp_path / "task"
    workspace.mkdir()
    task_dir.mkdir()
    (workspace / "article.md").write_text(
        "Correct sourced fact.\n",
        encoding="utf-8",
    )
    (task_dir / "oracle.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "target_files": ["article.md"],
                "required_contains": [
                    {"path": "article.md", "text": "Correct sourced fact."}
                ],
                "forbidden_contains": [
                    {"path": "article.md", "text": "Wrong claim"}
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )

    result = verify_oracle(workspace=workspace, task_dir=task_dir)

    assert result.passed
    assert result.score == 1.0


def test_verify_oracle_fails_missing_required_text(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    task_dir = tmp_path / "task"
    workspace.mkdir()
    task_dir.mkdir()
    (workspace / "article.md").write_text("Different text.\n", encoding="utf-8")
    (task_dir / "oracle.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "required_contains": [
                    {"path": "article.md", "text": "Correct sourced fact."}
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )

    result = verify_oracle(workspace=workspace, task_dir=task_dir)

    assert not result.passed
    assert result.score == 0.0
    assert "Required text not found" in result.failures[0]


def test_oracle_cli_writes_score_file(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    task_dir = tmp_path / "task"
    score_file = tmp_path / "score.txt"
    workspace.mkdir()
    task_dir.mkdir()
    (workspace / "file.txt").write_text("ok\n", encoding="utf-8")
    (task_dir / "oracle.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "required_regex": [{"path": "file.txt", "pattern": "^ok$"}],
            }
        )
        + "\n",
        encoding="utf-8",
    )

    exit_code = main(
        [
            "verify",
            "--workspace",
            str(workspace),
            "--task-dir",
            str(task_dir),
            "--score-file",
            str(score_file),
        ]
    )

    assert exit_code == 0
    assert score_file.read_text(encoding="utf-8") == "1.000000\n"
