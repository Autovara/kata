from __future__ import annotations

from pathlib import Path

from kata.eval_pack import render_validation_result, validate_eval_pack


def write_eval_file(root: Path, name: str, content: str) -> None:
    path = root / name
    path.write_text(content, encoding="utf-8")
    if name == "checks.sh":
        path.chmod(0o755)


def test_validate_eval_pack_rejects_placeholder_scaffold(tmp_path: Path) -> None:
    write_eval_file(
        tmp_path,
        "task.md",
        "# Eval Task: demo\n\n## Goal\n- Describe the exact change the agent must make.\n",
    )
    write_eval_file(tmp_path, "repo_ref.txt", "https://github.com/example/repo.git@main\n")
    write_eval_file(
        tmp_path,
        "checks.sh",
        '#!/usr/bin/env bash\nset -euo pipefail\necho "TODO: add repo-specific checks"\n',
    )
    write_eval_file(tmp_path, "rubric.md", "# Rubric\n\n- Task goal is completed.\n")
    write_eval_file(tmp_path, "allowed_paths.txt", "src/\n")
    write_eval_file(tmp_path, "forbidden_paths.txt", "eval/\n")

    result = validate_eval_pack(str(tmp_path))

    assert not result.is_valid
    assert result.placeholder_files == ["task.md", "checks.sh", "rubric.md"]
    rendered = render_validation_result(result)
    assert "Placeholder scaffold content still present:" in rendered


def test_validate_eval_pack_accepts_real_content(tmp_path: Path) -> None:
    write_eval_file(
        tmp_path,
        "task.md",
        "# Eval Task: demo\n\n## Goal\n- Add a missing CLI flag to export JSON output.\n",
    )
    write_eval_file(tmp_path, "repo_ref.txt", "https://github.com/example/repo.git@main\n")
    write_eval_file(
        tmp_path,
        "checks.sh",
        "#!/usr/bin/env bash\nset -euo pipefail\npython -m pytest tests/test_cli.py\n",
    )
    write_eval_file(
        tmp_path,
        "rubric.md",
        "# Rubric\n\n## Pass Conditions\n- The new flag writes valid JSON to stdout.\n",
    )
    write_eval_file(tmp_path, "allowed_paths.txt", "src/\n")
    write_eval_file(tmp_path, "forbidden_paths.txt", "eval/\n")

    result = validate_eval_pack(str(tmp_path))

    assert result.is_valid
    assert result.placeholder_files == []
