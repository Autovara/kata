"""Repository preflight behavior for each supported submission pack."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from kata.submissions import preflight

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SEALED_KEY = "04" + "ab" * 120
NETWORKING_AGENT = (
    "import socket\n"
    "import urllib.request\n\n\n"
    "def agent_main(project_dir=None, inference_api=None):\n"
    "    return {'vulnerabilities': []}\n"
)


def _write_bundle(
    repository_root: Path,
    pack: str,
    submission_id: str,
    agent_source: str,
    *,
    sealed_key: str | None = SEALED_KEY,
) -> Path:
    directory = (
        repository_root / "submissions" / pack / preflight.SUBMISSION_MODE / submission_id
    )
    directory.mkdir(parents=True)
    (directory / "agent.py").write_text(agent_source, encoding="utf-8")
    (directory / "agent_manifest.json").write_text(
        json.dumps({"schema_version": 1, "runtime": "python", "entrypoint": "agent.py"}) + "\n",
        encoding="utf-8",
    )
    (directory / "submission.json").write_text(
        json.dumps(
            {
                "schema_version": 2,
                "subnet_pack": pack,
                "mode": preflight.SUBMISSION_MODE,
                "submission_id": submission_id,
                "created_at": "2026-07-29T00:00:00Z",
                "author": "alice",
                "title": "t",
                "notes": "n",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    if sealed_key is not None:
        (directory / preflight.SEALED_KEY_FILENAME).write_text(
            sealed_key + "\n",
            encoding="utf-8",
        )
    return directory


def _check(directory: Path, repository_root: Path) -> list[str]:
    return preflight.check_submission(directory, repository_root=repository_root)


def _sn22_banned_tuple() -> tuple[str, ...] | None:
    """Read the actual local tuple iterated by SN22's static screen."""

    plugin = REPOSITORY_ROOT.parent / "kata-sn22" / "kata_sn22" / "plugin.py"
    if not plugin.is_file():
        return None
    tree = ast.parse(plugin.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(target, ast.Name) and target.id == "banned"
                   for target in node.targets):
            continue
        if not isinstance(node.value, (ast.Tuple, ast.List)):
            continue
        values = [
            element.value
            for element in node.value.elts
            if isinstance(element, ast.Constant) and isinstance(element.value, str)
        ]
        if values:
            return tuple(values)
    return None


@pytest.mark.contract
def test_sn22_network_markers_match_its_static_screen() -> None:
    banned = _sn22_banned_tuple()
    if banned is None:
        pytest.skip("kata-sn22 is not checked out beside this repository")
    assert preflight.SN22_DIRECT_NETWORK_MARKERS == banned


def test_pack_policies_are_explicit() -> None:
    assert preflight.SUPPORTED_PACKS == ("sn60__bitsec", "sn22__desearch")
    assert not preflight.PACK_POLICIES["sn60__bitsec"].banned_source_markers
    assert (
        preflight.PACK_POLICIES["sn22__desearch"].banned_source_markers
        == preflight.SN22_DIRECT_NETWORK_MARKERS
    )


def test_sn60_may_reach_the_inference_gateway(tmp_path: Path) -> None:
    directory = _write_bundle(
        tmp_path,
        "sn60__bitsec",
        "alice-20260729-01",
        NETWORKING_AGENT,
    )
    assert _check(directory, tmp_path) == []


def test_reigning_sn60_king_passes(tmp_path: Path) -> None:
    king = REPOSITORY_ROOT / "kings" / "sn60__bitsec" / "miner" / "agent.py"
    directory = _write_bundle(
        tmp_path,
        "sn60__bitsec",
        "alice-20260729-02",
        king.read_text(encoding="utf-8"),
    )
    assert _check(directory, tmp_path) == []


@pytest.mark.parametrize("marker", preflight.SN22_DIRECT_NETWORK_MARKERS)
def test_sn22_may_not_reach_providers_directly(tmp_path: Path, marker: str) -> None:
    source = f"{marker}\n\n\ndef agent_main():\n    return {{}}\n"
    directory = _write_bundle(
        tmp_path,
        "sn22__desearch",
        "bob-20260729-01",
        source,
    )
    problems = _check(directory, tmp_path)
    assert any(marker in problem for problem in problems), problems


def test_sn22_network_refusal_explains_the_supported_path(tmp_path: Path) -> None:
    directory = _write_bundle(
        tmp_path,
        "sn22__desearch",
        "bob-20260729-02",
        NETWORKING_AGENT,
    )
    problems = _check(directory, tmp_path)
    assert any(
        "sn22__desearch" in problem and "broker capability" in problem
        for problem in problems
    )


def test_reigning_sn22_king_passes(tmp_path: Path) -> None:
    king = REPOSITORY_ROOT / "kings" / "sn22__desearch" / "miner" / "agent.py"
    directory = _write_bundle(
        tmp_path,
        "sn22__desearch",
        "carol-20260729-01",
        king.read_text(encoding="utf-8"),
    )
    assert _check(directory, tmp_path) == []


@pytest.mark.parametrize("pack", preflight.SUPPORTED_PACKS)
def test_production_four_file_bundle_is_accepted(tmp_path: Path, pack: str) -> None:
    directory = _write_bundle(
        tmp_path,
        pack,
        "alice-20260729-03",
        "def agent_main():\n    return {'vulnerabilities': []}\n",
    )
    assert sorted(path.name for path in directory.iterdir()) == [
        "agent.py",
        "agent_manifest.json",
        "sealed_inference_key",
        "submission.json",
    ]
    assert _check(directory, tmp_path) == []


@pytest.mark.parametrize("pack", preflight.SUPPORTED_PACKS)
def test_unexpected_top_level_file_is_rejected(tmp_path: Path, pack: str) -> None:
    directory = _write_bundle(
        tmp_path,
        pack,
        "alice-20260729-04",
        "def agent_main():\n    return {}\n",
    )
    (directory / "notes.txt").write_text("hello", encoding="utf-8")
    problems = _check(directory, tmp_path)
    assert any("unexpected top-level entry 'notes.txt'" in problem for problem in problems)


def test_three_file_bundle_remains_a_valid_layout(tmp_path: Path) -> None:
    directory = _write_bundle(
        tmp_path,
        "sn60__bitsec",
        "alice-20260729-05",
        "def agent_main():\n    return {}\n",
        sealed_key=None,
    )
    assert _check(directory, tmp_path) == []


@pytest.mark.parametrize("pack", preflight.SUPPORTED_PACKS)
def test_shared_source_checks_still_apply_to_every_pack(tmp_path: Path, pack: str) -> None:
    directory = _write_bundle(
        tmp_path,
        pack,
        "alice-20260729-06",
        "def agent_main(:\n",
    )
    problems = _check(directory, tmp_path)
    assert any("syntax error" in problem for problem in problems)


def test_module_cli_discovers_submissions(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    directory = _write_bundle(
        tmp_path,
        "sn60__bitsec",
        "alice-20260729-07",
        "def agent_main():\n    return {}\n",
    )
    assert preflight.main(["--all"], repository_root=tmp_path) == 0
    assert f"ok    {directory.relative_to(tmp_path)}" in capsys.readouterr().out
