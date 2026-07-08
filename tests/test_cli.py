from __future__ import annotations

import json
import types
from pathlib import Path

import pytest

from kata.interfaces.cli import build_parser, main, parse_round_candidate


def test_top_level_cli_exposes_agent_competition_commands() -> None:
    parser = build_parser()
    subparser_action = next(
        action
        for action in parser._actions
        if getattr(action, "choices", None)
    )
    commands = set(subparser_action.choices)

    assert {"king", "submission", "lane", "round"} == commands


def test_lane_cli_registers_and_lists_packs(tmp_path: Path, capsys) -> None:
    assert (
        main(
            [
                "lane",
                "init",
                "--lane-id",
                "sn60__bitsec",
                "--evaluator-id",
                "sn60_bitsec",
                "--public-root",
                str(tmp_path),
                "--json",
            ]
        )
        == 0
    )
    init_payload = json.loads(capsys.readouterr().out)
    assert init_payload["lane_id"] == "sn60__bitsec"

    assert (
        main(
            [
                "lane",
                "list",
                "--active-only",
                "--public-root",
                str(tmp_path),
                "--json",
            ]
        )
        == 0
    )
    list_payload = json.loads(capsys.readouterr().out)
    assert [pack["lane_id"] for pack in list_payload["packs"]] == ["sn60__bitsec"]
    assert list_payload["packs"][0]["evaluator_id"] == "sn60_bitsec"
    assert list_payload["packs"][0]["active"] is True

    registry_path = tmp_path / "lanes" / "registry.json"
    assert registry_path.exists()

    # Deactivate and confirm active-only listing excludes the lane.
    assert (
        main(
            [
                "lane",
                "init",
                "--lane-id",
                "sn60__bitsec",
                "--evaluator-id",
                "sn60_bitsec",
                "--inactive",
                "--public-root",
                str(tmp_path),
            ]
        )
        == 0
    )
    capsys.readouterr()
    assert (
        main(
            [
                "lane",
                "list",
                "--active-only",
                "--public-root",
                str(tmp_path),
                "--json",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["packs"] == []


def test_lane_cli_accepts_subnet_pack_alias(tmp_path: Path, capsys) -> None:
    assert (
        main(
            [
                "lane",
                "init",
                "--lane-id",
                "sn60__bitsec",
                "--subnet-pack",
                "sn60__bitsec",
                "--evaluator-id",
                "sn60_bitsec",
                "--public-root",
                str(tmp_path),
                "--json",
            ]
        )
        == 0
    )
    capsys.readouterr()

    assert (
        main(["lane", "list", "--public-root", str(tmp_path), "--json"])
        == 0
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["packs"][0]["subnet_pack"] == "sn60__bitsec"


def test_lane_cli_sync_registry_rebuilds_from_disk(tmp_path: Path, capsys) -> None:
    assert (
        main(
            [
                "lane",
                "init",
                "--lane-id",
                "sn60__bitsec",
                "--evaluator-id",
                "sn60_bitsec",
                "--public-root",
                str(tmp_path),
            ]
        )
        == 0
    )
    capsys.readouterr()
    (tmp_path / "lanes" / "registry.json").unlink()

    assert main(["lane", "sync-registry", "--public-root", str(tmp_path), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["packs"] == ["sn60__bitsec"]


def test_parse_round_candidate_accepts_id_path_pairs() -> None:
    assert parse_round_candidate("cand-1=/tmp/agent") == ("cand-1", "/tmp/agent")
    assert parse_round_candidate(" cand-2 = /tmp/x ") == ("cand-2", "/tmp/x")


def test_parse_round_candidate_rejects_malformed_specs() -> None:
    for bad in ("no-equals", "=only-path", "only-id="):
        with pytest.raises(SystemExit):
            parse_round_candidate(bad)


def test_round_cli_parses_candidates_and_emits_json(monkeypatch, capsys) -> None:
    import kata.interfaces.cli as cli

    fake_result = types.SimpleNamespace(
        run_id="sn60-round-x",
        output_root="/tmp/runs/sn60-round-x",
        winner_submission_id="cand-b",
        winner_challenge_summary_path="/tmp/runs/sn60-round-x/d-1/challenge_summary.json",
        promotion_ready=True,
        promotion_reason="cand-b beat the current SN60 king",
        king=types.SimpleNamespace(
            aggregated_score=0.25,
            average_detection_rate=0.25,
            true_positives=1,
            total_expected=4,
            total_found=2,
            precision=0.5,
            f1_score=0.4,
            invalid_runs=0,
            codebase_pass_count=1,
            project_summaries=[],
        ),
        entries=[
            types.SimpleNamespace(
                submission_id="cand-b",
                beats_king=True,
                duel_run_id="d-1",
                candidate=types.SimpleNamespace(
                    aggregated_score=0.5,
                    average_detection_rate=0.5,
                    true_positives=2,
                    total_expected=4,
                    total_found=3,
                    precision=0.66,
                    f1_score=0.5,
                    invalid_runs=0,
                    codebase_pass_count=2,
                    project_summaries=[],
                ),
            )
        ],
    )
    captured: dict[str, object] = {}

    def fake_run_sn60_round(**kwargs):
        captured.update(kwargs)
        return fake_result

    monkeypatch.setattr(cli, "run_sn60_round", fake_run_sn60_round)

    exit_code = main(
        [
            "round",
            "--king-path", "/king",
            "--candidate", "cand-b=/c-b",
            "--sn60-project-key", "project-alpha",
            "--json",
        ]
    )

    assert exit_code == 0
    assert captured["candidates"] == [("cand-b", "/c-b")]
    assert captured["project_keys"] == ["project-alpha"]
    payload = json.loads(capsys.readouterr().out)
    assert payload["winner_submission_id"] == "cand-b"
    assert payload["promotion_ready"] is True
    assert payload["entries"][0]["submission_id"] == "cand-b"
    assert payload["entries"][0]["beats_king"] is True
    # Rich per-variant detail for the dashboard's per-PR duel view.
    assert payload["king"]["precision"] == 0.5
    assert "projects" in payload["king"]
    assert payload["entries"][0]["precision"] == 0.66
    assert payload["entries"][0]["f1_score"] == 0.5
    assert "projects" in payload["entries"][0]


def test_round_cli_samples_problems_when_keys_omitted(tmp_path, monkeypatch, capsys) -> None:
    import kata.interfaces.cli as cli

    benchmark = tmp_path / "sandbox" / "validator" / "curated-highs-only-2025-08-08.json"
    benchmark.parent.mkdir(parents=True)
    keys = [f"proj-{index}" for index in range(5)]
    benchmark.write_text(
        json.dumps([{"project_id": key, "vulnerabilities": [{"title": "x"}]} for key in keys])
        + "\n",
        encoding="utf-8",
    )
    king = tmp_path / "king"
    king.mkdir()
    (king / "agent.py").write_text("def agent_main():\n    return {}\n", encoding="utf-8")

    monkeypatch.delenv("KATA_SN60_PROJECT_KEYS", raising=False)
    monkeypatch.setenv("KATA_SN60_PROJECT_SAMPLE_SIZE", "3")
    monkeypatch.setenv("KATA_SN60_PROJECT_SAMPLE_SECRET", "round-secret")

    captured: dict[str, object] = {}

    def fake_run_sn60_round(**kwargs):
        captured.update(kwargs)
        return types.SimpleNamespace(
            run_id="r",
            output_root=str(tmp_path / "runs" / "r"),
            winner_submission_id=None,
            winner_challenge_summary_path=None,
            promotion_ready=False,
            promotion_reason="no candidate beat the current SN60 king",
            king=types.SimpleNamespace(
                aggregated_score=0.0,
                average_detection_rate=0.0,
                true_positives=0,
                total_expected=0,
                total_found=0,
                precision=0.0,
                f1_score=0.0,
                invalid_runs=0,
                codebase_pass_count=0,
                project_summaries=[],
            ),
            entries=[],
        )

    monkeypatch.setattr(cli, "run_sn60_round", fake_run_sn60_round)

    exit_code = main(
        [
            "round",
            "--king-path", str(king),
            "--candidate", "cand=/tmp/cand",
            "--sn60-sandbox-root", str(tmp_path / "sandbox"),
            "--sn60-benchmark-file", str(benchmark),
            "--sn60-sandbox-commit", "test-commit",
            "--json",
        ]
    )

    assert exit_code == 0
    sampled = captured["project_keys"]
    assert len(sampled) == 3
    assert set(sampled).issubset(set(keys))
