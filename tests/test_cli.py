from __future__ import annotations

import json
import types
from pathlib import Path

import pytest

from kata.interfaces.cli import build_parser, main, parse_round_candidate

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_top_level_cli_exposes_agent_competition_commands() -> None:
    parser = build_parser()
    subparser_action = next(
        action for action in parser._actions if getattr(action, "choices", None)
    )
    commands = set(subparser_action.choices)

    assert {"king", "submission", "lane", "round", "sn60-baseline"} == commands


def test_sn60_baseline_cli_is_separate_from_round_mode() -> None:
    parser = build_parser()
    subparser_action = next(
        action for action in parser._actions if getattr(action, "choices", None)
    )
    baseline_parser = subparser_action.choices["sn60-baseline"]
    option_dests = {
        action.dest for action in baseline_parser._actions if action.option_strings
    }

    assert "candidate" in option_dests
    assert "king_path" not in option_dests
    assert "candidate_only" not in option_dests


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

    assert main(["lane", "list", "--public-root", str(tmp_path), "--json"]) == 0
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


def test_king_show_reports_current_king(capsys) -> None:
    exit_code = main(
        [
            "king",
            "show",
            "--lane-id",
            "sn60__bitsec",
            "--public-root",
            str(REPO_ROOT),
            "--json",
        ]
    )
    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["lane_id"] == "sn60__bitsec"
    assert payload["repo_pack"] == "sn60__bitsec"
    assert payload["mode"] == "miner"
    assert payload["submission_id"] == "daedalus-Icarus-20260710-01"
    assert payload["artifact_hash"]
    assert payload["king_root"]


def test_king_show_unknown_lane_errors() -> None:
    with pytest.raises(SystemExit):
        main(["king", "show", "--lane-id", "does-not-exist"])


def test_king_export_copies_bundle(tmp_path: Path, capsys) -> None:
    output_dir = tmp_path / "exported-king"
    exit_code = main(
        [
            "king",
            "export",
            "--lane-id",
            "sn60__bitsec",
            "--output",
            str(output_dir),
            "--public-root",
            str(REPO_ROOT),
            "--json",
        ]
    )
    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["submission_id"] == "daedalus-Icarus-20260710-01"
    assert Path(payload["output_path"]) == output_dir.resolve()
    assert (output_dir / "agent.py").exists()
    assert (output_dir / "agent_manifest.json").exists()


def test_king_show_no_king_lane(tmp_path: Path, capsys) -> None:
    assert (
        main(
            [
                "lane",
                "init",
                "--lane-id",
                "empty-lane",
                "--evaluator-id",
                "sn60_bitsec",
                "--public-root",
                str(tmp_path),
            ]
        )
        == 0
    )
    capsys.readouterr()
    assert main(["king", "show", "--lane-id", "empty-lane", "--public-root", str(tmp_path)]) == 2
    assert "no crowned king" in capsys.readouterr().out


def test_round_cli_unknown_evaluator_errors() -> None:
    with pytest.raises(SystemExit):
        main(
            [
                "round",
                "--evaluator",
                "does-not-exist",
                "--king-path",
                "/k",
                "--candidate",
                "a=/a",
            ]
        )


def test_parse_round_candidate_accepts_id_path_pairs() -> None:
    assert parse_round_candidate("cand-1=/tmp/agent") == ("cand-1", "/tmp/agent")
    assert parse_round_candidate(" cand-2 = /tmp/x ") == ("cand-2", "/tmp/x")


def test_parse_round_candidate_rejects_malformed_specs() -> None:
    for bad in ("no-equals", "=only-path", "only-id="):
        with pytest.raises(SystemExit):
            parse_round_candidate(bad)


def test_round_cli_parses_candidates_and_emits_json(monkeypatch, capsys) -> None:

    fake_result = types.SimpleNamespace(
        run_id="sn60-round-x",
        output_root="/tmp/runs/sn60-round-x",
        winner_submission_id="cand-b",
        winner_challenge_summary_path="/tmp/runs/sn60-round-x/d-1/challenge_summary.json",
        promotion_ready=True,
        promotion_reason="cand-b beat the current SN60 king",
        replicas_per_project=1,
        competition_mode="king_duel",
        king_skipped_reason=None,
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
                selected_winner=False,
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

    def fake_run_round(self, **kwargs):
        captured.update(kwargs)
        return fake_result

    monkeypatch.setattr(
        "kata.packages.sn60.plugin.Sn60BitsecPlugin.run_round", fake_run_round
    )

    exit_code = main(
        [
            "round",
            "--king-path",
            "/king",
            "--candidate",
            "cand-b=/c-b",
            "--sn60-project-key",
            "project-alpha",
            "--json",
        ]
    )

    assert exit_code == 0
    assert captured["candidates"] == [("cand-b", "/c-b")]
    assert captured["config"]["project_keys"] == ["project-alpha"]
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


def test_round_cli_supports_candidate_only_mode(monkeypatch, capsys) -> None:

    fake_result = types.SimpleNamespace(
        run_id="sn60-round-recovery",
        output_root="/tmp/runs/sn60-round-recovery",
        winner_submission_id="cand-a",
        winner_challenge_summary_path="/tmp/runs/sn60-round-recovery/challenge_summary.json",
        promotion_ready=True,
        promotion_reason="cand-a won candidate-only recovery mode",
        replicas_per_project=1,
        competition_mode="candidate_only",
        king_skipped_reason="candidate-only recovery enabled",
        king=None,
        entries=[
            types.SimpleNamespace(
                submission_id="cand-a",
                beats_king=None,
                selected_winner=True,
                duel_run_id="candidate-only-cand-a",
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

    def fake_run_round(self, **kwargs):
        captured.update(kwargs)
        return fake_result

    monkeypatch.setattr(
        "kata.packages.sn60.plugin.Sn60BitsecPlugin.run_round", fake_run_round
    )

    exit_code = main(
        [
            "round",
            "--king-path",
            "/king",
            "--candidate",
            "cand-a=/c-a",
            "--sn60-project-key",
            "project-alpha",
            "--candidate-only",
            "--json",
        ]
    )

    assert exit_code == 0
    assert captured["score_king"] is False
    payload = json.loads(capsys.readouterr().out)
    assert payload["competition_mode"] == "candidate_only"
    assert payload["king"] is None
    assert payload["entries"][0]["selected_winner"] is True
    assert payload["entries"][0]["beats_king"] is None
    assert "projects" in payload["entries"][0]


def test_round_cli_samples_problems_when_keys_omitted(tmp_path, monkeypatch, capsys) -> None:

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

    def fake_run_round(self, **kwargs):
        captured.update(kwargs)
        return types.SimpleNamespace(
            run_id="r",
            output_root=str(tmp_path / "runs" / "r"),
            winner_submission_id=None,
            winner_challenge_summary_path=None,
            promotion_ready=False,
            promotion_reason="no candidate beat the current SN60 king",
            replicas_per_project=1,
            competition_mode="king_duel",
            king_skipped_reason=None,
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

    monkeypatch.setattr(
        "kata.packages.sn60.plugin.Sn60BitsecPlugin.run_round", fake_run_round
    )

    exit_code = main(
        [
            "round",
            "--king-path",
            str(king),
            "--candidate",
            "cand=/tmp/cand",
            "--sn60-sandbox-root",
            str(tmp_path / "sandbox"),
            "--sn60-benchmark-file",
            str(benchmark),
            "--sn60-sandbox-commit",
            "test-commit",
            "--json",
        ]
    )

    assert exit_code == 0
    # No explicit --sn60-project-key: the CLI passes None and the plugin samples.
    assert captured["config"]["project_keys"] is None
