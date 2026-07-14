"""Phase 0 characterization tests for the multi-subnet plugin refactor.

These lock the *full* observable output of the SN60 round flows that later phases
rewrite (Phase 3 replaces `run_sn60_round` / `run_sn60_candidate_only_round` with a
generic, plugin-driven orchestrator). The golden files are the durable contract that
kata-bot and the dashboard consume (`round_summary.json`), so any unintended drift
during the refactor fails here loudly.

Volatile fields (run ids, timestamps, absolute temp paths) are normalized to stable
placeholders; deterministic content (bundle/benchmark hashes, scores, per-problem
breakdowns) is kept.

Regenerate goldens after an *intended* change with:  UPDATE_GOLDEN=1 uv run pytest \
    tests/test_characterization_sn60.py
Then review the diff before committing.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from kata.packages.sn60.validator_system import run_sn60_round
from kata.packages.sn60.validator_system.challenge import run_sn60_candidate_only_round

GOLDEN_DIR = Path(__file__).parent / "characterization"

# Per-candidate duels each mint their own id (sn60-duel-<timestamp>-<hex>), embedded
# in duel_run_id and the report/evaluation paths. Normalize them to a placeholder.
_DUEL_ID_RE = re.compile(r"sn60-duel-\d{8}T\d{6}Z-[0-9a-f]+")

_VOLATILE_TIMESTAMP_KEYS = {
    "created_at",
    "timestamp",
    "updated_at",
    "promotion_timestamp",
    "finished_at",
    "started_at",
}


def _scrub_timestamps(value: object) -> object:
    if isinstance(value, dict):
        return {
            key: ("<TS>" if key in _VOLATILE_TIMESTAMP_KEYS else _scrub_timestamps(val))
            for key, val in value.items()
        }
    if isinstance(value, list):
        return [_scrub_timestamps(item) for item in value]
    return value


def _normalize(summary: dict, *, tmp_path: Path, run_id: str) -> dict:
    """Replace run ids, timestamps and temp paths with stable placeholders."""
    text = json.dumps(summary, sort_keys=True)
    text = text.replace(str(tmp_path), "<TMP>")
    text = text.replace(run_id, "<RUN_ID>")
    text = _DUEL_ID_RE.sub("<DUEL_ID>", text)
    return _scrub_timestamps(json.loads(text))


def _assert_golden(name: str, actual: dict) -> None:
    path = GOLDEN_DIR / f"{name}.json"
    serialized = json.dumps(actual, indent=2, sort_keys=True) + "\n"
    if os.environ.get("UPDATE_GOLDEN"):
        GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
        path.write_text(serialized, encoding="utf-8")
        return
    assert path.exists(), (
        f"Missing golden {path}. Generate it with UPDATE_GOLDEN=1 and review the diff."
    )
    expected = json.loads(path.read_text(encoding="utf-8"))
    assert actual == expected, (
        f"Characterization drift in {name}. If this change is intended, regenerate with "
        "UPDATE_GOLDEN=1 and review the diff; otherwise the refactor changed behavior."
    )


def _write_detection_bundle(root: Path, detection: float) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "agent.py").write_text(
        f"# detection={detection}\n"
        "def agent_main(project_dir=None, inference_api=None):\n"
        "    return {'vulnerabilities': []}\n",
        encoding="utf-8",
    )


def _write_benchmark(root: Path) -> Path:
    benchmark_path = root / "validator" / "curated-highs-only-2025-08-08.json"
    benchmark_path.parent.mkdir(parents=True, exist_ok=True)
    benchmark_path.write_text(
        json.dumps([{"project_id": "project-alpha", "vulnerabilities": [{"title": "expected"}]}])
        + "\n",
        encoding="utf-8",
    )
    return benchmark_path


def _detection_hooks():
    def execute(context) -> dict[str, object]:
        source = (Path(context.bundle_root) / "agent.py").read_text(encoding="utf-8")
        detection = 0.0
        for line in source.splitlines():
            if "# detection=" in line:
                detection = float(line.split("# detection=")[1].strip())
        return {
            "success": True,
            "report": {
                "project": context.project_key,
                "vulnerabilities": [{"title": "v"}],
                "detection": detection,
            },
        }

    def evaluate(_context, report_payload: dict[str, object]) -> dict[str, object]:
        detection = report_payload["report"]["detection"]
        return {
            "status": "success",
            "result": {
                "result": "PASS" if detection >= 1.0 else "FAIL",
                "detection_rate": detection,
                "true_positives": int(round(detection * 4)),
                "total_expected": 4,
                "total_found": 4,
                "precision": 1.0,
                "f1_score": detection,
            },
        }

    return execute, evaluate


def _build_round_inputs(tmp_path: Path):
    sandbox_root = tmp_path / "sandbox"
    benchmark_path = _write_benchmark(sandbox_root)
    king_root = tmp_path / "king"
    _write_detection_bundle(king_root, 0.25)
    candidates = []
    for name, detection in (("cand-a", 0.0), ("cand-b", 0.5), ("cand-c", 0.75)):
        path = tmp_path / name
        _write_detection_bundle(path, detection)
        candidates.append((name, str(path)))
    return sandbox_root, benchmark_path, king_root, candidates


def test_char_sn60_round_summary_golden(tmp_path: Path) -> None:
    sandbox_root, benchmark_path, king_root, candidates = _build_round_inputs(tmp_path)
    execute, evaluate = _detection_hooks()

    result = run_sn60_round(
        king_artifact_path=str(king_root),
        candidates=candidates,
        project_keys=["project-alpha"],
        output_root=str(tmp_path / "runs"),
        replicas_per_project=1,
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit="commit-golden",
        king_scoreboard_path=str(tmp_path / "king_scoreboard.json"),
        execution_hook=execute,
        evaluation_hook=evaluate,
    )
    summary = json.loads(
        (Path(result.output_root) / "round_summary.json").read_text(encoding="utf-8")
    )
    _assert_golden(
        "sn60_round_summary", _normalize(summary, tmp_path=tmp_path, run_id=result.run_id)
    )


def test_char_sn60_candidate_only_round_summary_golden(tmp_path: Path) -> None:
    sandbox_root, benchmark_path, king_root, candidates = _build_round_inputs(tmp_path)
    execute, evaluate = _detection_hooks()

    result = run_sn60_candidate_only_round(
        king_artifact_path=str(king_root),
        candidates=candidates,
        project_keys=["project-alpha"],
        output_root=str(tmp_path / "runs"),
        replicas_per_project=1,
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark_path),
        sandbox_commit="commit-golden",
        execution_hook=execute,
        evaluation_hook=evaluate,
    )
    summary = json.loads(
        (Path(result.output_root) / "round_summary.json").read_text(encoding="utf-8")
    )
    _assert_golden(
        "sn60_candidate_only_round_summary",
        _normalize(summary, tmp_path=tmp_path, run_id=result.run_id),
    )
