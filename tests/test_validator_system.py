from __future__ import annotations

import json
from pathlib import Path

from kata.evaluators.sn60_bitsec import Sn60SandboxSource
from kata.packages.sn60.validator_system.project_selection import (
    parse_sn60_project_keys_from_env,
    resolve_sn60_project_keys,
    sample_sn60_project_keys,
)


def write_benchmark(root: Path) -> Path:
    benchmark = root / "validator" / "curated-highs-only-2025-08-08.json"
    benchmark.parent.mkdir(parents=True, exist_ok=True)
    benchmark.write_text(
        json.dumps(
            [
                {"project_id": "proj-a"},
                {"project_id": "proj-b"},
                {"project_id": "proj-c"},
                {"project_id": "proj-d"},
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return benchmark


def test_parse_sn60_project_keys_from_env(monkeypatch) -> None:
    monkeypatch.setenv("KATA_SN60_PROJECT_KEYS", " proj-a,proj-b ,, proj-c ")

    assert parse_sn60_project_keys_from_env() == ["proj-a", "proj-b", "proj-c"]


def test_sample_sn60_project_keys_is_stable_and_dedupes() -> None:
    sample = sample_sn60_project_keys(
        ["proj-c", "proj-a", "proj-c", "proj-b"],
        sample_size=2,
        sample_secret="secret",
        sample_nonce="nonce",
        king_artifact_hash="king",
        candidate_artifact_hash="candidate",
        candidate_submission_id="alice-20260708-01",
    )

    assert sample == sample_sn60_project_keys(
        ["proj-c", "proj-a", "proj-c", "proj-b"],
        sample_size=2,
        sample_secret="secret",
        sample_nonce="nonce",
        king_artifact_hash="king",
        candidate_artifact_hash="candidate",
        candidate_submission_id="alice-20260708-01",
    )
    assert len(sample) == 2
    assert len(set(sample)) == 2


def test_resolve_sn60_project_keys_samples_benchmark(tmp_path: Path, monkeypatch) -> None:
    sandbox_root = tmp_path / "sandbox"
    benchmark = write_benchmark(sandbox_root)
    monkeypatch.setenv("KATA_SN60_PROJECT_SAMPLE_SIZE", "2")
    monkeypatch.setenv("KATA_SN60_PROJECT_SAMPLE_SECRET", "secret")
    monkeypatch.setattr(
        "kata.packages.sn60.validator_system.project_selection.secrets.token_hex",
        lambda _size: "nonce",
    )

    source = Sn60SandboxSource(
        sandbox_root=str(sandbox_root),
        benchmark_file=str(benchmark),
        benchmark_sha256="benchmark",
        sandbox_commit="sandbox",
        scorer_version="ScaBenchScorerV2",
    )
    monkeypatch.setattr(
        "kata.packages.sn60.validator_system.project_selection.resolve_sn60_sandbox_source",
        lambda **_kwargs: source,
    )
    selected = resolve_sn60_project_keys(
        configured_keys=None,
        sandbox_root=None,
        benchmark_file=None,
        sandbox_commit=None,
        king_artifact_hash="king",
        candidate_artifact_hash="candidate",
        candidate_submission_id="alice-20260708-01",
    )

    assert selected == sample_sn60_project_keys(
        ["proj-a", "proj-b", "proj-c", "proj-d"],
        sample_size=2,
        sample_secret="secret",
        sample_nonce="nonce",
        king_artifact_hash="king",
        candidate_artifact_hash="candidate",
        candidate_submission_id="alice-20260708-01",
    )
