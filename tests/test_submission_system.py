from __future__ import annotations

import json
from pathlib import Path

from kata.submission_system import (
    SUBMISSIONS_DIRNAME,
    SubmissionDescriptor,
    SubmissionMetadata,
    load_submission_metadata,
    normalize_changed_paths,
    resolve_submission_descriptor,
    validate_changed_paths,
    validate_submission_metadata,
    write_submission_metadata,
)


def test_submission_metadata_round_trips_subnet_pack_field(tmp_path: Path) -> None:
    metadata_path = tmp_path / "submission.json"
    metadata = SubmissionMetadata(
        schema_version=2,
        repo_pack="sn60__bitsec",
        mode="miner",
        submission_id="alice-20260708-01",
        created_at="2026-07-08T00:00:00+00:00",
        author="alice",
    )

    write_submission_metadata(metadata_path, metadata)
    payload = json.loads(metadata_path.read_text(encoding="utf-8"))

    assert payload["subnet_pack"] == "sn60__bitsec"
    assert "repo_pack" not in payload
    assert load_submission_metadata(metadata_path) == metadata


def test_resolve_submission_descriptor_parses_repo_relative_path(tmp_path: Path) -> None:
    repo_root = tmp_path / "kata"
    submission_root = (
        repo_root / SUBMISSIONS_DIRNAME / "sn60__bitsec" / "miner" / "alice-20260708-01"
    )
    submission_root.mkdir(parents=True)

    descriptor, reasons = resolve_submission_descriptor(
        submission_root,
        repo_root=repo_root,
    )

    assert reasons == []
    assert descriptor is not None
    assert descriptor.repo_pack == "sn60__bitsec"
    assert descriptor.mode == "miner"
    assert descriptor.submission_id == "alice-20260708-01"
    assert descriptor.agent_path == submission_root / "agent.py"


def test_changed_path_validation_requires_single_bundle_scope(tmp_path: Path) -> None:
    descriptor = SubmissionDescriptor(
        root=tmp_path / "submissions/sn60__bitsec/miner/alice-20260708-01",
        repo_pack="sn60__bitsec",
        mode="miner",
        submission_id="alice-20260708-01",
        agent_path=tmp_path / "agent.py",
        agent_manifest_path=tmp_path / "agent_manifest.json",
        metadata_path=tmp_path / "submission.json",
    )

    result = validate_changed_paths(
        descriptor,
        normalize_changed_paths(
            [
                "/submissions/sn60__bitsec/miner/alice-20260708-01/agent.py",
                "kata/cli.py",
            ]
        ),
    )

    assert "kata/cli.py" in result.off_scope_paths
    assert result.reasons == [
        "Submission PR touches paths outside the allowed submission scope."
    ]


def test_validate_submission_metadata_detects_descriptor_mismatch() -> None:
    metadata = SubmissionMetadata(
        schema_version=2,
        repo_pack="sn60__bitsec",
        mode="miner",
        submission_id="alice-20260708-01",
        created_at="2026-07-08T00:00:00+00:00",
    )
    descriptor = SubmissionDescriptor(
        root=Path("submissions/sn60__bitsec/miner/bob-20260708-01"),
        repo_pack="sn60__bitsec",
        mode="miner",
        submission_id="bob-20260708-01",
        agent_path=Path("agent.py"),
        agent_manifest_path=Path("agent_manifest.json"),
        metadata_path=Path("submission.json"),
    )

    assert validate_submission_metadata(metadata, descriptor) == [
        "submission.json submission_id does not match the submission path."
    ]
