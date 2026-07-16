from __future__ import annotations

import json
from pathlib import Path

from kata.submissions.constants import SUBMISSIONS_DIRNAME
from kata.submissions.layout import (
    load_submission_metadata,
    normalize_changed_paths,
    resolve_submission_descriptor,
    write_submission_metadata,
)
from kata.submissions.models import (
    SubmissionDescriptor,
    SubmissionMetadata,
)
from kata.submissions.validation import (
    validate_changed_paths,
    validate_submission_metadata,
)


def test_stage_submission_bundle_preserves_metadata_and_source_bytes(tmp_path: Path) -> None:
    from kata.submissions.bundle import stage_submission_bundle

    source = tmp_path / "source"
    source.mkdir()
    agent = b"def agent_main(): pass  \n\n"
    metadata = b'{"submission_id":"alice-20260708-01"}'
    sealed_key = b"public-ciphertext"
    helper = b"def inspect(): return 1\n"
    (source / "agent.py").write_bytes(agent)
    (source / "agent_manifest.json").write_bytes(b'{"schema_version":1}\n')
    (source / "submission.json").write_bytes(metadata)
    (source / "sealed_inference_key").write_bytes(sealed_key)
    helpers = source / "helpers"
    helpers.mkdir()
    (helpers / "scan.py").write_bytes(helper)
    cache = source / "__pycache__"
    cache.mkdir()
    (cache / "agent.pyc").write_bytes(b"ignored")

    destination = tmp_path / "staged"
    copied = stage_submission_bundle(source, destination)

    assert copied == [
        "agent.py",
        "agent_manifest.json",
        "helpers/scan.py",
        "sealed_inference_key",
        "submission.json",
    ]
    assert (destination / "agent.py").read_bytes() == agent
    assert (destination / "submission.json").read_bytes() == metadata
    assert (destination / "sealed_inference_key").read_bytes() == sealed_key
    assert (destination / "helpers/scan.py").read_bytes() == helper
    assert not (destination / "__pycache__").exists()


def test_mirror_public_king_artifact_publishes_source_bytes_verbatim(tmp_path: Path) -> None:
    from kata.state.artifacts import mirror_public_king_artifact

    source = tmp_path / "candidate"
    source.mkdir()
    # Non-canonical bytes (no trailing newline, the common case). A normalizing
    # write would change these and break the sealed_inference_key binding, which
    # the room re-checks over the king's bytes on every re-scoring round.
    agent = b"def agent_main(project_dir=None, inference_api=None):\n    return {'vulns': []}"
    metadata = b'{"schema_version":2,"subnet_pack":"sn60__bitsec","mode":"miner"}'
    sealed = b"deadbeef" * 8
    (source / "agent.py").write_bytes(agent)
    (source / "agent_manifest.json").write_bytes(
        b'{"schema_version":1,"runtime":"python","entrypoint":"agent.py"}'
    )
    (source / "submission.json").write_bytes(metadata)
    (source / "sealed_inference_key").write_bytes(sealed)

    king_root = mirror_public_king_artifact(
        public_root=str(tmp_path / "pub"),
        repo_pack="sn60__bitsec",
        mode="miner",
        artifact_path=str(source),
    )

    # The promoted king must carry the exact submitted bytes -- including
    # submission.json and the sealed credential -- so the miner's binding holds.
    assert (king_root / "agent.py").read_bytes() == agent
    assert (king_root / "submission.json").read_bytes() == metadata
    assert (king_root / "sealed_inference_key").read_bytes() == sealed


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


def test_resolve_submission_descriptor_rejects_nested_helper_as_submission_root(
    tmp_path: Path,
) -> None:
    repo_root = tmp_path / "kata"
    submission_root = (
        repo_root / SUBMISSIONS_DIRNAME / "sn60__bitsec" / "miner" / "alice-20260708-01"
    )
    helper_root = submission_root / "helpers"
    helper_root.mkdir(parents=True)

    descriptor, reasons = resolve_submission_descriptor(
        helper_root,
        repo_root=repo_root,
    )

    assert descriptor is None
    assert reasons == [
        "Submission path must match `submissions/<subnet-pack>/<mode>/<submission-id>`."
    ]


def test_changed_path_validation_allows_helper_module(tmp_path: Path) -> None:
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
        ["submissions/sn60__bitsec/miner/alice-20260708-01/helpers/audit.py"],
    )

    assert result.off_scope_paths == []
    assert result.reasons == []


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
    assert result.reasons == ["Submission PR touches paths outside the allowed submission scope."]


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
