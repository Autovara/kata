from __future__ import annotations

import json
from pathlib import Path

import pytest

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


def test_stage_submission_bundle_preserves_previous_bundle_on_copy_failure(
    tmp_path: Path, monkeypatch
) -> None:
    # BUG-3 regression: a crash/IO error mid-copy must never leave an empty or
    # half-copied king. The old bundle is only swapped out by a single atomic rename
    # after the new bundle is fully staged, so a failure leaves the old king intact.
    from kata.submissions import bundle as bundle_mod

    source = tmp_path / "source"
    source.mkdir()
    (source / "agent.py").write_bytes(b"NEW\n")
    (source / "agent_manifest.json").write_bytes(b'{"schema_version":1}\n')
    (source / "submission.json").write_bytes(b'{"new":true}')
    (source / "sealed_inference_key").write_bytes(b"new-sealed")

    destination = tmp_path / "king"
    destination.mkdir()
    (destination / "agent.py").write_bytes(b"OLD\n")
    (destination / "submission.json").write_bytes(b'{"old":true}')

    real_copyfile = bundle_mod.shutil.copyfile
    calls = {"n": 0}

    def flaky_copyfile(src, dst, *args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 2:
            raise OSError("disk full mid-copy")
        return real_copyfile(src, dst, *args, **kwargs)

    monkeypatch.setattr(bundle_mod.shutil, "copyfile", flaky_copyfile)

    with pytest.raises(OSError, match="disk full"):
        bundle_mod.stage_submission_bundle(source, destination)

    # Previous king untouched; the swap never happened.
    assert (destination / "agent.py").read_bytes() == b"OLD\n"
    assert (destination / "submission.json").read_bytes() == b'{"old":true}'
    # No staging/backup directories left behind.
    assert [p.name for p in tmp_path.iterdir() if p.name.startswith(".")] == []


def test_write_json_is_atomic_and_leaves_no_temp(tmp_path: Path) -> None:
    from kata.util import write_json

    path = tmp_path / "state.json"
    write_json(path, {"a": 1})
    assert json.loads(path.read_text()) == {"a": 1}
    write_json(path, {"a": 2})  # atomic overwrite
    assert json.loads(path.read_text()) == {"a": 2}
    # Only the target file exists -- the temp file was renamed into place, not left.
    assert [p.name for p in tmp_path.iterdir()] == ["state.json"]


def test_promote_lane_king_rolls_back_king_and_state_on_write_failure(
    tmp_path: Path, monkeypatch
) -> None:
    # BUG-3 regression: if the lane state write fails after the king bundle is
    # published, the previous king bundle AND lane state are both restored, so the
    # lane never ends up with kings/ and state pointing at different kings (frozen).
    from types import SimpleNamespace

    import kata.plugins.discovery as discovery
    from kata.promotion import king as king_mod

    public_root = tmp_path / "pub"
    repo_pack, mode = "sn60__bitsec", "miner"
    king_root = public_root / "kings" / repo_pack / mode
    king_root.mkdir(parents=True)
    (king_root / "agent.py").write_bytes(b"OLD KING\n")
    (king_root / "agent_manifest.json").write_bytes(b'{"schema_version":1}')
    (king_root / "submission.json").write_bytes(b'{"old":true}')
    (king_root / "sealed_inference_key").write_bytes(b"old-sealed")

    state_path = king_mod.lane_king_state_path("lane-x", public_root=str(public_root))
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_bytes(b'{"current_king_submission_id":"old"}')

    candidate = tmp_path / "candidate"
    candidate.mkdir()
    (candidate / "agent.py").write_bytes(b"NEW KING\n")
    (candidate / "agent_manifest.json").write_bytes(b'{"schema_version":1}')
    (candidate / "submission.json").write_bytes(b'{"new":true}')
    (candidate / "sealed_inference_key").write_bytes(b"new-sealed")

    entry = SimpleNamespace(evaluator_id="no-plugin-evaluator", lane_id="lane-x")
    verification = SimpleNamespace(
        repo_pack=repo_pack,
        mode=mode,
        submission_id="new-id",
        submission_path=str(candidate),
        candidate_artifact_hash="hash-new",
    )
    summary = SimpleNamespace(run_id="run-1")

    monkeypatch.setattr(discovery, "plugin_for_evaluator", lambda _evaluator_id: None)

    def boom(*_args, **_kwargs):
        raise RuntimeError("disk full writing lane state")

    monkeypatch.setattr(king_mod, "write_lane_king_state", boom)

    with pytest.raises(RuntimeError, match="disk full"):
        king_mod.promote_lane_king(
            entry=entry,
            verification=verification,
            summary=summary,
            public_root=str(public_root),
        )

    # Rolled back to the previous, consistent king + state.
    assert (king_root / "agent.py").read_bytes() == b"OLD KING\n"
    assert (king_root / "submission.json").read_bytes() == b'{"old":true}'
    assert state_path.read_bytes() == b'{"current_king_submission_id":"old"}'
    # No rollback/staging leftovers under kings/<pack>/.
    assert [p.name for p in king_root.parent.iterdir() if p.name.startswith(".")] == []


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
