"""SN60 single-duel evaluation -- the legacy ``kata submission evaluate`` path.

Moved out of the generic submission workflow so the platform stays subnet-blind. Trusted
round winners are promoted without this duel (they skip it); it remains for the manual
``submission evaluate`` CLI and its tests. Relocates to ``kata-sn60`` in Phase 3.
"""

from __future__ import annotations

from pathlib import Path

from kata.evaluators.sn60_bitsec import DEFAULT_REPLICAS_PER_PROJECT
from kata.promotion_system import resolve_sn60_king_artifact
from kata.screening_system.rules import hash_submission_bundle
from kata.submission_system.workflow import is_sn60_miner_metadata, validate_submission
from kata.validator_system import (
    ChallengeSummary,
    resolve_sn60_project_keys,
    run_sn60_challenge,
)


def evaluate_submission(
    submission_path: str,
    *,
    output_root: str | None = None,
    sn60_project_keys: list[str] | None = None,
    sn60_replicas_per_project: int | None = None,
    sn60_sandbox_root: str | None = None,
    sn60_benchmark_file: str | None = None,
    sn60_sandbox_commit: str | None = None,
) -> ChallengeSummary:
    validation = validate_submission(submission_path)
    if not validation.is_valid or validation.metadata is None or validation.agent_path is None:
        raise ValueError(
            "Submission is invalid. Run `kata submission validate` first. "
            + "; ".join(validation.reasons or ["unknown validation failure"])
        )
    if not is_sn60_miner_metadata(validation.metadata):
        raise ValueError(
            "Submission does not target a registered SN60 evaluator lane. "
            "Register the lane in the pack registry before evaluating."
        )
    lane_id, king_artifact_path = resolve_sn60_king_artifact(validation.metadata)
    project_keys = resolve_sn60_project_keys(
        configured_keys=sn60_project_keys,
        sandbox_root=sn60_sandbox_root,
        benchmark_file=sn60_benchmark_file,
        sandbox_commit=sn60_sandbox_commit,
        king_artifact_hash=hash_submission_bundle(Path(king_artifact_path)),
        candidate_artifact_hash=hash_submission_bundle(Path(validation.submission_path)),
        candidate_submission_id=validation.metadata.submission_id,
    )
    if not project_keys:
        raise ValueError(
            "SN60 miner evaluation requires at least one project key in the "
            "resolved benchmark snapshot."
        )
    return run_sn60_challenge(
        king_artifact_path=king_artifact_path,
        candidate_artifact_path=validation.submission_path,
        project_keys=project_keys,
        candidate_submission_id=validation.metadata.submission_id,
        lane_id=lane_id,
        output_root=output_root,
        replicas_per_project=sn60_replicas_per_project or DEFAULT_REPLICAS_PER_PROJECT,
        sandbox_root=sn60_sandbox_root,
        benchmark_file=sn60_benchmark_file,
        sandbox_commit=sn60_sandbox_commit,
    )
