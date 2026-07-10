from __future__ import annotations

import hashlib
import os

from kata.evaluators.sn60_bitsec import (
    load_sn60_benchmark_project_keys,
    resolve_sn60_sandbox_source,
)

SN60_PROJECT_SAMPLE_SIZE_ENV = "KATA_SN60_PROJECT_SAMPLE_SIZE"
SN60_PROJECT_SAMPLE_SECRET_ENV = "KATA_SN60_PROJECT_SAMPLE_SECRET"


def parse_sn60_project_keys_from_env() -> list[str]:
    configured = os.environ.get("KATA_SN60_PROJECT_KEYS", "")
    return [part.strip() for part in configured.split(",") if part.strip()]


def parse_sn60_project_sample_size_from_env() -> int | None:
    value = os.environ.get(SN60_PROJECT_SAMPLE_SIZE_ENV, "")
    if not value.strip():
        return None
    try:
        sample_size = int(value.strip())
    except ValueError as exc:
        raise ValueError(f"{SN60_PROJECT_SAMPLE_SIZE_ENV} must be a positive integer.") from exc
    if sample_size <= 0:
        raise ValueError(f"{SN60_PROJECT_SAMPLE_SIZE_ENV} must be greater than 0.")
    return sample_size


def resolve_sn60_project_keys(
    *,
    configured_keys: list[str] | None,
    sandbox_root: str | None,
    benchmark_file: str | None,
    sandbox_commit: str | None,
    king_artifact_hash: str | None = None,
    candidate_artifact_hash: str | None = None,
    candidate_submission_id: str | None = None,
) -> list[str]:
    explicit_keys = configured_keys or parse_sn60_project_keys_from_env()
    if explicit_keys:
        return explicit_keys
    sandbox_source = resolve_sn60_sandbox_source(
        sandbox_root=sandbox_root,
        benchmark_file=benchmark_file,
        sandbox_commit=sandbox_commit,
        scorer_version="ScaBenchScorerV2",
    )
    benchmark_keys = load_sn60_benchmark_project_keys(sandbox_source)
    sample_size = parse_sn60_project_sample_size_from_env()
    if sample_size is None or sample_size >= len(benchmark_keys):
        return benchmark_keys
    sample_secret = os.environ.get(SN60_PROJECT_SAMPLE_SECRET_ENV, "")
    if not sample_secret.strip():
        raise ValueError(
            f"{SN60_PROJECT_SAMPLE_SECRET_ENV} must be set when "
            f"{SN60_PROJECT_SAMPLE_SIZE_ENV} narrows the SN60 benchmark."
        )
    return sample_sn60_project_keys(
        benchmark_keys,
        sample_size=sample_size,
        sample_secret=sample_secret.strip(),
        sample_nonce="",
        king_artifact_hash=king_artifact_hash or "",
        candidate_artifact_hash=candidate_artifact_hash or "",
        candidate_submission_id=candidate_submission_id or "",
    )


def sample_sn60_project_keys(
    project_keys: list[str],
    *,
    sample_size: int,
    sample_secret: str,
    sample_nonce: str,
    king_artifact_hash: str,
    candidate_artifact_hash: str,
    candidate_submission_id: str,
) -> list[str]:
    if sample_size <= 0:
        raise ValueError("SN60 project sample size must be greater than 0.")
    ordered_keys = list(dict.fromkeys(project_keys))
    if sample_size >= len(ordered_keys):
        return ordered_keys
    seed = "\x1f".join(
        [
            sample_secret,
            sample_nonce,
            king_artifact_hash,
            candidate_artifact_hash,
            candidate_submission_id,
        ]
    )
    ordered = sorted(
        ordered_keys,
        key=lambda key: hashlib.sha256(f"{seed}\x1f{key}".encode()).hexdigest(),
    )
    return ordered[:sample_size]
