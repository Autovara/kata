from __future__ import annotations

import json
import secrets
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

from kata.agent_bundle import AGENT_ENTRY_FILENAME, load_bundle_files
from kata.benchmarks import resolve_eval_pack_path, resolve_private_eval_pack_path
from kata.config import resolve_validator_model
from kata.eval_pack import discover_live_eval_pack_tasks
from kata.eval_runner import ArtifactVariant, EvalRunSummary, run_artifact_variants
from kata.frontier import (
    DEFAULT_PROMOTION_MARGIN_POINTS,
    PRIMARY_SELECTION_RANDOM_LIVE,
    FrontierManifest,
    FrontierModeConfig,
    load_frontier_manifest,
    resolve_frontier_artifact_hash,
)
from kata.live_progress import update_live_status
from kata.provenance import EVALUATOR_VERSION, pool_fingerprint, short_hash
from kata.public_artifacts import resolve_artifact_path

SUBMISSION_METADATA_FILENAME = "submission.json"


@dataclass(frozen=True)
class ChallengePoolSummary:
    task_ids: list[str]
    eval_run_summary: str
    total_task_weight: float
    variant_successes: dict[str, int]
    variant_invalid_tasks: dict[str, int]
    variant_scores: dict[str, float]
    candidate_beats_frontier: bool
    candidate_score_delta: float


@dataclass(frozen=True)
class ChallengeSummary:
    schema_version: int
    run_id: str
    manifest_path: str
    mode: str
    evaluator_version: str
    validator_model: str
    frontier_artifact: str
    candidate_artifact: str
    frontier_artifact_hash: str
    candidate_artifact_hash: str
    primary_pool_fingerprint: str | None
    holdout_pool_fingerprint: str | None
    promotion_margin_points: float
    holdout_promotion_margin_points: float
    created_at: str
    primary: ChallengePoolSummary
    holdout: ChallengePoolSummary | None
    promotion_ready: bool
    promotion_reason: str


def run_frontier_challenge(
    *,
    eval_pack_path: str,
    mode: str,
    candidate_artifact_path: str,
    agent_command: str,
    output_root: str | None = None,
    agent_timeout_seconds: int | None = None,
    checks_timeout_seconds: int | None = None,
) -> ChallengeSummary:
    eval_pack_root = resolve_eval_pack_path(eval_pack_path)
    manifest = load_frontier_manifest(eval_pack_path)
    mode_config = resolve_mode(manifest, mode)
    candidate_path = Path(candidate_artifact_path).expanduser().resolve()
    if candidate_path.is_file():
        candidate_path = candidate_path.parent
    output_base = Path(output_root) if output_root else Path("runs")
    challenge_run_id = build_challenge_id(eval_pack_root.name, mode)
    challenge_root = output_base / challenge_run_id
    challenge_root.mkdir(parents=True, exist_ok=False)

    frontier_files = load_bundle_files(resolve_artifact_path(mode_config.frontier_artifact))
    candidate_files = load_bundle_files(candidate_path)
    evaluator_version = mode_config.evaluator_version or EVALUATOR_VERSION
    validator_model = resolve_validator_model()
    frontier_hash = resolve_frontier_artifact_hash(mode_config)
    candidate_hash = sha256_bundle_dict(candidate_files)
    promotion_margin_points = mode_config.promotion_margin_points
    selected_primary_tasks = resolve_primary_task_ids(eval_pack_path, mode_config)
    current_primary_fingerprint = current_primary_pool_fingerprint(
        eval_pack_path,
        mode_config,
        selected_task_ids=selected_primary_tasks,
    )
    if mode_config.holdout_task_count > 0 and not mode_config.holdout_tasks:
        raise ValueError(
            "Private holdout tasks are configured for this lane, but they are not available "
            "in the current validator environment. Set KATA_PRIVATE_BENCHMARKS_ROOT."
        )
    current_holdout_fingerprint = current_holdout_pool_fingerprint(
        eval_pack_path,
        mode_config,
    )
    update_live_status(
        {
            "state": "running",
            "phase": "primary",
            "repo_pack": eval_pack_root.name,
            "mode": mode,
            "candidate_submission_id": candidate_path.name,
            "candidate_author": resolve_candidate_author(candidate_path),
            "challenge_run_id": challenge_run_id,
            "evaluator_version": evaluator_version,
            "validator_model": validator_model,
            "frontier_artifact_hash": frontier_hash,
            "candidate_artifact_hash": candidate_hash,
            "primary_pool_fingerprint": current_primary_fingerprint,
            "holdout_pool_fingerprint": current_holdout_fingerprint,
            "pools": {
                "primary": queued_pool_status("primary", selected_primary_tasks),
                "holdout": queued_pool_status("holdout", mode_config.holdout_tasks),
            },
        }
    )

    primary_eval = run_artifact_variants(
        repo_ref=manifest.repo_ref,
        eval_pack_path=eval_pack_path,
        mode=mode,
        agent_command=agent_command,
        artifact_variants=[
            ArtifactVariant(
                name="frontier",
                files=frontier_files,
                entrypoint=AGENT_ENTRY_FILENAME,
            ),
            ArtifactVariant(
                name="candidate",
                files=candidate_files,
                entrypoint=AGENT_ENTRY_FILENAME,
            ),
        ],
        task_names=selected_primary_tasks,
        output_root=str(challenge_root / "primary"),
        run_label=f"{eval_pack_root.name}-{mode}-primary",
        run_kind="challenge-primary",
        metadata={
            "evaluator_version": evaluator_version,
            "pool_name": "primary",
            "pool_fingerprint": current_primary_fingerprint or "",
            "validator_model": validator_model,
            "frontier_artifact_hash": frontier_hash,
            "candidate_artifact_hash": candidate_hash,
        },
        agent_timeout_seconds=agent_timeout_seconds,
        checks_timeout_seconds=checks_timeout_seconds,
    )
    primary_summary = summarize_pool(primary_eval, selected_primary_tasks)

    holdout_summary: ChallengePoolSummary | None = None
    promotion_ready = False
    if primary_summary.candidate_beats_frontier and mode_config.holdout_tasks:
        update_live_status(
            {
                "state": "running",
                "phase": "holdout",
                "holdout_pool_fingerprint": current_holdout_fingerprint,
            }
        )
        holdout_eval_pack_path = (
            str(
                resolve_private_eval_pack_path(
                    mode_config.holdout_eval_pack or eval_pack_root.name
                )
            )
            if mode_config.holdout_is_private
            else (mode_config.holdout_eval_pack or eval_pack_path)
        )
        holdout_eval = run_artifact_variants(
            repo_ref=manifest.repo_ref,
            eval_pack_path=holdout_eval_pack_path,
            mode=mode,
            agent_command=agent_command,
            artifact_variants=[
                ArtifactVariant(
                    name="frontier",
                    files=frontier_files,
                    entrypoint=AGENT_ENTRY_FILENAME,
                ),
                ArtifactVariant(
                    name="candidate",
                    files=candidate_files,
                    entrypoint=AGENT_ENTRY_FILENAME,
                ),
            ],
            task_names=mode_config.holdout_tasks,
            output_root=str(challenge_root / "holdout"),
            run_label=f"{eval_pack_root.name}-{mode}-holdout",
            run_kind="challenge-holdout",
            metadata={
                "evaluator_version": evaluator_version,
                "pool_name": "holdout",
                "pool_fingerprint": current_holdout_fingerprint or "",
                "validator_model": validator_model,
                "frontier_artifact_hash": frontier_hash,
                "candidate_artifact_hash": candidate_hash,
            },
            agent_timeout_seconds=agent_timeout_seconds,
            checks_timeout_seconds=checks_timeout_seconds,
        )
        holdout_summary = summarize_pool(holdout_eval, mode_config.holdout_tasks)
    promotion_ready, reason = evaluate_promotion(
        primary_summary,
        holdout_summary,
        promotion_margin_points=promotion_margin_points,
        holdout_promotion_margin_points=mode_config.holdout_promotion_margin_points,
    )
    summary = ChallengeSummary(
        schema_version=4,
        run_id=challenge_run_id,
        manifest_path=str(eval_pack_root / "frontier.json"),
        mode=mode,
        evaluator_version=evaluator_version,
        validator_model=validator_model,
        frontier_artifact=str(resolve_artifact_path(mode_config.frontier_artifact)),
        candidate_artifact=str(candidate_path),
        frontier_artifact_hash=frontier_hash,
        candidate_artifact_hash=candidate_hash,
        primary_pool_fingerprint=current_primary_fingerprint,
        holdout_pool_fingerprint=current_holdout_fingerprint,
        promotion_margin_points=promotion_margin_points,
        holdout_promotion_margin_points=mode_config.holdout_promotion_margin_points,
        created_at=datetime.now(UTC).isoformat(),
        primary=primary_summary,
        holdout=holdout_summary,
        promotion_ready=promotion_ready,
        promotion_reason=reason,
    )
    write_challenge_summary(challenge_root / "challenge_summary.json", summary)
    update_live_status(
        {
            "state": "verifying",
            "phase": "verifying",
            "challenge_summary_path": str(challenge_root / "challenge_summary.json"),
            "promotion_ready": promotion_ready,
            "promotion_reason": reason,
        }
    )
    return summary


def queued_pool_status(pool_name: str, task_ids: list[str]) -> dict[str, object]:
    return {
        "name": pool_name,
        "state": "queued",
        "total_tasks": len(task_ids),
        "completed_tasks": 0,
        "task_statuses": [
            {
                "task_id": task_id,
                "status": "queued",
                "completed": False,
                "candidate": {"started": False, "finished": False},
                "frontier": {"started": False, "finished": False},
            }
            for task_id in task_ids
        ],
    }


def render_challenge_summary(summary: ChallengeSummary) -> str:
    lines: list[str] = []
    lines.append(f"Challenge run: {summary.run_id}")
    lines.append(f"Mode: {summary.mode}")
    lines.append(f"Manifest: `{summary.manifest_path}`")
    lines.append(f"Candidate artifact: `{summary.candidate_artifact}`")
    lines.append(f"Evaluator version: {summary.evaluator_version}")
    lines.append(f"Validator model: {summary.validator_model}")
    lines.append(f"Frontier artifact hash: {short_hash(summary.frontier_artifact_hash)}")
    lines.append(f"Candidate artifact hash: {short_hash(summary.candidate_artifact_hash)}")
    if summary.primary_pool_fingerprint:
        lines.append(
            f"Primary pool fingerprint: {short_hash(summary.primary_pool_fingerprint)}"
        )
    if summary.holdout_pool_fingerprint:
        lines.append(
            f"Holdout pool fingerprint: {short_hash(summary.holdout_pool_fingerprint)}"
        )
    lines.append("")
    lines.append("Primary pool")
    lines.extend(render_pool(summary.primary))
    if summary.holdout is not None:
        lines.append("")
        lines.append("Holdout pool")
        lines.extend(render_pool(summary.holdout))
    lines.append("")
    lines.append(f"Promotion margin: {summary.promotion_margin_points:.1f} points")
    lines.append(
        f"Holdout margin: {summary.holdout_promotion_margin_points:.1f} points"
    )
    lines.append(f"Promotion ready: {'yes' if summary.promotion_ready else 'no'}")
    lines.append(f"Reason: {summary.promotion_reason}")
    return "\n".join(lines)


def load_challenge_summary(path: str) -> ChallengeSummary:
    payload = json.loads(Path(path).expanduser().resolve().read_text(encoding="utf-8"))
    holdout_payload = payload.get("holdout")
    frontier_artifact = payload.get("frontier_artifact")
    if frontier_artifact is None:
        frontier_artifact = payload["frontier_prompt"]
    candidate_artifact = payload.get("candidate_artifact")
    if candidate_artifact is None:
        candidate_artifact = payload["candidate_prompt"]
    return ChallengeSummary(
        schema_version=payload["schema_version"],
        run_id=payload["run_id"],
        manifest_path=payload["manifest_path"],
        mode=payload["mode"],
        evaluator_version=payload.get("evaluator_version", EVALUATOR_VERSION),
        validator_model=payload.get("validator_model", resolve_validator_model()),
        frontier_artifact=frontier_artifact,
        candidate_artifact=candidate_artifact,
        frontier_artifact_hash=payload.get(
            "frontier_artifact_hash",
            payload.get("frontier_prompt_hash", ""),
        ),
        candidate_artifact_hash=payload.get(
            "candidate_artifact_hash",
            payload.get("candidate_prompt_hash", ""),
        ),
        primary_pool_fingerprint=payload.get("primary_pool_fingerprint"),
        holdout_pool_fingerprint=payload.get("holdout_pool_fingerprint"),
        promotion_margin_points=payload.get(
            "promotion_margin_points", DEFAULT_PROMOTION_MARGIN_POINTS
        ),
        holdout_promotion_margin_points=payload.get(
            "holdout_promotion_margin_points", 0.0
        ),
        created_at=payload["created_at"],
        primary=parse_challenge_pool(payload["primary"]),
        holdout=parse_challenge_pool(holdout_payload) if holdout_payload else None,
        promotion_ready=payload["promotion_ready"],
        promotion_reason=payload["promotion_reason"],
    )


def parse_challenge_pool(payload: dict[str, object]) -> ChallengePoolSummary:
    variant_scores = payload.get("variant_scores") or {}
    candidate_score = float(variant_scores.get("candidate", 0.0)) if variant_scores else 0.0
    frontier_score = float(variant_scores.get("frontier", 0.0)) if variant_scores else 0.0
    return ChallengePoolSummary(
        task_ids=list(payload["task_ids"]),
        eval_run_summary=str(payload["eval_run_summary"]),
        total_task_weight=float(payload.get("total_task_weight", len(payload["task_ids"]))),
        variant_successes=dict(payload.get("variant_successes") or {}),
        variant_invalid_tasks=dict(payload.get("variant_invalid_tasks") or {}),
        variant_scores={name: float(score) for name, score in variant_scores.items()},
        candidate_beats_frontier=bool(
            payload.get("candidate_beats_frontier", candidate_score > frontier_score)
        ),
        candidate_score_delta=float(
            payload.get("candidate_score_delta", round(candidate_score - frontier_score, 2))
        ),
    )


def summarize_pool(summary: EvalRunSummary, task_ids: list[str]) -> ChallengePoolSummary:
    successes = count_variant_successes(summary)
    invalid_tasks = count_variant_invalid_tasks(summary)
    scores = score_variants(summary)
    total_weight = sum(task.task_weight for task in summary.tasks)
    candidate_score = scores.get("candidate", 0.0)
    frontier_score = scores.get("frontier", 0.0)
    return ChallengePoolSummary(
        task_ids=task_ids,
        eval_run_summary=str(resolve_run_summary_path(summary)),
        total_task_weight=total_weight,
        variant_successes=successes,
        variant_invalid_tasks=invalid_tasks,
        variant_scores=scores,
        candidate_beats_frontier=candidate_score > frontier_score,
        candidate_score_delta=round(candidate_score - frontier_score, 2),
    )


def count_variant_successes(summary: EvalRunSummary) -> dict[str, int]:
    successes: dict[str, int] = {}
    for task in summary.tasks:
        for variant in task.variants:
            if variant.success:
                successes[variant.name] = successes.get(variant.name, 0) + 1
            else:
                successes.setdefault(variant.name, 0)
    return successes


def count_variant_invalid_tasks(summary: EvalRunSummary) -> dict[str, int]:
    invalid_tasks: dict[str, int] = {}
    for task in summary.tasks:
        for variant in task.variants:
            if not variant.validity_passed:
                invalid_tasks[variant.name] = invalid_tasks.get(variant.name, 0) + 1
            else:
                invalid_tasks.setdefault(variant.name, 0)
    return invalid_tasks


def score_variants(summary: EvalRunSummary) -> dict[str, float]:
    total_weight = sum(task.task_weight for task in summary.tasks)
    if total_weight <= 0:
        raise ValueError("Challenge pool has zero total task weight.")
    weighted_scores: dict[str, float] = {}
    for task in summary.tasks:
        for variant in task.variants:
            weighted_scores[variant.name] = (
                weighted_scores.get(variant.name, 0.0) + variant.weighted_task_score
            )
    return {
        name: round((weighted_score / total_weight) * 100, 2)
        for name, weighted_score in weighted_scores.items()
    }


def evaluate_promotion(
    primary: ChallengePoolSummary,
    holdout: ChallengePoolSummary | None,
    *,
    promotion_margin_points: float = DEFAULT_PROMOTION_MARGIN_POINTS,
    holdout_promotion_margin_points: float = 0.0,
) -> tuple[bool, str]:
    primary_delta = primary.candidate_score_delta
    if primary.variant_invalid_tasks.get("candidate", 0) > 0:
        return False, "candidate has invalid primary-pool task runs"
    if not primary.candidate_beats_frontier:
        return False, "candidate did not beat the current frontier on the primary score"
    if primary_delta < promotion_margin_points:
        return (
            False,
            "candidate improved the primary score but did not clear the promotion margin",
        )
    if holdout is None:
        return True, "candidate cleared the primary score margin"
    if holdout.variant_invalid_tasks.get("candidate", 0) > 0:
        return False, "candidate has invalid holdout-pool task runs"
    holdout_delta = holdout.candidate_score_delta
    if holdout_delta < holdout_promotion_margin_points:
        if holdout_delta < 0:
            return False, "candidate cleared the primary score margin but regressed on holdout"
        return (
            False,
            "candidate cleared the primary score margin but did not clear the holdout margin",
        )
    return True, "candidate cleared the primary score margin and holdout margin"


def promotion_reason(primary: ChallengePoolSummary, holdout: ChallengePoolSummary | None) -> str:
    return evaluate_promotion(primary, holdout)[1]


def resolve_mode(manifest: FrontierManifest, mode: str) -> FrontierModeConfig:
    mode_config = manifest.modes.get(mode)
    if mode_config is None:
        raise ValueError(
            f"Mode is not configured in frontier manifest: {mode}. "
            "Run `kata frontier init` first."
        )
    return mode_config


def resolve_primary_task_ids(
    eval_pack_path: str,
    mode_config: FrontierModeConfig,
) -> list[str]:
    if mode_config.primary_selection != PRIMARY_SELECTION_RANDOM_LIVE:
        return list(mode_config.primary_tasks)
    validations = discover_live_eval_pack_tasks(eval_pack_path)
    available = sorted(result.root.name for result in validations)
    requested_count = mode_config.primary_task_count or len(available)
    if requested_count <= 0:
        raise ValueError("Random public primary pool requires at least one task.")
    if len(available) < requested_count:
        raise ValueError(
            "Random public primary pool is underfilled. "
            f"Requested {requested_count} live tasks but only {len(available)} are available."
        )
    return sorted(secrets.SystemRandom().sample(available, requested_count))


def current_primary_pool_fingerprint(
    eval_pack_path: str,
    mode_config: FrontierModeConfig,
    *,
    selected_task_ids: list[str] | None = None,
) -> str | None:
    eval_pack_root = resolve_eval_pack_path(eval_pack_path)
    if mode_config.primary_selection == PRIMARY_SELECTION_RANDOM_LIVE:
        if selected_task_ids is not None:
            if not selected_task_ids:
                return None
            return pool_fingerprint(
                [
                    eval_pack_root / validate_selected_task_id(task_id)
                    for task_id in selected_task_ids
                ]
            )
        validations = discover_live_eval_pack_tasks(eval_pack_path)
        return pool_fingerprint([result.root for result in validations]) if validations else None
    if not mode_config.primary_tasks:
        return None
    return pool_fingerprint([eval_pack_root / task_id for task_id in mode_config.primary_tasks])


def validate_selected_task_id(task_id: str) -> str:
    task_path = Path(task_id)
    if task_path.is_absolute() or task_path.name != task_id or task_id in {"", ".", ".."}:
        raise ValueError(f"Invalid challenge task id: {task_id}")
    return task_id


def current_holdout_pool_fingerprint(
    eval_pack_path: str,
    mode_config: FrontierModeConfig,
) -> str | None:
    if not mode_config.holdout_tasks:
        return None
    holdout_pack_ref = mode_config.holdout_eval_pack or resolve_eval_pack_path(
        eval_pack_path
    ).name
    holdout_eval_pack_root = (
        resolve_private_eval_pack_path(holdout_pack_ref)
        if mode_config.holdout_is_private
        else resolve_eval_pack_path(mode_config.holdout_eval_pack or eval_pack_path)
    )
    holdout_task_roots = [
        holdout_eval_pack_root / task_id for task_id in mode_config.holdout_tasks
    ]
    return pool_fingerprint(holdout_task_roots)


def render_pool(pool: ChallengePoolSummary) -> list[str]:
    lines = [
        f"- Tasks: {', '.join(pool.task_ids)}",
        f"- Eval run: `{pool.eval_run_summary}`",
        f"- Total task weight: {pool.total_task_weight:g}",
    ]
    for variant_name in ("frontier", "candidate"):
        lines.append(f"- {variant_name} solved: {pool.variant_successes.get(variant_name, 0)}")
        lines.append(
            f"- {variant_name} invalid tasks: {pool.variant_invalid_tasks.get(variant_name, 0)}"
        )
        lines.append(f"- {variant_name} score: {pool.variant_scores.get(variant_name, 0.0):.2f}")
    lines.append(
        f"- Candidate beats frontier: {'yes' if pool.candidate_beats_frontier else 'no'}"
    )
    lines.append(f"- Candidate score delta: {pool.candidate_score_delta:+.2f}")
    return lines


def resolve_run_summary_path(summary: EvalRunSummary) -> Path:
    if not summary.tasks:
        raise ValueError("Eval summary contains no tasks.")
    first_task_path = Path(summary.tasks[0].task_path).resolve()
    return first_task_path.parents[1] / "run_summary.json"


def build_challenge_id(eval_pack_name: str, mode: str) -> str:
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return f"challenge-{eval_pack_name}-{mode}-{timestamp}"


def write_challenge_summary(path: Path, summary: ChallengeSummary) -> None:
    path.write_text(json.dumps(asdict(summary), indent=2) + "\n", encoding="utf-8")


def infer_submission_author(submission_id: str) -> str | None:
    if submission_id.startswith("kata-init"):
        return "Kata Seed"
    parts = submission_id.rsplit("-", 2)
    if len(parts) == 3 and parts[1].isdigit() and parts[2].isdigit():
        return parts[0]
    return submission_id or None


def resolve_candidate_author(candidate_path: Path) -> str | None:
    metadata_path = candidate_path / SUBMISSION_METADATA_FILENAME
    try:
        payload = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return infer_submission_author(candidate_path.name)
    if not isinstance(payload, dict):
        return infer_submission_author(candidate_path.name)
    author = payload.get("author")
    if isinstance(author, str) and author.strip():
        return author.strip()
    return infer_submission_author(candidate_path.name)


def sha256_bundle_dict(files: dict[str, str]) -> str:
    import hashlib

    hasher = hashlib.sha256()
    for relative_path in sorted(files):
        hasher.update(relative_path.encode("utf-8"))
        hasher.update(b"\0")
        hasher.update(files[relative_path].encode("utf-8"))
        hasher.update(b"\0")
    return hasher.hexdigest()
