# Submission Workflow

PromptForge uses miner PR submissions as challenger prompts.

## Canonical Layout

Each miner PR should add exactly one submission directory:

```text
submissions/
  <repo-pack>/
    <mode>/
      <submission-id>/
        candidate.md
        submission.json
```

## Required Files

### `candidate.md`

This is the challenger prompt text that will compete against the current
frontier prompt for the same repo pack and mode.

### `submission.json`

This identifies the competition lane and submission metadata. Current schema:

```json
{
  "schema_version": 1,
  "repo_pack": "example__repo",
  "mode": "contributor",
  "submission_id": "carlos4s-20260629-01",
  "created_at": "2026-06-29T00:00:00+00:00",
  "author": "carlos4s",
  "title": "short optional title",
  "notes": "short optional notes"
}
```

Recommended identity convention:

- `author`: GitHub username
- `submission_id`: `<github-username>-YYYYMMDD-NN`

Example:

- `author`: `carlos4s`
- `submission_id`: `carlos4s-20260629-01`

Why this is the preferred convention:

- leaderboard rows can use `author`
- frontend can resolve avatar/profile directly from `author`
- each submission still has a unique stable id for history and retries

## Validation Rules

A competition PR is valid only if:

- it edits one submission directory
- it changes `candidate.md`
- it does not edit files outside that submission directory
- it targets an existing benchmark repo pack
- the target pack already has a frontier manifest
- the target mode is configured in that frontier manifest

These rules are enforced locally or in CI with:

```bash
uv run python -m promptforge submission validate --path <submission-dir>
```

Before checking out the PR branch, CI can inspect the diff only:

```bash
uv run python -m promptforge submission inspect-pr \
  --repo-root "$PWD" \
  --changed-path-file /path/to/changed-paths.txt
```

That command decides whether an external bot should:

- be auto-closed immediately
- proceed to challenger evaluation

## Evaluation Flow

After validation, PromptForge can evaluate the challenger against the current
frontier:

```bash
uv run python -m promptforge submission evaluate \
  --path <submission-dir> \
  --agent-command "$PWD/scripts/run_codex_eval.sh"
```

This runs:

- `baseline`
- `frontier`
- `candidate`

against the benchmark lane referenced by the submission.

## Stale Frontier Protection

Submission results are only safe to merge if the frontier has not changed since
the evaluation completed.

PromptForge checks that with:

```bash
uv run python -m promptforge submission verify \
  --path <submission-dir> \
  --challenge-run <challenge-summary.json>
```

The verification currently checks:

- candidate prompt hash still matches the submission
- frontier prompt hash is still current
- evaluator version is still current
- primary and holdout pool fingerprints are still current
- the challenge itself was promotion-ready

If any of those drift, the submission result is stale and should be rerun.

## PR Decision Actions

After verification, PromptForge can collapse the result into a PR action:

```bash
uv run python -m promptforge submission decide \
  --path <submission-dir> \
  --challenge-run <challenge-summary.json>
```

Current decision actions are:

- `close-invalid`
- `close-losing`
- `rerun-stale`
- `merge`

These actions are intended to drive a separate GitHub bot cleanly.
