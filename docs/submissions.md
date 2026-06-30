# Submission Workflow

Kata now accepts challenger agents through PR submissions.

The benchmark lane is still repo-specific, but the miner artifact is no longer
just prompt text. The required entrypoint is `agent.py`.

## Canonical Layout

Each miner PR should add exactly one submission directory:

```text
submissions/
  <repo-pack>/
    <mode>/
      <submission-id>/
        agent.py
        submission.json
```

Current scope:

- single-file `agent.py` submissions
- one submission directory per PR
- one repo-pack lane per submission

## Required Files

### `agent.py`

This is the challenger agent entrypoint.

It must define:

```python
def solve(repo_path: str, issue: str, model: str, api_base: str, api_key: str) -> dict:
    ...
```

The validator owns:

- `model`
- `api_base`
- `api_key`
- timeouts
- benchmark tasks

So miners compete on agent behavior, not on model routing or secret management.

### `submission.json`

This identifies the competition lane and submission metadata.

Current schema:

```json
{
  "schema_version": 2,
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

## Validation Rules

A competition PR is valid only if:

- it edits one submission directory
- it changes `agent.py`
- it does not edit files outside that submission directory
- `agent.py` exists and is not the scaffold placeholder
- `agent.py` defines `solve(...)`
- it targets a repo-pack that is active in the benchmark registry
- it targets an existing benchmark repo pack
- the target pack already has a frontier manifest
- the target mode is configured in that frontier manifest

These rules are enforced with:

```bash
uv run kata submission validate --path <submission-dir>
```

Before checking out the PR branch, CI can inspect the diff only:

```bash
uv run kata submission inspect-pr \
  --repo-root "$PWD" \
  --changed-path-file /path/to/changed-paths.txt
```

## Evaluation Flow

After validation, Kata can evaluate the challenger against the current
benchmark lane:

```bash
uv run kata submission evaluate \
  --path <submission-dir> \
  --agent-command "$PWD/scripts/run_python_agent_eval.sh"
```

The current evaluator supports a transition mode:

- challenger submissions can be `agent.py`
- existing baseline/frontier lane artifacts may still be prompt-backed
- the runner is artifact-aware and can execute either path

That keeps the migration working while the frontier seeding flow is being
converted fully to agent artifacts.

## Stale Frontier Protection

Submission results are only safe to merge if the frontier has not changed since
the evaluation completed.

Kata checks that with:

```bash
uv run kata submission verify \
  --path <submission-dir> \
  --challenge-run <challenge-summary.json>
```

The verification currently checks:

- challenger artifact hash still matches the submission
- frontier hash is still current
- evaluator version is still current
- primary and holdout pool fingerprints are still current
- the challenge itself was promotion-ready

If any of those drift, the submission result is stale and should be rerun.

## PR Decision Actions

After verification, Kata can collapse the result into a PR action:

```bash
uv run kata submission decide \
  --path <submission-dir> \
  --challenge-run <challenge-summary.json>
```

Current decision actions are:

- `close-invalid`
- `close-losing`
- `rerun-stale`
- `merge`

These actions are intended to drive a separate GitHub bot cleanly.
