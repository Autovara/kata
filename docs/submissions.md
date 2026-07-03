# Submission Workflow

Kata accepts miner agents through PR submissions in the public `kata` repo.

Miners only edit `submissions/`. They do not edit `kings/`, lane state, or
validator configuration.

## Canonical Layout

Each miner PR should add or update exactly one submission directory:

```text
submissions/
  <subnet-pack>/
    <mode>/
      <submission-id>/
        agent.py
        agent_manifest.json
        submission.json
```

Current scope:

- Python agent bundles
- one submission directory per PR
- one subnet-pack lane per submission

## Required Files

### `agent.py`

This is the miner entrypoint.

It must define:

```python
def agent_main(project_dir: str | None = None, inference_api: str | None = None) -> dict:
    ...
```

Hard compatibility floor: the sandbox runner imports `agent.py` and calls
`agent_main()` with no arguments, so no-argument invocation must work. The
return value must be a JSON-serializable object with a top-level
`vulnerabilities` list (the Bitsec report schema).

The validator owns:

- the pinned sandbox and benchmark snapshot
- both inference keys — `INFERENCE_API_KEY` (agent inference) and
  `CHUTES_API_KEY` (scoring) — and the fixed agent model
- timeouts and replica counts
- lane state and the pack registry

**Miners submit only an agent — no API keys.** The validator funds all inference
and pins the model, so every candidate runs on the same model as the king. Miners
compete on agent behavior, not on budget or private provider access.

### `agent_manifest.json`

This describes the bundle contract.

Current requirements:

- `schema_version = 1`
- `runtime = "python"`
- `entrypoint = "agent.py"`

### `submission.json`

This identifies the target competition lane.

Example:

```json
{
  "schema_version": 2,
  "subnet_pack": "sn60__bitsec",
  "mode": "miner",
  "submission_id": "carlos4s-20260629-01",
  "created_at": "2026-06-29T00:00:00+00:00",
  "author": "carlos4s",
  "title": "short optional title",
  "notes": "short optional notes"
}
```

`subnet_pack` is the canonical field. Older `repo_pack` metadata is still
accepted as a legacy alias so existing submissions and lane files do not break.

Recommended identity convention:

- `author`: GitHub username
- `submission_id`: `<github-username>-YYYYMMDD-NN`

## Validation Rules

A competition PR is valid only if:

- it targets the default competition branch
- it edits one submission directory
- it changes at least one agent bundle file
- it does not edit files outside that submission directory
- `agent.py` exists and is not the scaffold placeholder
- `agent.py` defines a synchronous `agent_main(...)` that supports
  no-argument invocation and returns a Bitsec-compatible report with a
  top-level `vulnerabilities` list
- `agent_manifest.json` exists and matches the validator contract
- it targets a pack that is registered and active in the central pack registry

Current anti-cheat rules also reject:

- challenger bundles that duplicate the current lane king
- helper files (SN60 miner submissions must stay self-contained in `agent.py`)
- invalid Python syntax in `agent.py`
- symlinks inside the submission bundle
- bundles above the current file-count or size limits
- direct references to validator/provider secret env vars
- obvious hardcoded secret-like tokens
- benchmark-answer leakage tokens and model sampling overrides

Before checking out untrusted PR content, the bot can inspect only the changed
paths:

```bash
uv run kata submission inspect-pr \
  --repo-root "$PWD" \
  --changed-path-file /path/to/changed-paths.txt
```

Validate a checked-out submission bundle:

```bash
uv run kata submission validate \
  --path submissions/<subnet-pack>/<mode>/<submission-id>
```

## Evaluation Flow

After validation, Kata evaluates the candidate against the current king.

```bash
uv run kata submission evaluate \
  --path submissions/<subnet-pack>/<mode>/<submission-id> --json
```

For the current live design:

- the candidate is screened first: static checks plus one sandbox execution
- candidate and king each run repeated replicas per benchmark codebase in the
  pinned Bitsec sandbox
- if no explicit SN60 project keys are provided, Kata evaluates every
  `project_id` in the resolved benchmark snapshot
- a codebase passes only if at least 2 of 3 runs pass
- the aggregated score is passed codebases divided by total codebases

Promotion gate (in order):

1. aggregated score
2. codebases passed
3. true positives

Candidates with invalid replica runs never promote.

## Stale King Protection

Results are only safe to merge if the lane has not changed since evaluation.

Kata checks that with:

```bash
uv run kata submission verify \
  --path submissions/<subnet-pack>/<mode>/<submission-id> \
  --challenge-run runs/<challenge-run>/challenge_summary.json
```

Verification checks that:

- the submission hash still matches the evaluated candidate
- the king artifact hash is still current
- the evaluator version is still current
- the validator model is still current
- the benchmark lane fingerprint is still current
- the challenge itself is promotion-ready

If any of those drift, the result is stale and should be rerun.

## PR Decision Actions

After verification, Kata reduces the result to one PR action:

```bash
uv run kata submission decide \
  --path submissions/<subnet-pack>/<mode>/<submission-id> \
  --challenge-run runs/<challenge-run>/challenge_summary.json
```

Possible actions are:

- `close-invalid`
- `close-losing`
- `rerun-stale`
- `merge`

## Promotion

If the decision is `merge`, the bot or maintainer can promote the verified
submission:

```bash
uv run kata king promote \
  --challenge-run <challenge-summary.json> \
  --submission-path <submission-dir>
```

The production bot does more than promotion:

1. merge the winning PR
2. update the king under `kings/<subnet-pack>/<mode>/`
3. update the lane king state
4. clear the merged `submissions/.../<submission-id>/` directory from `main`

So `submissions/` stays empty between active miner PRs, while `kings/` remains
the public source of truth for the current winner.
