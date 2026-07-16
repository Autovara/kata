# Submission Contract

This is the generic Kata submission contract: the bundle every contributor submits,
whatever the target. Each subnet plugin adds its own task, report, execution, and timing
rules on top. For SN60, those live in [`../kata-sn60`](../kata-sn60).

The goal is simple: submit one honest agent that can be scored fairly against the current
king. You only edit `submissions/`. Do not edit engine, benchmark, workflow, or king code.

## Directory layout

A valid PR adds or updates exactly one submission directory:

```text
submissions/
  <subnet-pack>/
    miner/
      <github-username>-YYYYMMDD-NN/
        agent.py
        agent_manifest.json
        submission.json
        helpers/            # optional, Python only
```

Example: `submissions/sn60__bitsec/miner/alice-20260716-01/`.

The `<github-username>` prefix must match the GitHub account that opens the PR. If the PR
author is `alice`, the submission id must start with `alice-`. Identity mismatches are
closed `kata:invalid` before the PR can enter a round.

## The three required files

### `agent.py`

`agent.py` is the executable agent. It must define `agent_main`:

```python
def agent_main(project_dir: str | None = None, inference_api: str | None = None) -> dict:
    return {
        "vulnerabilities": [
            # findings the agent produced from analyzing the code it received
        ]
    }
```

Rules the core checks:

- `agent_main` must be **synchronous**. The runner calls it directly and does not await
  coroutines.
- `agent_main()` must be callable with **no arguments** (all parameters have defaults).
- It must return a dict with a top-level `vulnerabilities` key. The return value must be
  JSON-serializable.
- The Python must parse and compile.

### `agent_manifest.json`

Use exactly this runtime contract:

```json
{
  "schema_version": 1,
  "runtime": "python",
  "entrypoint": "agent.py"
}
```

`runtime` must be `python` and `entrypoint` must be `agent.py`.

### `submission.json`

Schema version 2:

```json
{
  "schema_version": 2,
  "subnet_pack": "sn60__bitsec",
  "mode": "miner",
  "submission_id": "alice-20260716-01",
  "created_at": "2026-07-16T00:00:00+00:00",
  "author": "alice",
  "title": "short optional title",
  "notes": "short optional notes"
}
```

- `schema_version` must be `2`.
- `subnet_pack` must match the path.
- `mode` must be `miner`.
- `submission_id` must match the directory name.
- `author` must match the GitHub account that opened the PR.

## Bundle limits

- At most **16 files** in the bundle.
- At most **128 KiB** per file.
- At most **256 KiB** total.
- No symlinks.
- The only files allowed are `agent.py`, `agent_manifest.json`, `submission.json`, and
  optional Python helpers under `helpers/`. Helper files must be `.py`. Anything else is an
  unsupported file and is rejected.

## Anti-cheat rules the core enforces

These run for every target, before any expensive work. They are source-only and cheap.

- **Identity match.** The submission path, `submission_id`, and `submission.json` fields
  must agree, and the id prefix and `author` must match the PR author.
- **No secrets.** No hardcoded API-key-shaped tokens in the bundle, and no direct reference
  to Kata platform-secret environment variables such as `KATA_VALIDATOR_API_KEY`.
- **No no-op or canned agent.** The unedited scaffold (its placeholder text still present)
  is rejected, and `agent_main` must return a report with `vulnerabilities`. Your agent
  must do real analysis of the code it receives, not return a constant canned report. The
  subnet plugin applies deeper canned-report checks.
- **No king copy.** A bundle that is an exact copy of the current king, or whose `agent.py`
  is AST-equivalent to the king's, is rejected. A near-copy is held for review.
- **No benchmark-answer replay.** As a principle, do not recognize known benchmark projects
  and return prewritten findings. General reusable analysis is allowed; project-specific
  answer replay is not. The concrete replay checks (fingerprints, known finding ids,
  banned tokens) are applied by the subnet plugin.

The shared screen is inference-policy neutral: it does not mandate a model, provider, token
budget, call limit, retry limit, or sampling policy. A subnet plugin may add its own
task-specific checks.

## Inference

Kata's core does not provide or require inference. When a target's agent needs a model,
the subnet's execution contract supplies it. The common shape is:

- The endpoint is passed to `agent_main(..., inference_api=...)`, or read from the
  `INFERENCE_API` environment variable.
- The API key is read from the `INFERENCE_API_KEY` environment variable.
- Do not put a private key in the bundle or its source. Use the target's sealed-secret
  mechanism where one is supplied.

The exact request and response format, authentication, and any per-call or per-agent timing
limits are defined by the subnet, not here. See that subnet's repo, for example
[`../kata-sn60`](../kata-sn60).

## Local commands

Create a submission:

```bash
uv run kata submission init \
  --subnet-pack sn60__bitsec \
  --mode miner \
  --submission-id <github-user>-YYYYMMDD-01 \
  --author <github-user>
```

Validate before opening a PR:

```bash
uv run kata submission validate \
  --path submissions/sn60__bitsec/miner/<github-user>-YYYYMMDD-01
```

Run these from the top-level Kata repository directory, then commit only that submission
directory and open one PR.
