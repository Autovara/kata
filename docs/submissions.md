# Submission Guide

This document is the contributor-facing contract for miner submissions. It lists
what a valid Kata submission must contain, what is rejected, and what to check
before opening a pull request.

For the full PR-to-promotion process, see [workflow.md](workflow.md).

## Current Scope

The live lane is:

```text
sn60__bitsec / miner
```

Current submission scope:

- Python-only miner agents
- one submission directory per PR
- one subnet-pack and mode per submission
- self-contained SN60 agents in `agent.py`
- no API keys, benchmark answers, helper files, or validator configuration

## Directory Layout

A valid PR adds exactly one submission directory:

```text
submissions/
  <subnet-pack>/
    <mode>/
      <submission-id>/
        agent.py
        agent_manifest.json
        submission.json
```

For SN60 today:

```text
submissions/sn60__bitsec/miner/<submission-id>/
```

Recommended `submission_id` format:

```text
<github-username>-YYYYMMDD-NN
```

Example:

```text
alice-20260704-01
```

## Required Files

### `agent.py`

`agent.py` is the only executable miner code in the bundle.

It must define a synchronous function named `agent_main`:

```python
def agent_main(project_dir: str | None = None, inference_api: str | None = None) -> dict:
    return {
        "vulnerabilities": [
            {
                "title": "Missing access control on privileged update",
                "description": (
                    "A privileged state-changing function appears callable by any "
                    "account, allowing unauthorized changes to protected settings."
                ),
                "severity": "high",
            }
        ]
    }
```

Requirements:

- `agent_main` must be callable with no arguments.
- It must return a JSON-serializable dictionary.
- The returned dictionary must include a top-level `vulnerabilities` list.
- Screening rejects direct no-op returns such as `{"vulnerabilities": []}`.
- The file must contain valid Python syntax.
- The file must not be the scaffold placeholder.
- The implementation must be self-contained for SN60 V1.
- Keep screening fast. The recommended MVP validator rejects the one screening
  sandbox run after `300` seconds.

### `agent_manifest.json`

`agent_manifest.json` declares the bundle runtime contract.

Required values:

```json
{
  "schema_version": 1,
  "runtime": "python",
  "entrypoint": "agent.py"
}
```

### `submission.json`

`submission.json` identifies the target lane and submission metadata.

Example:

```json
{
  "schema_version": 2,
  "subnet_pack": "sn60__bitsec",
  "mode": "miner",
  "submission_id": "alice-20260704-01",
  "created_at": "2026-07-04T00:00:00+00:00",
  "author": "alice",
  "title": "short optional title",
  "notes": "short optional notes"
}
```

Requirements:

- `schema_version` must be `2`.
- `subnet_pack` should be `sn60__bitsec` for the live lane.
- `mode` must be `miner`.
- `submission_id` should match the directory name.
- `author` should be the GitHub username.

`subnet_pack` is the canonical field. The older `repo_pack` field is accepted
only as a legacy alias.

## Inference Contract

The validator pays for inference and pins the model. Miners submit agent logic,
not API keys or provider configuration.

Your agent runs in an isolated sandbox with no public internet access. It can
only reach the validator-provided inference proxy.

Use this contract:

- Endpoint: `POST <inference_api>/inference`
- `inference_api`: use the `agent_main(..., inference_api=...)` argument, or the
  `INFERENCE_API` environment variable
- Auth header: `x-inference-api-key`
- API key source: `INFERENCE_API_KEY` environment variable
- Request body: OpenAI chat-completions shape, for example
  `{"messages": [...], "max_tokens": 4000}`
- Do not set or depend on `model`; the validator pins it
- Response body: read `choices[0].message.content`

Do not use `Authorization: Bearer`; the proxy expects `x-inference-api-key`.

Minimal standard-library example:

```python
import json
import os
import urllib.request


def ask_model(inference_api, prompt):
    endpoint = (inference_api or os.environ.get("INFERENCE_API") or "").rstrip("/")
    body = json.dumps(
        {
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 4000,
        }
    ).encode()
    request = urllib.request.Request(
        endpoint + "/inference",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "x-inference-api-key": os.environ.get("INFERENCE_API_KEY", ""),
        },
    )
    with urllib.request.urlopen(request, timeout=600) as response:
        data = json.loads(response.read().decode())
    return data["choices"][0]["message"]["content"]
```

If the model call fails and your agent returns an empty `vulnerabilities` list,
screening treats the submission as a no-op and closes the PR before the full
duel. Test locally before opening a PR.

## Screening Checklist

Screening is the first cost-control gate. It is intentionally stricter than the
basic shape validator because it decides whether the expensive king-vs-candidate
duel should run.

Your submission should pass these checks:

- `agent_main` is synchronous and callable with no arguments.
- `agent_main` does real analysis; it must not directly return an empty
  `vulnerabilities` list.
- The one screening sandbox run finishes successfully.
- The screening sandbox run finishes before the validator timeout.
- The screening report is a JSON object with a top-level `vulnerabilities` list.
- The screening report contains at least one candidate vulnerability.
- Each candidate finding is a JSON object with a non-empty `title`.
- Each candidate finding has a useful `description` of at least 40 characters.
- If `severity` is present, use `critical`, `high`, `medium`, or `low`.
- Do not return more than 100 candidate findings from screening.

The screening finding does not guarantee a true positive. It only proves the
agent can run and produce a meaningful Bitsec-style report before the validator
pays for the full duel.

## PR Rules

A valid miner PR must:

- target the default competition branch
- touch exactly one submission directory
- change at least one bundle file
- avoid edits outside that submission directory
- include only allowed bundle files
- keep `submissions/` as the only miner-edited top-level area
- not edit `kings/`, `lanes/`, evaluator code, tests, docs, or deployment files

## Validation Checklist

Before opening a PR, verify:

- `agent.py` exists.
- `agent.py` defines synchronous `agent_main`.
- `agent_main` works with no arguments.
- `agent_main` returns at least one useful candidate vulnerability during
  screening.
- `agent_manifest.json` uses schema version `1`, runtime `python`, entrypoint
  `agent.py`.
- `submission.json` uses schema version `2`, `subnet_pack`, mode `miner`, and a
  unique `submission_id`.
- No helper files are included.
- No symlinks are included.
- No hardcoded API keys or provider tokens are included.
- No validator-only environment variables are referenced.
- No benchmark answers, oracle files, or private scorer data are referenced.
- No model sampling overrides are hardcoded.
- The bundle stays under current size and file-count limits.

Run local validation:

```bash
uv run kata submission validate \
  --path submissions/sn60__bitsec/miner/<submission-id>
```

## Rejection Conditions

Kata rejects submissions for:

- invalid PR shape
- more than one submission directory
- off-scope file changes
- missing required files
- invalid metadata
- invalid Python syntax
- async-only `agent_main`
- required positional arguments that prevent no-argument invocation
- missing top-level `vulnerabilities` list
- direct empty-report or no-op `agent_main` implementations
- empty screening reports
- screening findings without a title or useful description
- screening reports with more than 100 findings
- scaffold or duplicate current-king agents
- helper files in SN60 V1 bundles
- symlinks
- oversized bundles
- hardcoded secret-like values
- references to validator/provider secret env vars
- benchmark-answer leakage indicators
- provider endpoint or model override attempts

## Scoring Conditions

Validation only determines whether the candidate may be evaluated. Promotion is
decided later by the workflow in [workflow.md](workflow.md).

High-level promotion requirements:

- screening must pass
- candidate must strictly beat the current king
- the result must still be fresh at merge time

Kata uses SN60-style sampled validation for promotion. The primary score is:

```text
detection_score = total_true_positives / total_expected_vulnerabilities
```

Beginner definitions:

- `true positives`: expected benchmark vulnerabilities your agent correctly
  found.
- `precision`: the share of your reported findings that were real matches,
  `true_positives / total_found`. Noisy extra findings lower precision.
- `F1 score`: a balanced quality score combining detection score and precision.
- `invalid/error evaluation`: the agent run, report, sandbox, or scorer did not
  finish as a successful evaluation. It scores zero for that project and hurts
  tie-breaks.

Promotion comparison order:

1. higher detection score
2. more true positives
3. higher precision
4. higher F1 score
5. fewer invalid/error evaluations

Sandbox `PASS` means the run found every expected vulnerability for that
project. PASS projects are shown for context, but detection score is the main
promotion signal.

## Quick Start

```bash
uv run kata submission init \
  --subnet-pack sn60__bitsec \
  --mode miner \
  --submission-id <github-user>-YYYYMMDD-01

# edit the generated agent.py

uv run kata submission validate \
  --path submissions/sn60__bitsec/miner/<github-user>-YYYYMMDD-01
```

Then commit the one submission directory and open a PR.
