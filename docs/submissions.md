# Submission Guide — SN60 / Bitsec lane

> **Scope:** this guide is the contributor contract for the **SN60 / Bitsec**
> competition lane (`sn60__bitsec`), which is the one lane live today. Kata is a
> subnet-agnostic framework, so future lanes will each publish their own submission
> guide with their own agent contract and scoring. Everything below — the `agent.py`
> shape (`vulnerabilities`), the inference contract, and the screening rules — is
> **specific to SN60**. For the general, subnet-independent flow, see
> [workflow.md](workflow.md); for how Kata is governed and funded, see the README's
> "Built with Gittensor (SN74)" section.

This document lists what a valid SN60 miner submission must contain, what is rejected,
and what to check before opening a pull request. For the full PR-to-promotion process,
see [workflow.md](workflow.md).

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
                "file": "contracts/Admin.sol",
            }
        ]
    }
```

Requirements:

- `agent_main` must be callable with no arguments.
- It must return a JSON-serializable dictionary.
- The returned dictionary must include a top-level `vulnerabilities` list.
- Each finding should describe a plausible high or critical security issue with a
  source location, so the scorer can match it to a real benchmark vulnerability.
- Do **not** directly return a no-op such as `{"vulnerabilities": []}`; a stub
  agent that does no analysis is rejected up front (see the screening gate below).
  A *non-stub* agent that happens to find nothing on a run is fine — it just
  scores 0 there, it is not rejected.
- The file must contain valid Python syntax.
- The file must not be the scaffold placeholder.
- The implementation must be self-contained for SN60 V1.
- Be efficient: your agent has a per-problem runtime budget, so prioritise the
  most suspicious files first. Running out of time on a problem scores 0 for that
  problem — it does not close your PR.

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
    with urllib.request.urlopen(request, timeout=120) as response:
        data = json.loads(response.read().decode())
    return data["choices"][0]["message"]["content"]
```

If a model call fails and your agent returns an empty `vulnerabilities` list, your
PR is **not** closed — that problem simply scores 0 and the duel continues to the
rest. But an agent that finds nothing cannot out-detect the king, so test your
inference contract locally first.

The pinned model is a reasoning model. The validator gives it enough token budget
to both think and answer, so your `max_tokens` is raised to a safe ceiling
automatically — you do not need a large value. Read the final answer from
`choices[0].message.content` (the reasoning trace is separate; the answer you want
is in `content`).

## Screening Gate — what closes a PR, and what does not

There are exactly **two** ways a PR ends without merging. Knowing which is which
means nothing surprises you: a bad run on one problem will never sink your PR.

### 1. Static screening — runs BEFORE the duel; the only thing that closes a PR early

These are cheap, source-only checks (no model calls). If any fail, the PR is
closed immediately with a clear reason and **no duel cost is spent**. Pass all of
these and your submission is guaranteed a fair, full duel:

- Your PR touches exactly one `submissions/<pack>/<mode>/<id>/` directory and
  edits nothing else (not `kings/`, `lanes/`, evaluator code, tests, or docs).
- The bundle contains only allowed files — no `helpers/` directory in V1, no
  symlinks, and within the file-count/size limits.
- `agent.py` is valid Python and defines a **synchronous** `agent_main` that is
  callable with **no arguments** (`agent_main()`), returning a dict with a
  top-level `vulnerabilities` list.
- `agent_main` is **not a stub**: it must not directly return
  `{"vulnerabilities": []}` (or an empty list) without doing any analysis.
- No hardcoded provider secrets anywhere (for example `sk-...`, `ghp_...`,
  `cpk_...`).
- No references to validator-only secrets (`CHUTES_API_KEY`,
  `KATA_VALIDATOR_API_KEY`).
- No benchmark answer-key leakage tokens (for example `expected_findings`,
  `ground_truth`, `curated-highs-only`, `scabench`). Find the bugs — do not try
  to read the answers.
- Your agent is not a copy of the current king.

### 2. The duel — bad, empty, or slow output NEVER closes your PR

Once static screening passes, your agent runs against **every** sampled problem
alongside the king. Here, a bad result is only a **0 for that problem** — it is
never a rejection:

- If your agent errors, times out, or returns no findings on a problem, that
  problem scores **0** and the duel **continues** to the rest. One bad problem
  cannot sink an otherwise-good submission.
- If your inference calls fail and you return an empty list, you are **not
  rejected** — you simply score 0 and lose on detection. The PR comment tells you
  how many problems produced findings (for example, "produced findings on 2/6
  problems") so you can fix your inference contract and resubmit.
- You lose the duel only when you do not out-detect the king across the sampled
  problems.

**Takeaway:** take the static checklist seriously — it is the only early gate.
After that it is purely about detection quality, and no single failed problem or
flaky run will close your PR.

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
- `agent_main` is not a stub — it does real analysis (a direct empty return is
  rejected). When run locally it should produce real findings; an agent that
  finds nothing is not rejected, but it cannot out-detect the king.
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

These are the **static** conditions that close a PR *before* the duel. (Runtime
output problems — empty findings, unparsable reports, timeouts, weak or wrongly
shaped findings — are **not** rejections; they score 0 on that problem and the
duel continues. See "Screening Gate" above.)

Kata rejects submissions for:

- invalid PR shape
- more than one submission directory
- off-scope file changes
- missing required files
- invalid metadata
- invalid Python syntax
- async-only `agent_main`
- required positional arguments that prevent no-argument invocation
- a stub/no-op `agent_main` that directly returns an empty `vulnerabilities` list
  without any analysis
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

- static screening must pass (see the Screening Gate above)
- candidate must strictly beat the current king across the sampled problems
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
