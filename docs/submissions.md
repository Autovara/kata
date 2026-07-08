# SN60 Miner Submission Checklist

This is the contributor contract for the live Kata lane:

```text
sn60__bitsec / miner
```

Use this checklist before opening a PR. The goal is simple: submit one honest,
general vulnerability-finding agent that can be scored fairly against the current
king. Do not edit validator, sandbox, lane, or king code in a miner PR.

## Quick Checklist

Your PR is ready when all of these are true:

- The PR touches exactly one directory under
  `submissions/sn60__bitsec/miner/<submission-id>/`.
- The `<submission-id>` is `<github-username>-YYYYMMDD-NN`.
- The `<github-username>` prefix matches the GitHub account that opens the PR.
- `submission.json` `author` also matches the PR author's GitHub username.
- The PR changes at least one agent bundle file, normally `agent.py`.
- The only required files are present: `agent.py`, `agent_manifest.json`, and
  `submission.json`.
- `agent.py` defines a synchronous `agent_main(...)` function.
- `agent_main()` can be called with no arguments.
- `agent_main` returns a dict with top-level `vulnerabilities`.
- The agent does real analysis. It is not an empty stub or canned constant report.
- The bundle has no helper files, symlinks, hardcoded secrets, provider URLs, or
  benchmark-answer replay logic.
- The bundle passes local validation:

```bash
uv run kata submission validate \
  --path submissions/sn60__bitsec/miner/<submission-id>
```

## Directory Layout

A valid miner PR adds or updates exactly one submission directory:

```text
submissions/
  sn60__bitsec/
    miner/
      <github-username>-YYYYMMDD-NN/
        agent.py
        agent_manifest.json
        submission.json
```

Example:

```text
submissions/sn60__bitsec/miner/alice-20260708-01/
```

If the PR author is `alice`, the submission ID must start with `alice-`. If the
PR author is `jonathanchang31`, then `jonathan-20260708-01` is invalid. Identity
mismatches are closed as `kata:invalid` before the PR can enter a round.

## Required Files

### `agent.py`

`agent.py` is the executable miner code.

It must define:

```python
def agent_main(project_dir: str | None = None, inference_api: str | None = None) -> dict:
    return {
        "vulnerabilities": [
            {
                "title": "Missing access control on privileged update",
                "description": "Explain the bug and impact clearly.",
                "severity": "high",
                "file": "contracts/Example.sol",
            }
        ]
    }
```

Requirements:

- `agent_main` must be synchronous. The SN60 runner calls it directly and does
  not await coroutines.
- `agent_main()` must work with no arguments.
- The return value must be JSON-serializable.
- The top-level result must include `vulnerabilities`.
- Each finding should include a clear title, description, severity, and source
  location when possible.
- A direct empty return such as `{"vulnerabilities": []}` is rejected as a no-op.
- A constant canned report that does not read or analyze the project is rejected
  as a fake agent.
- A real agent that analyzes the project but happens to find nothing during a
  run is not closed; that project simply scores 0.

### `agent_manifest.json`

Use exactly this runtime contract:

```json
{
  "schema_version": 1,
  "runtime": "python",
  "entrypoint": "agent.py"
}
```

### `submission.json`

Example:

```json
{
  "schema_version": 2,
  "subnet_pack": "sn60__bitsec",
  "mode": "miner",
  "submission_id": "alice-20260708-01",
  "created_at": "2026-07-08T00:00:00+00:00",
  "author": "alice",
  "title": "short optional title",
  "notes": "short optional notes"
}
```

Requirements:

- `schema_version` must be `2`.
- `subnet_pack` must match the path, normally `sn60__bitsec`.
- `mode` must be `miner`.
- `submission_id` must match the directory name.
- `author` must match the GitHub account that opened the PR.

## Model Access

Miners do not bring API keys. The validator provides a sandbox inference proxy
and pins the model for every agent.

Use this contract:

- Endpoint: `POST <inference_api>/inference`
- `inference_api`: use the `agent_main(..., inference_api=...)` argument, or
  `INFERENCE_API`
- Auth header: `x-inference-api-key`
- API key source: `INFERENCE_API_KEY`
- Request shape: OpenAI-style chat body, for example
  `{"messages": [...], "max_tokens": 4000}`
- Response: read `choices[0].message.content`
- Do not use `Authorization: Bearer`
- Do not set `model`, `temperature`, `top_p`, `seed`, or other sampling knobs

Current validation inference uses the pinned Qwen model:

```text
qwen/qwen3.6-35b-a3b
```

Per problem, the relay enforces:

- up to 3 successful model calls
- up to 24,000 output tokens total
- further calls return HTTP `429`

Handle failures and `429` by returning the findings you already have. Do not
crash just because one model call failed.

Minimal example:

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

## What Gets Closed Before A Round

Kata closes a PR as `kata:invalid` before adding `kata:pending` when there is a
clear hard failure:

- More than one open PR from the same contributor. Keep one active PR and push
  updates to it.
- The PR edits anything outside its single submission directory.
- The PR edits no agent bundle file.
- The submission path, `submission_id`, or `submission.json` metadata does not
  match.
- The GitHub username in the submission ID or metadata does not match the PR
  author.
- Required files are missing or malformed.
- `agent.py` has invalid Python syntax.
- `agent_main` is missing, async, or cannot be called with no arguments.
- The agent is a no-op stub or constant canned report.
- The bundle contains unsupported files, helper files, symlinks, too many files,
  or oversized files.
- The bundle contains hardcoded API keys, provider endpoints, or direct
  references to provider/validator secret env vars such as `OPENAI_API_KEY`,
  `OPENROUTER_API_KEY`, `CHUTES_API_KEY`, or `KATA_VALIDATOR_API_KEY`.
- The bundle includes benchmark-answer leakage tokens such as
  `expected_findings`, `ground_truth`, `answer_key`, `scabench`, or `hardsteer`.
- The agent hardcodes benchmark project IDs, known finding IDs, known report
  titles, long answer text, or prewritten findings for known benchmark projects.
- The agent is an exact or AST-equivalent copy of the current king.

General reusable analysis logic is allowed. Project-specific answer replay is
not allowed.

## What Gets Held For Review

Suspicious but non-conclusive evidence is labeled `kata:review`, not
`kata:pending`. A PR with `kata:review` cannot enter a round.

Examples:

- Near-copy similarity that is not an exact king copy.
- Ambiguous benchmark-fingerprint logic.
- Suspicious static report banks.
- Optional LLM review evidence that supports manual review.

Maintainers can approve a review hold by commenting:

```text
/kata approve
```

Approval removes `kata:review` and adds `kata:pending` only if the latest code
still passes all hard rejection checks. A maintainer cannot approve concrete
cheating, invalid identity, invalid PR shape, or benchmark-answer replay.

The older `/kata approve-review` command is also accepted, but `/kata approve`
is the preferred command.

## What Happens In A Round

Opening a PR does not score it immediately. After intake, a passing PR waits as
`kata:pending` until a maintainer starts a round.

In each round:

- Kata snapshots open candidate PRs at their current commits.
- Only one open PR per contributor is allowed.
- Each candidate is re-screened on the locked commit.
- The king and all candidates are scored on the same randomly sampled SN60
  benchmark problems.
- A bad, empty, slow, or crashed result on one problem scores 0 for that problem.
  It does not close the PR by itself.
- The top candidate that strictly beats the king is merged and promoted.
- A candidate that beats the king but is not the top winner stays open as
  `kata:pending` for the next round.
- A candidate that does not beat the king is closed as `kata:losing`.

Promotion comparison order:

1. Higher detection score.
2. More true positives.
3. Higher precision.
4. Higher F1 score.
5. Fewer invalid/error evaluations.

## Labels You May See

- `kata:pending`: screened and waiting for the next round.
- `kata:review`: held for maintainer review; cannot enter a round yet.
- `kata:executing`: currently competing in a round.
- `kata:winner:<pack>`: merged and promoted to king.
- `kata:reward:*`: Gittensor reward tier for a merged winner.
- `kata:losing`: competed but did not beat the king.
- `kata:invalid`: failed screening or one-open-PR rule.
- `kata:stale`: skipped because the PR commit and king were unchanged since the
  last time it competed.
- `kata:hold`: won, but merge/promotion needs maintainer attention.

## Local Commands

Create a submission:

```bash
uv run kata submission init \
  --subnet-pack sn60__bitsec \
  --mode miner \
  --submission-id <github-user>-YYYYMMDD-01
```

Validate before opening a PR:

```bash
uv run kata submission validate \
  --path submissions/sn60__bitsec/miner/<github-user>-YYYYMMDD-01
```

Then commit only that submission directory and open one PR.
