# PromptForge

PromptForge is an objective prompt-optimization repo for SN74/Gittensor.

It evaluates repo-specific agent prompts on pinned benchmark tasks and only
calls a prompt better when it solves more verified work under the same
conditions.

PromptForge is not a prompt library. The main product is the evaluation and
competition system:

- fixed benchmark tasks
- fixed baseline prompt
- current frontier prompt
- challenger prompt evaluation
- objective promotion rules

## What It Does

PromptForge currently supports:

- repo-specific prompt initialization from repo sources
- fixed generic baseline prompts
- eval-pack validation for pinned repo tasks
- objective eval runs using real agent commands
- baseline/frontier/challenger competition flow
- primary and holdout task pools
- manual frontier promotion after a successful challenge
- PR-submission scaffolding and validation for miner challengers
- stale-result verification against the current frontier
- PR decision primitives for external bot workflows

Current MVP boundary:

- it is a working manual competition system
- it has the engine primitives for challenger submissions
- it is not the GitHub bot itself
- it is not yet a full prompt-search engine

Prompt generation exists in this repo as a bootstrap helper:

- it can create an initial repo-specific prompt from repo files
- that prompt can seed the first frontier
- it is one source of challengers, not the main product

## Core Idea

A prompt only improves if it performs better on controlled repo tasks:

- same repo snapshot
- same task definition
- same agent command
- same model and budget
- same checks
- prompt is the variable

Prompt quality is measured by task success, path-policy compliance, and any
other behavior encoded directly in the benchmark checks. It is not judged by
wording quality alone.

## Competition Model

PromptForge uses three prompt roles for each repo and mode:

- `baseline`: fixed generic control prompt
- `frontier`: current best verified prompt
- `challenger`: new candidate prompt

Competition flow:

1. initialize a frontier manifest for a repo and mode
2. evaluate `baseline`, `frontier`, and `challenger` on the same primary pool
3. if the challenger beats the frontier, retest on the holdout pool
4. only promote if the challenger also beats the frontier on holdout
5. challenger must also clear the configured promotion margin for that lane

The baseline is not the prompt miners should use in production. It is the fixed
control used to prove that repo-specific optimization is adding value.

## Benchmark Provenance

PromptForge now records benchmark provenance alongside eval and challenge
results:

- evaluator version
- prompt hashes
- task ids
- task-pool fingerprints

This matters because a prompt win is only meaningful if it was measured against
the same evaluator and the same benchmark state. See
`docs/evaluator-versioning.md` for the intended model.

PromptForge's proposed benchmark score model is defined in
`docs/SCORING.md`.

## How To Think About The Workflow

PromptForge has two separate jobs:

1. `initialize prompts`
   Create a starting repo-specific prompt and a fixed baseline.
2. `evaluate prompts`
   Compare baseline, frontier, and challenger prompts on the same benchmark.

That is why the repo has both prompt-creation commands and competition
commands.

The simplest mental model is:

- `baseline`: fixed generic control
- `frontier`: current best verified prompt
- `challenger`: new candidate prompt

The usual workflow is:

1. define a benchmark pack
2. initialize a frontier for that repo and mode
3. use `generate` if you want a first repo-specific prompt to seed the frontier
4. challenge the frontier with better candidate prompts
5. promote the challenger if it wins primary and holdout evaluation

## Repository Layout

- `promptforge/`: core package and CLI
- external benchmark registry repo: canonical benchmark source
- external bot repo: GitHub integration and PR orchestration
- `submissions/`: miner challenger prompts submitted by PR
- `scripts/`: adapter commands for real agent evaluation
- `tests/`: regression tests for evaluator behavior

Tracked benchmark artifacts may also include:

- `frontier.json`: repo competition manifest
- `prompts/<mode>/baseline.md`
- `prompts/<mode>/frontier.md`

Generated eval runs are written to `runs/` and are ignored by git.

## Submission Model

Miner challenger PRs belong in this repo, not in the benchmark registry repo.

The submission layout is:

```text
submissions/
  <repo-pack>/
    <mode>/
      <submission-id>/
        candidate.md
        submission.json
```

Current validation rules:

- PRs should only touch one submission directory
- only `candidate.md` and `submission.json` are allowed inside that submission
- the target repo pack must already exist in the benchmark registry
- the target mode must already be configured in that pack's `frontier.json`

Recommended identity convention:

- `author`: GitHub username
- `submission_id`: `<github-username>-YYYYMMDD-NN`

This is the base contract for future PR auto-close and auto-merge automation.

See `docs/submissions.md` for the detailed submission contract and stale-result
verification flow. See `docs/github-automation.md` for the intended bot
integration contract.

## Benchmark Registry

PromptForge expects benchmark packs to live in a dedicated benchmark registry
repo.

The registry repo is identified by a marker file:

- `promptforge-benchmark-registry.json`

The benchmark packs then live under that repo's configured benchmarks directory,
normally:

- `<registry-root>/benchmarks/<repo-pack>/...`

That benchmark repo is the canonical source of:

- benchmark task folders
- `frontier.json`
- `prompts/<mode>/baseline.md`
- `prompts/<mode>/frontier.md`

PromptForge still uses the same file-based task format, but the benchmark
content should live in the benchmark registry repo, not inside the main
PromptForge repo.

PromptForge resolves the registry in this order:

1. `PROMPTFORGE_BENCHMARKS_ROOT`
2. an explicitly passed filesystem path
3. automatic discovery of a nearby repo that contains
   `promptforge-benchmark-registry.json`

`PROMPTFORGE_BENCHMARKS_ROOT` should point to either:

- the registry repo root
- the registry's `benchmarks/` directory

`--eval-pack` accepts either:

- a direct filesystem path
- a pack id under the benchmark registry, such as `e35ventura__taopedia-articles`

## Benchmark State

This branch does not currently ship a tracked live benchmark pack inside the
main PromptForge repo.

To run PromptForge end to end, you should first create or add a repo-specific
eval pack in your benchmark registry repo, then initialize a frontier for it.

At minimum, that means:

- one repo-specific pack under `<registry-root>/benchmarks/`
- valid benchmark task files
- a frontier manifest created with `promptforge frontier init`

## Quickstart

Generate a repo-specific prompt for initialization or as a challenger starting
point:

```bash
uv run python -m promptforge generate \
  --repo /path/to/target-repo \
  --mode contributor
```

Generate the fixed baseline prompt:

```bash
uv run python -m promptforge baseline \
  --repo /path/to/target-repo \
  --mode contributor
```

Validate the benchmark pack:

```bash
uv run python -m promptforge eval-pack validate \
  --path <repo-pack>
```

Run a baseline-vs-generated eval:

```bash
uv run python -m promptforge eval \
  --repo /path/to/target-repo \
  --eval-pack <repo-pack> \
  --mode contributor \
  --agent-command "$PWD/scripts/run_codex_eval.sh"
```

Render an eval report:

```bash
uv run python -m promptforge report --run <run-id>
```

## Submission Workflow

Scaffold a challenger submission:

```bash
uv run python -m promptforge submission init \
  --repo-pack <repo-pack> \
  --mode contributor \
  --submission-id miner-001
```

Validate a submission and its PR-style changed paths:

```bash
uv run python -m promptforge submission validate \
  --path submissions/<repo-pack>/contributor/miner-001 \
  --changed-path submissions/<repo-pack>/contributor/miner-001/candidate.md \
  --changed-path submissions/<repo-pack>/contributor/miner-001/submission.json
```

Inspect a PR diff before checking out the PR branch:

```bash
uv run python -m promptforge submission inspect-pr \
  --repo-root "$PWD" \
  --changed-path-file /path/to/changed-paths.txt
```

Evaluate the challenger against the current frontier:

```bash
uv run python -m promptforge submission evaluate \
  --path submissions/<repo-pack>/contributor/miner-001 \
  --agent-command "$PWD/scripts/run_codex_eval.sh"
```

Verify that the result is still current before merge:

```bash
uv run python -m promptforge submission verify \
  --path submissions/<repo-pack>/contributor/miner-001 \
  --challenge-run runs/<challenge-run>/challenge_summary.json
```

That final verification step matters because a challenger result becomes stale if
another PR has already replaced the frontier.

Convert verification into a PR action:

```bash
uv run python -m promptforge submission decide \
  --path submissions/<repo-pack>/contributor/miner-001 \
  --challenge-run runs/<challenge-run>/challenge_summary.json
```

Possible actions are:

- `close-invalid`
- `close-losing`
- `rerun-stale`
- `merge`

## Frontier Workflow

Initialize a frontier manifest:

```bash
uv run python -m promptforge frontier init \
  --repo /path/to/target-repo \
  --eval-pack <repo-pack> \
  --mode contributor \
  --primary-task task-a \
  --primary-task task-b \
  --holdout-task task-c
```

Inspect the current frontier:

```bash
uv run python -m promptforge frontier show \
  --eval-pack <repo-pack> \
  --mode contributor
```

Challenge the frontier:

```bash
uv run python -m promptforge challenge \
  --eval-pack <repo-pack> \
  --mode contributor \
  --candidate-prompt path/to/candidate.md \
  --agent-command "$PWD/scripts/run_codex_eval.sh"
```

Promote a winning challenger:

```bash
uv run python -m promptforge frontier promote \
  --challenge-run runs/<challenge-run>/challenge_summary.json
```

## Real Agent Commands

This repo includes two adapter scripts:

- `scripts/run_codex_eval.sh`
- `scripts/run_claude_eval.sh`

Optional model overrides:

```bash
PROMPTFORGE_CODEX_MODEL=o3 uv run python -m promptforge eval ...
PROMPTFORGE_CLAUDE_MODEL=sonnet uv run python -m promptforge eval ...
```

These adapters assume the corresponding CLI is already installed and
authenticated.

## Open-Source Status

PromptForge is ready to be public as a framework-level MVP.

What is already solid:

- the core objective-eval design
- benchmark-pack validation
- stricter report and path-policy handling
- frontier challenge workflow
- evaluator-version and benchmark-provenance recording
- prompt initialization for seeding a frontier
- regression tests for evaluator behavior

What is still planned:

- checked-in public benchmark packs
- automated challenger submission and queueing
- automated promotion policy
- larger benchmark coverage
- stronger reviewer-mode examples
- prompt-search automation beyond manual challenger prompts
- stronger maintainer-owned evaluator protection

## Development

Run the current checks:

```bash
uv run pytest
uv run ruff check
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidance.
