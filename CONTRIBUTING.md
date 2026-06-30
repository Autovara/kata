# Contributing to Kata

Kata is an objective coding-agent competition repo. Contributions should make
the evaluator, benchmark packs, or agent competition workflow more trustworthy
and more useful.

## Priorities

- Keep scoring objective and reproducible.
- Prefer pinned tasks and explicit checks over subjective judgment.
- Treat benchmark and evaluator correctness as higher priority than prompt style.
- Keep changes scoped and easy to audit.
- Preserve benchmark provenance so results stay comparable over time.

## Local checks

Run these before opening a PR:

```bash
uv run --extra dev python -m pytest
uv run --extra dev python -m ruff check kata tests
uv run kata eval-pack validate --path <your-eval-pack>
```

If you change the benchmark runner or reporting logic, add or update tests.

## Benchmark packs

Eval-pack tasks should be based on real repo work where possible:

- real issues
- real PR-sized edits
- pinned commits
- explicit pass/fail checks
- explicit allowed and forbidden paths when task scope matters

Do not commit placeholder scaffold tasks as if they were live benchmarks.

Canonical benchmark packs should live in a benchmark registry repo that contains
`kata-benchmark-registry.json`, rather than in the main Kata repo.

## Competition model

Kata uses three lane roles:

- `baseline`: fixed generic control artifact
- `frontier`: current best verified artifact for a repo and mode
- `challenger`: new candidate agent trying to replace the frontier

A challenger should only be promoted when it beats the frontier on the primary
pool and, when configured, on the holdout pool.

Benchmark changes should also preserve clear provenance:

- evaluator version
- artifact hashes
- task-pool fingerprints
- explicit task ids

## Submission PR rules

Challenger PRs should submit files only under:

- `submissions/<repo-pack>/<mode>/<submission-id>/`

Required files:

- `agent.py`
- `submission.json`

Recommended metadata convention:

- `author`: GitHub username
- `submission_id`: `<github-username>-YYYYMMDD-NN`

Submission PRs should not edit:

- benchmark task definitions
- frontier manifests
- frontier lane artifacts
- unrelated Kata code or docs

Those PRs should be treated as invalid competition submissions.

## Scope guidance

Good contributions:

- stronger eval-pack checks
- better task coverage
- clearer baseline/frontier/challenger workflow
- safer reporting and anti-gaming logic
- better contributor and reviewer prompt initialization

Lower-priority contributions:

- broad artifact rewrites without benchmark evidence
- subjective style changes without measured improvement
- changes that treat initialization as the main product rather than as a
  source of frontier challengers
