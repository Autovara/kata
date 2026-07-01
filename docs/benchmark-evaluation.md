# Benchmark Evaluation Contract

This document answers the core maintainer question:

> What is the benchmark, and how do we know an agent actually improved?

## Current Benchmark Object

A Kata benchmark task is a pinned repo repair problem. Each task directory
contains:

- `task.md`: the visible task statement sent to the agent
- `repo_ref.txt`: the target repo pinned to a specific git ref
- `checks.sh`: validator-side verification commands
- `rubric.md`: human-readable pass/fail contract
- `allowed_paths.txt`: paths the agent may edit
- `forbidden_paths.txt`: paths the agent must not edit
- `oracle.json`: optional deterministic task-specific assertions
- `benchkit.json`: provenance and lifecycle metadata

For the current Taopedia lane, tasks are mined from historical commits. The
task repo ref points to the parent commit, and `source_ref` records the
historical commit that originally fixed or added the article.

## Current Duel

The current production lane uses:

- `10` public primary tasks sampled from `kata-benchmarks`
- `10` private holdout tasks from `kata-benchmarks-private`
- the same validator-owned model, command, budget, repo snapshot, and task set
  for both king and candidate

Each pool is scored on a normalized `0-100` scale. With 10 equal-weight binary
tasks, one solved task is worth 10 points.

Promotion requires:

- primary score at least `king + 30`
- holdout score at least `king + 10`
- no path-policy or benchmark-integrity failure

In task-count terms, that is roughly `+3` public tasks and `+1` hidden task.

## Honest Current Weakness

The current generated Taopedia tasks are not strong enough yet.

They usually run:

```bash
npm run format:check
npm run validate
```

Those checks prove that the repo remains syntactically valid. They do not prove
that the article change solved the intended historical content problem.

So the current benchmark has good provenance and scoped execution, but weak
semantic verification. A candidate could potentially pass by making a valid but
incomplete or irrelevant article edit if the repo-level validator does not catch
that distinction.

## Correct Verification Standard

A production benchmark task should have a task-specific oracle. The oracle does
not need to require an identical patch, but it must reject clearly wrong or
partial solutions.

For coding repos, the best oracle is usually deterministic:

- failing test before the fix, passing test after the fix
- targeted unit/integration/regression test
- static assertion over expected API behavior
- command output comparison
- schema or migration validation

For content repos like Taopedia, the oracle should combine deterministic checks:

- the intended file changed and unrelated files did not
- required front matter fields are valid
- required source/citation rules are satisfied
- required facts or claims are present
- known wrong claims are absent
- repo format and validation pass

The historical after-commit can be used as reference material, but the checker
should avoid exact full-file equality unless exact reproduction is the intended
task. Equivalent correct solutions should pass.

## Deterministic Oracle Format

Kata supports an optional `oracle.json` file in each task:

```json
{
  "schema_version": 1,
  "target_files": ["content/pages/example/index.mdx"],
  "required_contains": [
    {
      "path": "content/pages/example/index.mdx",
      "text": "required factual claim"
    }
  ],
  "forbidden_contains": [
    {
      "path": "content/pages/example/index.mdx",
      "text": "known wrong claim"
    }
  ],
  "required_regex": [],
  "forbidden_regex": []
}
```

Task checks should run the oracle after repo-level checks:

```bash
python -m kata.oracle verify \
  --workspace "$KATA_WORKSPACE" \
  --task-dir "$KATA_EVAL_TASK_DIR" \
  --score-file "$KATA_SCORE_FILE"
```

The oracle writes `1.0` or `0.0` to the score file and exits nonzero on failure.

## LLM Judges

LLM judging can be useful for content quality, but it should not be the only
public MVP scoring mechanism.

If used, the safer pattern is:

- deterministic checks remain the hard gate
- LLM judgment is limited to a small rubric with explicit evidence
- the judge sees the task, candidate diff, before state, and hidden reference
  notes
- use a stronger validator-owned model than the miner execution model
- record judge model, prompt version, and score in evaluator provenance
- use multi-sample or multi-judge only after the cost and variance are measured

Do not use a freeform "does this look better?" judge as the primary reward
source. That would make the reward boundary hard to audit and easier to dispute.

## Required Upgrade Before Broad GitTensor Registration

Before presenting Kata as a robust GitTensor reward target, each live task
should satisfy:

- `checks.sh` contains task-specific assertions, not only generic repo checks
- `benchkit.json.objective_verification` means the task has a real oracle
- task lint/reporting should flag generic-only checks as not production-ready
- primary and holdout pools should contain diverse task types and paths
- retired holdout tasks can be published later as examples of the hidden oracle
