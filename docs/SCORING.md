# Kata Scoring Specification

**Applies to**: Kata benchmark competition

**Status**: Proposed scoring contract for the public MVP

**Version**: 1.0

---

## Overview

Kata is an objective repo-specific agent evaluation system. Its scoring
algorithm
must answer one question:

> Under the same repo, benchmark, and execution conditions, did one prompt
> perform better than another?

This document defines the scoring model for that comparison.

The design goal is:

- scientific enough to be defensible
- simple enough to audit
- strict enough to resist gaming
- scoped enough to compare prompts within one repo benchmark lane

Kata does **not** define one universal score across all repos.

Scores are only intended to be compared inside the same:

- repo
- mode
- evaluator version
- benchmark task pool

See [evaluator-versioning.md](./evaluator-versioning.md) for the provenance
requirements behind that rule.

---

## Competition Lane

One prompt competition lane is:

`repo + mode + evaluator_version + task_pool_fingerprint`

User-facing shorthand:

`repo + mode + benchmark version`

Examples:

- contributor prompts for `e35ventura/taopedia-articles`
- reviewer prompts for `entrius/gittensor`

Scores from different lanes should not be treated as directly comparable.

---

## Scoring Principles

Kata scoring follows these principles:

1. **Objective first**
   Scores must come from benchmark checks, not subjective prompt judgments.

2. **Validity before score**
   A run that violates benchmark integrity should not be rescued by partial
   credit.

3. **Per-task quality, then aggregate**
   Each benchmark task produces a quality value in `[0, 1]`. Pool scores are
   built from those per-task values.

4. **Primary and holdout stay separate**
   Optimization and generalization should not be collapsed into one number for
   promotion decisions.

5. **Cost is a second axis**
   Cost may be reported, but should not change correctness score in the MVP.

---

## Prompt Roles

Kata evaluates three artifact roles inside one challenge:

- `baseline`: fixed generic control prompt
- `frontier`: current best verified prompt
- `candidate`: challenger prompt trying to replace the frontier

The purpose of the score is:

- compare `candidate` vs `frontier`
- quantify `candidate` vs `baseline`
- support promotion decisions using primary and holdout pools

---

## Task-Level Scoring

Each benchmark task produces a task quality value `q_i` in `[0, 1]`.

### Formula

For task `i`:

`q_i = verifier_score_i * validity_gate_i`

Where:

- `verifier_score_i` is the objective score produced by benchmark verification
- `validity_gate_i` is either `1` or `0`

### Validity Gate

`validity_gate_i = 0` when the run is invalid for scoring purposes.

Examples:

- forbidden path violation
- changed files outside the allowed scope
- missing required output artifacts
- run failed in a way that produced no valid benchmark result
- benchmark-defined hard disqualification condition

If the task run is valid:

`validity_gate_i = 1`

This means invalid benchmark behavior collapses the task score to zero.

### Verifier Score

`verifier_score_i` should be defined by the benchmark task and must stay within
`[0, 1]`.

Recommended forms:

- binary pass/fail:
  - pass = `1.0`
  - fail = `0.0`
- continuous test fraction:
  - `passed_checks / total_checks`
- objective subtask fraction:
  - `completed_required_items / total_required_items`

Kata should not use subjective freeform LLM grading as the primary score
for the public MVP.

---

## Pool-Level Scoring

Each task has a nonnegative weight `w_i`.

For a pool of tasks, the score is:

`pool_score = 100 * sum(w_i * q_i) / sum(w_i)`

This produces a normalized score in `[0, 100]`.

### Default Weight Rule

For the MVP:

- every task should default to `w_i = 1.0`

This keeps scoring easy to audit and avoids arbitrary weight inflation.

### When Unequal Weights Are Acceptable

Unequal weights may be justified when a repo maintainer explicitly wants to
emphasize:

- a critical maintainer workflow
- a high-value representative task
- an anti-gaming or policy-sensitive task

If unequal weights are introduced, they should be tracked with the benchmark
definition and therefore included in the benchmark versioning story.

---

## Primary and Holdout Scores

Kata uses at least two task pools:

- `primary`
- `holdout`

Each pool gets its own score:

- `primary_score`
- `holdout_score`

These scores must remain separate.

Reason:

- `primary_score` measures optimization on the visible challenge set
- `holdout_score` measures whether the improvement generalizes beyond the set
  used for optimization

Kata should not merge primary and holdout into one promotion number in
the MVP.

---

## Promotion Decision

Promotion should not be based on "candidate score is slightly larger."

The decision should use:

- score comparison
- holdout protection
- hard integrity gates

### Recommended MVP Rule

Promote the candidate only if all of the following are true:

1. `candidate_primary_score > frontier_primary_score + m`
2. `candidate_holdout_score >= frontier_holdout_score`
3. the candidate has no benchmark-integrity disqualification

Where:

- `m` is the primary improvement margin

Recommended public-MVP default:

- `m = 3.0` points on the `0-100` scale

This protects the frontier from noise and trivial score differences.

### Why A Margin Is Needed

Without a margin:

- tiny benchmark noise can flip the frontier
- miners are rewarded for negligible or lucky differences
- the benchmark becomes unstable

This follows the same high-level logic used in `trajectoryRL`: improvement
should clear a takeover bar, not just a strict epsilon.

---

## Binary vs Continuous Benchmarks

Kata supports both styles.

### Binary Benchmarks

Best for:

- simple repo tasks
- strong pass/fail checks
- repos with one clear success condition

Task quality:

- pass = `1.0`
- fail = `0.0`

### Continuous Benchmarks

Best for:

- richer tasks with multiple objective checks
- cases where partial success matters
- verifier suites with many test assertions

Task quality examples:

- fraction of tests passed
- fraction of objective subtasks completed
- weighted combination of objective sub-checks

Continuous scoring is often more informative, but only when the benchmark can
define partial credit objectively.

---

## Cost Reporting

Kata should report cost separately from correctness score.

Recommended metrics:

- total cost
- average cost per task
- average cost per successful task

The MVP should **not** subtract cost from benchmark score.

Reason:

- task correctness and execution cost are different optimization axes
- combining them too early can hide whether a prompt is actually better or just
  cheaper

Future versions may support separate efficiency leaderboards or Pareto-style
comparison, but not in the core promotion score.

---

## Variance and Repeated Runs

LLM-based agent evaluation contains runtime variance. The most defensible long
term model is to evaluate prompts across fixed seeds or repeated runs.

### Future Stronger Formula

For task `i` and seed `s`:

`q_i = mean_s(q_i,s)`

Then:

`pool_score = 100 * sum(w_i * mean_s(q_i,s)) / sum(w_i)`

This is more scientifically robust than a single run.

### MVP Boundary

The public MVP may use one run per task for operational simplicity.

When repeated-run evaluation is added, the number of seeds and the aggregation
rule should become part of evaluator versioning.

---

## Required Benchmark Contract

For a benchmark task to participate in scoring reliably, it should define:

- exact task statement
- fixed repo reference
- objective verification logic
- allowed and forbidden paths when task scope matters

In practice, this means the eval task should provide:

- `task.md`
- `repo_ref.txt`
- `checks.sh`
- `rubric.md`
- `allowed_paths.txt`
- `forbidden_paths.txt`

The benchmark must be strong enough that:

- correct solutions pass
- fake or partial solutions fail or score lower
- out-of-scope edits are punished through validity gating

---

## Recommended Challenge Output

Every challenge summary should report at least:

- `primary_score`
- `holdout_score`
- `tasks_total`
- `tasks_solved`
- `invalid_tasks`
- `score_delta_vs_frontier`
- `score_delta_vs_baseline`
- `promotion_ready`

Helpful secondary metrics:

- total cost
- average cost per task
- prompt hashes
- task-pool fingerprints

---

## Anti-Gaming Rules

A scoring system is only useful if it resists the easiest gaming paths.

Kata scoring should therefore preserve these rules:

- invalid benchmark behavior scores zero for the affected task
- holdout tasks are not merged away into the primary score
- benchmark provenance is recorded
- promotion requires more than a tiny edge
- task weights should remain simple and auditable

The benchmark should always prefer:

- stronger checks
- clearer task scope
- harder-to-fake success conditions

over more complicated scoring formulas.

---

## Recommended MVP Defaults

For the public MVP, the recommended defaults are:

- one competition lane per `repo + mode + benchmark version`
- per-task quality in `[0, 1]`
- invalid task runs score `0`
- equal task weights
- pool score normalized to `[0, 100]`
- separate primary and holdout scores
- cost reported separately
- promotion margin of `3.0` primary-score points
- no promotion when holdout regresses

This gives Kata a scoring model that is:

- objective
- simple
- competitive
- explainable to miners and reviewers

---

## References

- [README.md](../README.md)
- [evaluator-versioning.md](./evaluator-versioning.md)
- `trajectoryRL` scoring references:
  - https://github.com/trajectoryRL/trajectoryRL/blob/main/README.md
  - https://github.com/trajectoryRL/trajectoryRL/blob/main/docs/EVALUATION_S1.md
  - https://github.com/trajectoryRL/trajectoryRL/blob/main/docs/INCENTIVE_MECHANISM.md
