# Kata Workflow

This document explains how work moves through Kata, from a miner pull request to
a new king, and how engine contributors should change the system safely.

Kata has two contributor paths:

- **Miner contributors** submit one candidate agent under `submissions/`.
- **Engine contributors** change the competition engine, docs, lane tooling, or
  evaluator integration.

For the exact miner bundle contract, see [submissions.md](submissions.md).

## System Roles

- `kata` is the engine. It validates submissions, runs screening, scores a round
  (the cached king vs. all candidates on the same problems), ranks them, records
  provenance, and promotes winners.
- `kata-bot` is the GitHub automation layer. On a PR event it **intakes** the PR
  (screen into `kata:pending`, `kata:review`, or `kata:invalid`). When a **round** is run, it locks the pending PRs,
  gates and screens them, calls the engine to score them, applies the outcome labels,
  and merges + promotes the winner. It publishes a live round status and history for
  the dashboard.
- `kata-board` is the dashboard. It reads live round status, lane state, run artifacts,
  the round-history highlights feed, and PR history.
- `sandbox` is the pinned SN60 Bitsec evaluator mirror. Kata reads and executes
  against it, but Kata changes must not modify upstream subnet code.

## Miner Submission Lifecycle

Scoring happens in **scheduled rounds**, not on PR open. Opening a PR enters you as a
pending entrant; a round scores every pending entrant against the king at once.

**Intake — when you open or update a PR:**

1. **Create a branch.** The miner works in the public Kata repo on a normal GitHub
   branch.
2. **Add one bundle.** The PR adds exactly one directory under
   `submissions/<subnet-pack>/<mode>/<submission-id>/`. A contributor may have only one
   open PR at a time.
3. **Validate locally.** The miner runs `kata submission validate` before opening the PR.
4. **Open PR.** The PR targets the default competition branch and only touches the
   submission bundle. The submission directory/id prefix and `submission.json`
   `author` must match the GitHub account that opens the PR.
5. **Intake.** `kata-bot` screens the PR (shape + cheap static anti-cheat) and labels it
   `kata:pending` — it now waits for the next round. A failing or identity-mismatched
   PR is closed `kata:invalid` before pending. Suspicious but non-conclusive evidence is
   held as `kata:review`; maintainers can clear it with `/kata approve`,
   re-run screening with `/kata review`, or close it with `/kata close`, but
   hard rejects cannot be bypassed.
   Pushing a commit to a benched (`kata:stale`) PR re-enters it as `kata:pending`.

**Round — when a competition round is run (`kata-bot run-round-env`):**

6. **Lock pending entrants.** The round snapshots currently-open PRs that carry
   `kata:pending`, keeps one PR per contributor (extras closed `kata:invalid`), and
   applies the re-entry rule — a kept-open PR is re-scored only if its commit or the
   king changed since it last competed. `kata:review` and unlabeled PRs do not enter.
7. **Execution screener & mark.** The round does not re-run full static/LLM screening;
   that already happened at intake or on the latest push/review command. If enabled,
   the one-project execution screener runs before scoring. Candidates that fail it are
   closed `kata:invalid`; candidates that pass are labeled `kata:executing`.
8. **Score.** Kata scores the **cached** king and every candidate on the same
   secretly-sampled problems, then ranks them.
9. **Decide & apply.** The top candidate that strictly beats the king wins. The bot
   applies outcome labels: winner → merge + promote; a runner-up that also beat the king →
   kept open `kata:pending`; a candidate that didn't → closed `kata:losing`.
10. **Promote.** The verified winner is merged, published as the new king under `kings/`,
    and the lane state is updated.

## Evaluation Stages

The stages, decisions, and provenance below are the general Kata flow and apply to any
lane. The concrete rules, metrics, and environment variables in this section are the
implementation of the one lane live today — **SN60 / Bitsec** (`sn60__bitsec/miner`).
Future lanes plug into the same stages with their own evaluator, benchmark, and scoring;
they will document their lane-specific rules separately.

### 1. Validation

Validation checks the candidate bundle before any expensive sandbox work:

- exactly one submission directory
- required files are present
- `agent.py` defines a valid synchronous `agent_main`
- Python sources compile
- the target lane exists and is active
- the bundle uses the supported small bundle layout and stays within size limits
- obvious secret leakage and benchmark-answer leakage are rejected
- model/sampling fields are handled by the relay at runtime, not rejected just
  because they appear in source
- benchmark-specific answer replay is rejected; agents may use general reusable
  analysis heuristics, but must not recognize known benchmark projects and return
  prewritten findings

### 2. Screening

Screening has two parts:

**Static screening — runs during PR intake/update, before pending.** Cheap, source-only
checks (no model calls). If a hard rule fails, the PR is closed immediately with the
reason and never receives `kata:pending`:

- hardcoded provider keys or validator-secret env references
- benchmark-answer leakage indicators
- benchmark-specific answer replay, including exact project fingerprints, known
  finding IDs, or prewritten findings for known benchmark projects
- async or non-callable `agent_main`
- a stub that directly returns `{"vulnerabilities": []}` without doing any analysis

Static screening currently allows:

- Python helper modules under `helpers/`
- normal request fields such as `temperature`, `top_p`, `top_k`, and `seed`

Those request fields are still ignored or stripped by the relay during execution, so
they do not create a model-control advantage.

**Optional screener project — runs BEFORE the duel when enabled.** Production can set
`KATA_SN60_ENABLE_SCREENER_PROJECT=1` and optionally
`KATA_SN60_SCREENER_PROJECT_KEY=<benchmark-project-id>` to run the candidate once on a
single benchmark project before scoring. This gate checks only that the agent executes
successfully and returns valid report JSON with a top-level `vulnerabilities` list. It
does **not** require the agent to find a vulnerability on the screener project, and it
does not contribute to the final score. If it fails because of candidate behavior, the
PR is closed `kata:invalid` as a screening failure, not `kata:losing`.

**Execution note — informational only; never closes a PR.** The candidate already runs
on every sampled project inside the duel, so Kata reuses those runs to record a
per-problem findings note — e.g. *"produced findings on 2/7 problems"* — for feedback.
A bad, empty, or unparsable result on a scored problem is simply **scored 0 for that
problem**, never a rejection. An agent that finds nothing loses on score; it is not
"screened out". A *non-stub* agent that happens to return no findings is fine.

When the optional screener is disabled, there is no separate screening sandbox run and
no separate screening timeout; each agent runs once per selected project inside the
duel, under the normal duel execution timeout.

### 3. Round scoring

A round scores the king against **all** qualified candidates on the **same** problem set.

- **The king is cached.** Its per-project scores are stored keyed by the king artifact
  and benchmark version, so the king is scored at most once per problem — not re-run for
  every round or every candidate. It is recomputed only when the king or benchmark changes.
- **One sampled problem set per round.** The round samples the round's problems once
  (secret-seeded); every candidate faces that identical set, so results are directly
  comparable. Different rounds sample different problems, which prevents overfitting.
- In SN60-compatible production mode, each selected project runs 3 times. A project
  passes only if at least 2 of 3 runs return PASS.
- Scoring is **resilient** — every selected project is scored, and a bad or invalid result
  on one project (scored 0 for that project) does not abort the rest.
- The sandbox returns SN60 metrics for each project: true positives, total expected,
  detection rate, precision, F1, and PASS/FAIL.
- Each candidate's per-project scores are summarized, and candidates are ranked by
  SN60 pass/fail score first. Detection rate remains visible as a diagnostic metric.

Sampling configuration (set on the validator):

- `KATA_SN60_PROJECT_SAMPLE_SIZE` — how many problems each round samples. Recent
  SN60 v3 rounds use 7 scoring projects, so production should use `7` unless the
  active Bitsec project set changes.
- `KATA_SN60_PROJECT_SAMPLE_SECRET` — required when the sample size is smaller than the
  full benchmark; keeps the per-round problem set private until results.
- `KATA_SN60_PROJECT_KEYS` — an explicit override; normally left unset for production.

The selected keys are recorded in the round/challenge summary and lane provenance.

Example MVP settings:

```bash
KATA_SN60_PROJECT_KEYS=
KATA_SN60_PROJECT_SAMPLE_SIZE=7
KATA_SN60_PROJECT_SAMPLE_SECRET=<private-validator-secret>
KATA_SN60_REPLICAS_PER_PROJECT=3
KATA_SN60_VALIDATOR_REPLICA_COUNT=1
KATA_SN60_ENABLE_SCREENER_PROJECT=1
KATA_SN60_SCREENER_PROJECT_KEY=<valid-benchmark-project-id>
```

### 4. Promotion Gate

A candidate promotes only if all conditions pass:

- screening passed
- candidate strictly beats the king by rank
- the result is fresh against the current king and benchmark state

The rank comparator is:

1. SN60 pass score: passed projects / selected projects
2. codebase pass count
3. true positives
4. fewer invalid/error evaluations
5. precision
6. F1 score

Same score and same tie-breakers are not enough; the candidate must strictly
beat the current king.

SN60 pass score follows the Bitsec leaderboard style: a project only counts as
passed when all expected high/critical findings are found reliably. With
`KATA_SN60_REPLICAS_PER_PROJECT=3`, Kata uses the 2-of-3 project pass rule.
Detection score is still recorded as `total_true_positives / total_expected_vulnerabilities`
for diagnostics and public proof.

Metric meanings:

- `true positives`: benchmark vulnerabilities the agent correctly found.
- `precision`: how many reported findings were real matches,
  `true_positives / total_found`.
- `F1 score`: balance between detection score and precision.
- `invalid/error evaluation`: the sandbox or scorer could not produce a valid
  successful evaluation for that project. It contributes zero metrics and hurts
  tie-breaks.

Sandbox `PASS` still means a project run found all expected vulnerabilities.
Passed project count is the primary promotion score.

## Round Outcomes

At the end of a round, each PR resolves to one outcome (and its label):

- **Winner** (`kata:winner:<pack>`) — the top candidate that strictly beat the king; it is
  merged and promoted. At most one per round. Winners also receive exactly one
  `kata:reward:*` tier for Gittensor/SN74 reward weighting.
- **Kept pending** (`kata:pending`) — a candidate that beat the king but was not the top
  challenger; it stays open to compete again next round.
- **Losing** (`kata:losing`) — a candidate that entered scoring but did not beat the
  king; closed.
- **Invalid** (`kata:invalid`) — failed intake screening, failed round-start execution
  screener, or an extra open PR beyond the one-per-contributor limit; closed.
- **Review** (`kata:review`) — suspicious but non-conclusive screening evidence; held out
  of rounds until a maintainer approves with `/kata approve` or the miner pushes a
  clean update. Maintainers can also re-run screening with `/kata review` or close
  the PR with `/kata close`. If `KATA_SCREENING_LLM_REVIEW=1` is enabled, a local Codex CLI review
  (`KATA_SCREENING_LLM_MODEL=gpt-5.4` by default) may add review evidence and an
  audit artifact, but it never hard-rejects by itself.
- **Stale** (`kata:stale`) — a kept-open PR that was unchanged since it last competed (same
  commit and same king), so it is skipped this round; a push re-enters it as pending.
- **Hold** (`kata:hold`) — a winner whose merge is currently blocked (merge conflict, or a
  pre-merge promotion check that would leave the king un-updated); held for attention rather
  than merged into a broken state.

Internally the engine still reduces a single candidate's result to one of `merge`,
`close-losing`, `close-invalid`, or `rerun-stale`; the round applies these across the batch
and maps them to the labels above.

## Winner Reward Tiers

The reward tier is separate from the promotion decision. A candidate must first win the
round and pass the pre-merge promotion checks. Then Kata reads the verified challenge
summary and applies one tier:

| Label | Condition |
| --- | --- |
| `kata:reward:s` | valid promotion below the higher tier thresholds |
| `kata:reward:m` | candidate true positives >= 3, or candidate beats king by >= 2 true positives, or score delta >= 15% |
| `kata:reward:l` | candidate true positives >= 5, or candidate beats king by >= 4 true positives, or detection score >= 60% |
| `kata:reward:xl` | candidate true positives >= 8, or candidate beats king by >= 6 true positives, or detection score >= 85% |

Gittensor uses the highest matching label multiplier on the merged PR. A base winner label
identifies the lane (`kata:winner:sn60__bitsec`), while the reward tier determines whether
the promotion is scored as small, medium, large, or extra-large. Gittensor also applies
time decay to merged winners, so a newer king has more reward weight than an older winner
PR inside the lookback window.

## Freshness And Provenance

Every evaluation records enough data to audit the result:

- candidate artifact hash
- king artifact hash
- selected project keys
- benchmark file hash
- sandbox commit
- scorer version
- replica count
- challenge fingerprint

Before merging, Kata verifies that the evaluated candidate still matches the PR,
the king is still current, and the benchmark lane fingerprint has not changed.

## Promotion

When the final action is `merge`, the production bot:

1. labels the PR with the winning lane label
2. labels the PR with the deterministic reward tier
3. merges the PR
4. publishes the candidate bundle under `kings/<subnet-pack>/<mode>/`
5. updates lane king state
6. clears the merged submission directory from `main`

This keeps `submissions/` empty between active PRs while `kings/` remains the
public source of truth for the current best agent.

## Engine Contribution Workflow

Engine contributions should preserve evaluator integrity and provenance.

1. Identify the affected area:
   - submission contract: `kata/submission_system/`
   - screening rules: `kata/screening_system/`
   - validator and challenge flow: `kata/validator_system/`, `kata/evaluators/`
   - promotion logic: `kata/promotion_system/`
   - lane and public state: `kata/state_system/`, `lanes/`
   - docs: `README.md`, `docs/`
2. Add or update tests for behavior changes.
3. Run targeted tests first, then broader tests when practical.
4. Do not weaken validation, screening, freshness, or promotion gates without a
   specific rationale and tests.
5. Do not modify upstream subnet code in `sandbox`.

Recommended local checks:

```bash
uv run pytest -q tests/test_submissions.py tests/test_sn60_challenge.py tests/test_sn60_bitsec.py
uv run --extra dev python -m pytest
uv run --extra dev python -m ruff check kata tests
```

## Manual Command Reference

Run a competition round (the bot: lock open PRs → gate → screen → score → apply outcomes):

```bash
uv run python -m kata_bot run-round-env    # kata-bot; reads the deployment env file
```

Score the king against several candidates directly (the engine, used by the round runner):

```bash
uv run kata round \
  --king-path kings/<subnet-pack>/<mode> \
  --candidate <submission-id>=<artifact-path> [--candidate ...] \
  [--king-scoreboard lanes/<lane-id>/king_scoreboard.json] \
  --json
```

Inspect changed paths:

```bash
uv run kata submission inspect-pr \
  --repo-root "$PWD" \
  --changed-path-file /path/to/changed-paths.txt
```

Validate a bundle:

```bash
uv run kata submission validate \
  --path submissions/<subnet-pack>/<mode>/<submission-id>
```

Evaluate a bundle:

```bash
uv run kata submission evaluate \
  --path submissions/<subnet-pack>/<mode>/<submission-id> \
  --json
```

Verify a result:

```bash
uv run kata submission verify \
  --path submissions/<subnet-pack>/<mode>/<submission-id> \
  --challenge-run runs/<challenge-run>/challenge_summary.json
```

Decide PR action:

```bash
uv run kata submission decide \
  --path submissions/<subnet-pack>/<mode>/<submission-id> \
  --challenge-run runs/<challenge-run>/challenge_summary.json
```

Promote a verified winner:

```bash
uv run kata king promote \
  --challenge-run <challenge-summary.json> \
  --submission-path <submission-dir>
```
