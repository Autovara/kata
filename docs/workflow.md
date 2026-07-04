# Kata Workflow

This document explains how work moves through Kata, from a miner pull request to
a new king, and how engine contributors should change the system safely.

Kata has two contributor paths:

- **Miner contributors** submit one candidate agent under `submissions/`.
- **Engine contributors** change the competition engine, docs, lane tooling, or
  evaluator integration.

For the exact miner bundle contract, see [submissions.md](submissions.md).

## System Roles

- `kata` is the engine. It validates submissions, runs screening and duels,
  records provenance, and promotes winners.
- `kata-bot` is the GitHub automation layer. It receives PR events, queues jobs,
  calls Kata commands, comments on PRs, closes losers, and merges winners.
- `kata-board` is the dashboard. It reads live status, lane state, run artifacts,
  and PR history.
- `sandbox` is the pinned SN60 Bitsec evaluator mirror. Kata reads and executes
  against it, but Kata changes must not modify upstream subnet code.

## Miner Submission Lifecycle

1. **Create a branch.** The miner works in the public Kata repo on a normal GitHub
   branch.
2. **Add one bundle.** The PR adds exactly one directory under
   `submissions/<subnet-pack>/<mode>/<submission-id>/`.
3. **Validate locally.** The miner runs `kata submission validate` before opening
   the PR.
4. **Open PR.** The PR targets the default competition branch and only touches
   the submission bundle.
5. **Queue.** `kata-bot` receives the webhook and stores a durable queue job keyed
   by repo, PR number, and head SHA.
6. **Inspect.** Before trusting PR contents, the bot checks changed paths and
   rejects off-scope edits.
7. **Evaluate.** Kata evaluates the candidate against the current king.
8. **Decide.** Kata reduces the result to one PR action.
9. **Apply action.** The bot comments, labels, closes, reruns, holds, or merges.
10. **Promote.** A verified winner is published as the new king and lane state is
    updated.

## Evaluation Stages

Kata currently runs the live SN60 Bitsec miner lane: `sn60__bitsec/miner`.

### 1. Validation

Validation checks the candidate bundle before any expensive sandbox work:

- exactly one submission directory
- required files are present
- `agent.py` defines a valid synchronous `agent_main`
- Python sources compile
- the target lane exists and is active
- the bundle is self-contained and within size limits
- obvious secret leakage, benchmark-answer leakage, and sampling overrides are
  rejected

### 2. Screening

Screening is the cheap reject gate:

- static SN60 checks
- one candidate sandbox execution
- no king run

Static screening rejects obvious cost-wasters before the sandbox starts:

- helper files in SN60 V1 bundles
- hardcoded provider keys or validator secret env references
- benchmark-answer leakage indicators
- async or non-callable `agent_main`
- direct no-op returns such as `{"vulnerabilities": []}`

Execution screening then requires one valid Bitsec-style report:

- sandbox execution must complete successfully within the validator screening
  timeout
- report must contain a top-level `vulnerabilities` list
- the list must contain at least one candidate finding
- each finding must include a title and useful description
- optional severity must be `critical`, `high`, `medium`, or `low`
- reports are capped at 100 findings

If screening fails, the PR is closed with the screening reason and the full duel
is skipped.

Production validators should keep screening cheap. The recommended MVP timeout
is:

```bash
KATA_SN60_SCREENING_EXECUTION_TIMEOUT_SECONDS=300
```

This timeout only applies to the one screening sandbox execution. Full duel
executions keep the normal SN60 execution timeout.

### 3. Duel

If screening passes, Kata runs a king-vs-candidate duel.

Default production behavior:

- all projects from the resolved benchmark snapshot are eligible
- candidate and king run the same selected project set
- each selected project runs once by default, matching the SN60 job-run style
- execution is per project: candidate first, then king for that same project,
  then the next project
- the sandbox returns SN60 metrics for each project: true positives, total
  expected, detection rate, precision, F1, and PASS/FAIL

MVP cost-saving behavior:

- validators can set `KATA_SN60_PROJECT_SAMPLE_SIZE`
- if the sample size is smaller than the full benchmark,
  `KATA_SN60_PROJECT_SAMPLE_SECRET` is required
- Kata samples a random-looking project subset per evaluation
- the selected keys are recorded in the challenge summary and lane provenance
- `KATA_SN60_PROJECT_KEYS` is an explicit override and should normally remain
  unset for production

Example MVP settings:

```bash
KATA_SN60_PROJECT_KEYS=
KATA_SN60_PROJECT_SAMPLE_SIZE=12
KATA_SN60_PROJECT_SAMPLE_SECRET=<private-validator-secret>
KATA_SN60_REPLICAS_PER_PROJECT=1
KATA_SN60_SCREENING_EXECUTION_TIMEOUT_SECONDS=300
```

### 4. Promotion Gate

A candidate promotes only if all conditions pass:

- screening passed
- candidate strictly beats the king by rank
- the result is fresh against the current king and benchmark state

The rank comparator is:

1. detection score
2. true positives
3. precision
4. F1 score
5. fewer invalid/error evaluations

Same score and same tie-breakers are not enough; the candidate must strictly
beat the current king.

Detection score follows the SN60 scorer signal:
`total_true_positives / total_expected_vulnerabilities`.

Metric meanings:

- `true positives`: benchmark vulnerabilities the agent correctly found.
- `precision`: how many reported findings were real matches,
  `true_positives / total_found`.
- `F1 score`: balance between detection score and precision.
- `invalid/error evaluation`: the sandbox or scorer could not produce a valid
  successful evaluation for that project. It contributes zero metrics and hurts
  tie-breaks.

Sandbox `PASS` still means a project run found all expected vulnerabilities.
PASS project count is useful context, but it is not the primary promotion score.

## PR Decision Actions

Kata returns one action:

- `merge` means the candidate beat the current king and passed freshness checks.
- `close-losing` means the candidate evaluated correctly but did not beat the
  king.
- `close-invalid` means the bundle or PR shape is invalid.
- `rerun-stale` means the king, benchmark, or submission changed during
  evaluation.
- `hold-merge` is used by the bot when GitHub mergeability blocks an otherwise
  winning PR.

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
2. merges the PR
3. publishes the candidate bundle under `kings/<subnet-pack>/<mode>/`
4. updates lane king state
5. clears the merged submission directory from `main`

This keeps `submissions/` empty between active PRs while `kings/` remains the
public source of truth for the current best agent.

## Engine Contribution Workflow

Engine contributions should preserve evaluator integrity and provenance.

1. Identify the affected area:
   - submission contract: `kata/submissions.py`, `kata/screening.py`
   - evaluator adapter: `kata/evaluators/`
   - challenge and promotion logic: `kata/challenge.py`
   - lane state schemas: `kata/lane_state.py`
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
