# Bot Integration Contract

Kata is the evaluation engine. GitHub-specific automation should live in a
separate bot repo.

## Repo Boundary

- `Kata`
  - owns validation, evaluation, scoring, freshness checks, and decision logic
- `kata-benchmarks`
  - owns benchmark packs and frontier state
- `kata-bot`
  - owns PR event handling, comments, close/merge actions, retries, and secrets

## What The Bot Calls

The bot should call Kata through these commands:

1. `submission inspect-pr`
2. `submission validate`
3. `submission evaluate`
4. `submission verify`
5. `submission decide`
6. `frontier promote`

## Expected Sequence

For each miner PR, the bot should do this:

1. inspect changed paths before checking out untrusted PR content
2. close immediately if the diff is not a valid submission PR or it targets an
   inactive repo-pack
3. validate the checked-out submission contents
   This includes checking that `agent.py` is real, defines `solve(...)`,
   and does not fail anti-cheat bundle policy.
4. evaluate the challenger against the current frontier lane
5. verify the result is still fresh
6. collapse the outcome to a simple action
7. rerun once if the result is stale
8. close the PR if it loses
9. promote the frontier and merge the PR if it wins

## Why The Bot Is Separate

- Kata stays clean as the engine
- GitHub event handling stays out of the scoring code
- secrets and deployment config stay out of the core repo
- the same engine can be reused by other automation later

## Runner Requirements

The bot runner should already have:

- Python and `uv`
- a checked-out Kata repo
- a checked-out `kata-benchmarks` repo
- the chosen agent runner installed
- read access to the benchmark repo
- write access to the benchmark repo if winners auto-promote

If using the challenger-agent path, the runner also needs validator-owned LLM
settings available through env vars such as:

- `KATA_VALIDATOR_MODEL`
- `KATA_VALIDATOR_API_BASE`
- `KATA_VALIDATOR_API_KEY`

Current default validator model:

- `Qwen3-32B`

## Safety Notes

- inspect PR scope before evaluating untrusted PR content
- treat `kata-benchmarks` as the source of truth frontier state
- rerun stale evaluations before merge if the frontier changed
- keep miner submissions away from direct model/provider override
