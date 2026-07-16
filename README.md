<p align="center">
  <img src="assets/hero.png" alt="Kata — an objective competition engine for autonomous AI agents" width="100%">
</p>

<h1 align="center">Kata</h1>

<p align="center"><b>An objective, pull-request-based competition engine for autonomous AI agents.</b></p>

<p align="center">
  <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT">
  <img src="https://img.shields.io/badge/python-3.12+-blue.svg" alt="Python 3.12+">
  <img src="https://img.shields.io/badge/built%20with-Gittensor%20(SN74)-2f6bff.svg" alt="Built with Gittensor (SN74)">
</p>

## Built with Gittensor (Bittensor Subnet 74)

Kata's development is coordinated by Gittensor, the open-source-software subnet on
Bittensor (Subnet 74, "SN74"). This repository is registered on Gittensor, which
coordinates and rewards the people who build and improve Kata. You do not need to use
Bittensor, join a Discord, or understand SN74 to use or contribute to Kata. SN74 funds the
*development of this repo*. It is separate from the subnets Kata builds agents *for* (the
"targets" below).

---

## What Kata is

Kata builds the best AI agent for a subnet through open competition, so anyone can mine
that subnet with a proven agent.

Mining a subnet well usually takes deep, subnet-specific expertise. Kata crowdsources it.
Contributors compete to build the strongest agent for a target subnet, and Kata keeps the
current best one, called the **king**. The king is scored against every new challenger, so
it stays the strongest agent on the benchmark.

The point is objectivity. A challenger wins by beating the king on a fixed benchmark, not
by a reviewer's opinion or the size of the pull request. Agent quality becomes a merge
decision that anyone can reproduce.

## King of the hill, in scheduled rounds

Kata runs a "king of the hill" tournament, but not one duel per pull request. Scoring
happens in **scheduled rounds**.

1. A contributor opens a pull request that adds exactly one agent.
2. Intake screens the PR and marks it as a pending entrant. No scoring yet.
3. On a schedule, a round runs. It locks the pending entrants and scores the king once,
   then scores every candidate against that same fresh king score on the same secretly
   sampled problems.
4. The candidates are ranked. The top one that beats the king is merged and becomes the
   new king.

Because the king is re-scored fresh every round, a candidate is always measured against
the king on the exact problems the king just faced.

New here? To compete, jump to [How to submit an agent](#how-to-submit-an-agent). To
understand the process, read [docs/workflow.md](docs/workflow.md).

## Targets

A "target" is a subnet Kata builds an agent for. Each target has its own benchmark,
execution environment, scoring rules, and current king. Today Kata runs one target: SN60
(`sn60__bitsec`), where agents find critical and high-severity vulnerabilities in
smart-contract code. The scoring rules for that target live in its own repo, `kata-sn60`.
The core engine in this repo does not know what any target does.

---

## Architecture

Kata is a small set of repos, each with one job.

| Repo | Role |
| --- | --- |
| **kata** | The engine (this repo). Submission format, validation, screening, the round loop that scores the king and candidates, ranking, and promotion. Knows nothing about any specific subnet. |
| **kata-bot** | GitHub automation. Intake (screen PRs into pending, review, or invalid), the round runner that scores the pending PRs, and the service that merges and promotes a round winner. Applies the PR labels. |
| **kata-sn60** | The SN60 subnet plugin. The task, benchmark, execution contract, scorer, and the exact "beats the king" rules for the `sn60__bitsec` target. |
| **kata-board** | Dashboard. Reads current king state, the live round, and the round-history feed. |
| **kata-tee-runner** | Sealed-room execution. Runs a candidate agent inside an attested, miner-paid confidential VM when a target asks for it. |
| **sandbox** | Pinned benchmark harness (agent runner plus scorer) for a target. Version-locked and never edited by Kata. |

A subnet plugin bundles everything subnet-specific behind one interface, the
`SubnetPlugin` contract in `kata/plugins/contract.py`. The core resolves a plugin by
evaluator id and calls only that contract, so adding a subnet is a new plugin, not a core
change. Each plugin lives in its own repo (for example `../kata-sn60`) and registers
through the `kata.subnets` entry-point group.

### Core package layout

```text
kata/
  cli.py          command-line entry point
  core/           subnet-neutral round orchestration
  plugins/        the SubnetPlugin contract, discovery, and registry
  submissions/    bundle layout, validation, workflow, rendering
  screening/      shared anti-cheat checks and plugin screening dispatch
  promotion/      verified king publication
  state/          lane, artifact, and live-progress persistence
```

---

## The competition loop

Scoring runs in scheduled rounds, not per PR. Opening a PR enters you as a pending
entrant; a round scores every pending entrant at once. In outline:

```text
PR opened or pushed
  └─ intake: screen ─▶ label kata:pending   (no scoring yet)

scheduled round:
  lock pending PRs
    └─ one per contributor, execution gate ─▶ label kata:executing
       └─ score the king once, then every candidate against that same king score
          on the same secretly sampled problems
          └─ rank ─▶ top candidate that beats the king ─▶ merge + promote new king
```

The core samples the problems, scores the king once, scores each candidate, and ranks them
with the plugin's comparator. What "beats the king" means is decided by the subnet plugin:
it scores the king and every candidate on the same sampled problems and applies its own
rule. See that subnet's repo for the actual rule, for example [`../kata-sn60`](../kata-sn60).

The full PR-to-promotion process, including intake labels and round outcomes, is in
[docs/workflow.md](docs/workflow.md).

---

## How to submit an agent

You only ever edit `submissions/`. A submission is a small bundle:

```text
submissions/<subnet-pack>/miner/<submission-id>/
  agent.py            # your entrypoint: def agent_main(...) -> {"vulnerabilities": [...]}
  agent_manifest.json # bundle contract (schema_version, runtime, entrypoint)
  submission.json      # target pack, mode, author, and submission id
```

The submission id must be `<github-username>-YYYYMMDD-NN`, and the username must be the
GitHub account that opens the PR. Each contributor may have only one open PR at a time.

```bash
# 1. scaffold a submission
uv run kata submission init \
  --subnet-pack sn60__bitsec --mode miner \
  --submission-id <your-github-username>-20260716-01 \
  --author <your-github-username>

# 2. edit submissions/sn60__bitsec/miner/<your-github-username>-20260716-01/agent.py

# 3. validate it locally before opening a PR
uv run kata submission validate \
  --path submissions/sn60__bitsec/miner/<your-github-username>-20260716-01

# 4. commit on a branch, push, and open one PR against the default branch
```

If the CLI says the `sn60__bitsec/miner` target is not registered, run the command from
the top-level Kata repo with `KATA_ROOT="$(pwd)"`.

The full submission contract, the required files, and the anti-cheat rules are in
[docs/submissions.md](docs/submissions.md). Task-specific details (the report your agent
must produce, inference, and any timing limits) live in the subnet repo, for example
[`../kata-sn60`](../kata-sn60).

Build an agent that analyzes the code it receives. General reusable analysis is allowed.
Hardcoded benchmark-answer replay is not: do not embed known project fingerprints, known
findings, or prewritten answers for specific benchmark projects.

---

## Contributing to the engine

Improvements to the engine, the contributor workflow, or the competition machinery are
welcome. Local checks:

```bash
uv run --extra dev python -m pytest
uv run --extra dev python -m ruff check kata tests
```

Guidelines and what-belongs-where: [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Repository layout

- `kata/` — the engine: submissions, screening, core round, state, promotion, plugins, CLI.
- `lanes/` — registry and state for the registered competition targets.
- `kings/` — the published current king artifact per target and mode. This is the public
  source of truth for the best promoted agent.
- `submissions/` — PR-submitted candidate bundles. A merged winner's bundle is cleared once
  it becomes the king.
- `runs/` — round artifacts with reproducible provenance. Gitignored, not committed.

## License

MIT — see [LICENSE](LICENSE).
