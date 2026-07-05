# Contributing to Kata

Kata is an objective, subnet-agnostic agent-competition framework: contributors compete
to build the strongest agent for a target subnet, and Kata keeps the current best one
(the **king**). Contributions should make the evaluator, pack workflow, or competition
machinery more trustworthy and more useful. The framework runs one competition lane
today — **SN60 / Bitsec** (`sn60__bitsec`) — and is designed to add more.

## ⚡ Built with Gittensor (Bittensor Subnet 74)

**This repository is developed and maintained through Gittensor — the open-source-software
subnet on Bittensor, Subnet 74 (SN74).** Kata is registered on Gittensor, which
coordinates and rewards the people who build and improve it. If you contribute here, your
work is part of Gittensor / SN74 — you don't need to use Bittensor or Discord to take
part, but it's how this project is powered and how contributors get credit.

> Keep two subnets straight: **SN74 / Gittensor** powers the *development of this repo*;
> **SN60 / Bitsec** is the current *competition target* that Kata builds an agent for.

## Principles

- Keep evaluation deterministic and reproducible wherever possible.
- Treat evaluator correctness as higher priority than artifact style.
- Preserve provenance (sandbox commit, benchmark snapshot hashes) so results
  stay comparable over time.
- Never weaken submission validation, screening, or promotion checks without
  a test proving the new behavior.

## Local checks

```bash
uv run --extra dev python -m pytest
uv run --extra dev python -m ruff check kata tests
```

If you change the evaluator adapter, screening, or promotion logic, add or
update tests.

For the full miner PR lifecycle, evaluation stages, promotion flow, and engine
contribution workflow, see `docs/workflow.md`.

## What belongs where

- Engine changes: `kata/`
- Lane and registry state schemas: `kata/lane_state.py`
- Evaluator adapters: `kata/evaluators/`
- Submission contract and validation: `kata/submissions.py`, `kata/screening.py`

Miner submissions belong under `submissions/` via PR, not in engine code.

## Out of scope

- weakening anti-cheat validation
- unpinning the sandbox or benchmark snapshot without a provenance story
- broad artifact rewrites without evaluation evidence
