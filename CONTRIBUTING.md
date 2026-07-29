# Contributing to Kata

Kata is an objective, subnet-agnostic agent-competition framework: contributors compete
to build the strongest agent for a target subnet, and Kata keeps the current best one
(the **king**). Contributions should make the evaluator, submission workflow, or competition
machinery more trustworthy and more useful.

This repository is the **engine**. It knows how to run a competition; it knows nothing about what
any particular subnet's task is, how it is scored, or what an agent there is allowed to do. All of
that lives in that subnet's own plugin repository, and it belongs there — a rule restated here is a
second copy that drifts from the one that owns it.

**Entering a competition is different from contributing to the framework.** If you are here to
submit an agent, everything you need is in the [README](README.md): open a
PR under your subnet's directory, one open PR per subnet per contributor, one subnet per PR. The
rest of this document is about changing Kata itself.

## ⚡ Built with Gittensor (Bittensor Subnet 74)

**This repository is developed and maintained through Gittensor — the open-source-software
subnet on Bittensor, Subnet 74 (SN74).** Kata is registered on Gittensor, which
coordinates and rewards the people who build and improve it. If you contribute here, your
work is part of Gittensor / SN74 — you don't need to use Bittensor or Discord to take
part, but it's how this project is powered and how contributors get credit.

> Keep the subnets straight: **SN74 / Gittensor** powers the *development of this repo*; the
> competition targets Kata runs lanes for are separate subnets with their own repositories.

## Principles

- Keep evaluation deterministic and reproducible wherever possible.
- Treat evaluator correctness as higher priority than artifact style.
- Preserve provenance (sandbox commit, benchmark snapshot hashes) so results
  stay comparable over time.
- Never weaken submission validation, screening, or promotion checks without
  a test proving the new behavior.
- Keep subnet policy out of the engine. If the engine needs to know something subnet-specific, the
  subnet declares it and the engine reads it as data — see [Subnet policy is data](#subnet-policy-is-data).

## Local checks

```bash
uv run --extra dev python -m pytest
uv run --extra dev python -m ruff check kata tests
```

If you change plugin, screening, promotion, or submission logic, add or update tests.

For the miner PR lifecycle, evaluation stages, and promotion flow, see
[How Kata works](README.md#how-kata-works).

## What belongs where

- Command line facade and handlers: `kata/cli/`
- Generic challenge evaluation and ranking: `kata/core/challenge.py`
- Plugin contract, discovery, and registry: `kata/plugins/`
- Submission bundle, repository preflight, and PR workflow: `kata/submissions/`
- Shared screening and anti-cheat dispatch: `kata/screening/`
- Promotion and public king publication: `kata/promotion/`
- Lane, artifact, and live-progress persistence: `kata/state/`
- Evaluator-specific logic, task definitions, scoring, and screening rules: the subnet's own
  plugin repository — never here

Miner submissions belong under `submissions/` via PR, not in engine code.

## Subnet policy is data

The engine must not carry a table of subnet names. It did once, and getting the table wrong
rejected every valid submission for one subnet while the tests stayed green.

Anything that varies per subnet is **declared by that subnet** in its `deploy/settings.json` and
published into this repository as `submissions/policies.json`, which the preflight gate reads. The
gate applies whatever it is told and fails closed on anything it cannot read or does not recognise:
an undeclared pack gets the strictest known rule, and an unreadable policy document is a refusal to
check rather than a pass.

Regenerate the published document with:

```bash
uv run python installer/generate_submission_policies.py   # in kata-subnets-deploy
```

Never hand-edit `submissions/policies.json`. It is generated, and a hand edit makes this repository
disagree with the subnet whose contract it describes.

## Public surfaces

Everything another project may depend on. A refactor may move code freely *behind* this list; it may
not change an entry here without changing every consumer named beside it.

**Console script** — `kata` → `kata.cli:main`

**Repository submission preflight** — branch protection and contributor documentation invoke
`python -m kata.submissions.preflight`. It must stay dependency-free: CI runs it on a bare Python
with no install step, and checks out only this repository, so no plugin is importable when it runs.

**CLI subcommands** — `bootstrap`, `capacity-estimate`, `challenge`, `init`, `inspect-pr`, `king`,
`lane`, `list`, `plugin`, `preflight`, `promote`, `submission`, `sync-registry`, `validate`.

`kata challenge` is the engine entry point kata-bot invokes as a subprocess. Its stdout JSON is a
cross-project contract; `tests/test_cli_surface_golden.py` freezes the parser's structure so a
renamed flag or a changed default cannot reach a separately deployed consumer unnoticed.

**Plugin discovery** — subnets are discovered through the **`kata.subnets`** entry-point group. Each
subnet package declares one entry pointing at its `SubnetPlugin`. The group name and the
`SubnetPlugin` base class are the contract; renaming either breaks every subnet repository, and they
are versioned and deployed independently.

**Environment variables**

| Variable | Meaning |
| --- | --- |
| `KATA_ROOT` | root of the competition tree (`lanes/`, `kings/`, `submissions/`, `runs/`) |
| `KATA_LIVE_STATUS_PATH` | where live challenge status is written |
| `KATA_SCREENING_REVIEW_MODE` | screening policy selector |
| `KATA_SCREENING_STRICT_REPLAY` | strict replay for recorded screening |
| `KATA_VALIDATOR_API_BASE`, `KATA_VALIDATOR_API_KEY`, `KATA_VALIDATOR_MODEL` | optional LLM review |

**File formats and paths** — written under `KATA_ROOT`, read by the bot and the board:

| Path | Owner |
| --- | --- |
| `lanes/registry.json` | lane registry the board reads |
| `lanes/<lane>/lane.json` | per-lane public record, incl. `active` |
| `lanes/<lane>/king.json` | king ledger (`seeded` marks an unearned first king) |
| `kings/<pack>/<mode>/` | king artifact bundle |
| `submissions/<pack>/<mode>/<id>/` | miner submission bundle |
| `submissions/policies.json` | generated per-subnet submission policy the preflight gate reads |
| `runs/<run-id>/challenge_result.json` | challenge result JSON |

`live-status.json` is written by **kata-bot**, not by this engine. `kata/state/progress.py` is an
engine-side writer with no caller; it is retained because `KATA_LIVE_STATUS_PATH` is still exported
into the child process and the function merges rather than overwrites. See that module's docstring.

No network endpoints are served.

## Out of scope

- weakening anti-cheat validation
- unpinning the sandbox or benchmark snapshot without a provenance story
- broad artifact rewrites without evaluation evidence
- teaching the engine about a specific subnet
