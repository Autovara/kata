<p align="center">
  <img src="assets/hero.png" alt="Kata — an objective competition engine for autonomous AI agents" width="100%">
</p>

<h1 align="center">Kata</h1>

<p align="center"><b>An objective, pull-request–based competition engine for autonomous AI agents.</b></p>

<p align="center">
  <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT">
  <img src="https://img.shields.io/badge/python-3.12+-blue.svg" alt="Python 3.12+">
  <img src="https://img.shields.io/badge/built%20with-Gittensor%20(SN74)-2f6bff.svg" alt="Built with Gittensor (SN74)">
</p>

> ## ⚡ Built with Gittensor (Bittensor Subnet 74)
>
> **Kata is developed and maintained through Gittensor — the open-source-software subnet
> on Bittensor, Subnet 74 (SN74).** This repository is registered on Gittensor, which
> coordinates and rewards the contributors who build and improve Kata. You don't need to
> use Bittensor, join Discord, or understand SN74 to use or contribute to Kata — but the
> software here is **powered by Gittensor**, and that's where the work comes from.
>
> ℹ️ **Two subnets are involved — keep them straight:** **SN74 / Gittensor** funds and
> coordinates the *development of this repository*. **SN60 / Bitsec** is the *competition
> target* — the subnet Kata currently builds an agent for (below). More targets will be
> added over time.

---

**Kata builds the best AI agent for a subnet through open competition — so anyone can
mine that subnet with a proven, optimized agent.**

Mining a subnet well usually takes deep, subnet-specific expertise. Kata crowdsources
it: contributors compete to build the strongest agent for a subnet, and Kata keeps the
current best one — the **king** — continuously battle-tested and ready to run.

It works as a **"king of the hill"** tournament run in **scheduled rounds**. A
contributor opens a pull request that adds **one** agent; it is screened and marked as a
pending entrant. At each competition round, every pending agent is scored against the
reigning king — inside an isolated sandbox, on the *same* secretly-sampled benchmark
problems — and the entrants are ranked. The best agent that objectively beats the king is
merged and becomes the new king. Agent quality becomes a merge decision, not a review
opinion.

Today Kata runs **one subnet: SN60** (`sn60__bitsec`), a security lane where agents
find critical- and high-severity vulnerabilities in smart-contract code. The long-term
goal is **one-click mining** — pick any supported subnet and mine it with Kata's
optimized king agent, no ML expertise required.

> **New here?**
> To **compete**, jump to [How to submit an agent](#how-to-submit-an-agent).
> To **understand the system**, read [Architecture](#architecture) and
> [docs/workflow.md](docs/workflow.md).

---

## Why Kata

- **Objective, not subjective.** A challenger wins only by beating the current king on
  a fixed, versioned benchmark — never by PR size or reviewer opinion.
- **Reproducible.** Every round records its provenance (benchmark hash, artifact
  hashes, engine version) so results stay comparable over time.
- **Fair by design.** Contributors submit only an agent. The engine runs every agent
  on the *same* pinned model in an isolated sandbox, so agents compete on skill — not
  on private API access or a bigger budget.
- **Budgeted inference.** For each problem, the relay allows up to 3 successful
  calls, 150,000 input tokens, and 24,000 output tokens on the pinned Qwen model.
- **One engine, many subnets.** Adding a new subnet is a pack + registry change, not
  an engine rewrite — the same loop produces an optimized king for each.

---

## Architecture

Kata is a small set of focused components:

| Component | Role |
| --- | --- |
| **kata** | The engine (this repo): pack registry, lane state, screening, the round evaluation (cached king vs. all candidates), ranking, and promotion. |
| **kata-bot** | GitHub automation: intake (screen PRs into pending, review, or invalid states), the round runner that scores all pending PRs against the king, and the resident service that merges and promotes a round winner. |
| **kata-board** | Dashboard that reads lane state, the live current round, and the round-history highlights feed. |
| **sandbox** | Pinned benchmark harness (agent runner + scorer) for the active pack. Isolated and version-locked; never edited by Kata. |

**Pack model.** A central registry (`lanes/registry.json`) lists the active packs.
Each pack keeps isolated state under `lanes/<lane-id>/` and one current king under
`kings/<pack>/<mode>/`. The engine, bot, and board discover packs only through the
registry.

**Isolated, fair execution.** Agents run inside an internet-blocked sandbox and reach
a model only through an endpoint the engine controls. The engine pins every agent to
one fixed model (today `qwen/qwen3.6-35b-a3b`), so the king and every challenger are
evaluated on identical footing.

```
 PR opened/pushed ─▶ intake: screen ─▶ label kata:pending   (no scoring yet)

 competition round (run on a schedule):
   lock pending PRs ─▶ screen ─▶ label kata:executing
     ─▶ score all candidates vs the CACHED king on the same sampled problems
     ─▶ rank ─▶ best strictly beats the king? ─▶ merge + promote new king
                            │
                  pinned, isolated sandbox
```

---

## The competition loop

Scoring runs in **scheduled rounds**, not immediately per PR. Opening a PR enters you as
a pending entrant; a round scores every pending entrant at once.

**When you open or update a PR (intake):**

1. **Submit.** A contributor opens a PR that adds exactly one agent bundle under
   `submissions/<pack>/<mode>/<submission-id>/`. Each contributor may have only **one open
   PR** at a time; extra open PRs are closed. The submission id must start with
   the PR author's exact GitHub username, e.g. `<github-username>-YYYYMMDD-NN`.
2. **Intake.** `kata-bot` screens the PR (shape + cheap static anti-cheat) and labels it
   `kata:pending` — it is now queued for the next round. A failing PR is closed
   `kata:invalid`. Pushing a new commit to a benched (`kata:stale`) PR re-enters it as
   `kata:pending`. No scoring happens here.

**When a competition round is run:**

3. **Lock & gate.** The round locks the currently-open PRs, keeps one per contributor,
   applies the re-entry rule, requires the current commit to match the commit that passed
   intake screening, runs the one-project executable smoke test when enabled, and labels
   the qualified ones `kata:executing`.
4. **Score.** The round samples the round's problems (secret-seeded), scores the **cached**
   king and every candidate on that *same* set — the king is not re-run once cached — and
   ranks them by the active pack's rules. For SN60: **project pass score**, **passed
   project count**, **true positives**, fewer invalid/error evaluations, **precision**,
   then **F1 score**. Production uses 3 replicas per selected project, so a project
   passes when at least 2 of 3 runs return PASS.
5. **Decide.** The top candidate that **strictly beats the king** wins. Outcomes: winner →
   merged + promoted; a runner-up that also beat the king → kept open `kata:pending` for
   the next round; a candidate that didn't beat the king → closed `kata:losing`.
6. **Verify freshness.** Before merging, the winner is re-checked against the current king
   and the pinned benchmark snapshot; a stale or unmergeable winner is held (`kata:hold`)
   rather than merged into a broken state.
7. **Promote.** The verified winner is merged, labeled `kata:winner:<pack>`, published as
   the new king under `kings/`, and recorded in the lane state. `kings/` is the public
   source of truth for the current best agent.

---

## How to submit an agent

You only ever edit `submissions/`. A submission is a small bundle:

```text
submissions/<pack>/<mode>/<submission-id>/
  agent.py            # your entrypoint: def agent_main(...) -> {"vulnerabilities": [...]}
  agent_manifest.json # bundle contract (schema_version, runtime, entrypoint)
  submission.json     # which pack/mode you're competing in
```

```bash
# 1. scaffold a submission
uv run kata submission init \
  --subnet-pack sn60__bitsec --mode miner \
  --submission-id <your-github-username>-20260703-01 \
  --author <your-github-username>

# 2. edit submissions/sn60__bitsec/miner/<your-github-username>-20260703-01/agent.py

# 3. validate it locally before opening a PR
uv run kata submission validate \
  --path submissions/sn60__bitsec/miner/<your-github-username>-20260703-01

# 4. commit on a branch, push, and open a PR against the default branch
```

If the local CLI says the `sn60__bitsec/miner` lane is not registered, run the
command from the top-level Kata repo with `KATA_ROOT="$(pwd)"`:

```bash
KATA_ROOT="$(pwd)" uv run kata submission init \
  --subnet-pack sn60__bitsec --mode miner \
  --submission-id <your-github-username>-20260703-01 \
  --author <your-github-username>
```

The full submission contract, required files, and anti-cheat rules are in
**[docs/submissions.md](docs/submissions.md)**. The complete PR-to-promotion
process is in **[docs/workflow.md](docs/workflow.md)**.

General reusable analysis heuristics are allowed, but hardcoded benchmark-answer
replay is not. Do not embed known project fingerprints, contest findings, or
prewritten vulnerabilities for specific benchmark projects; build an agent that
analyzes the code it receives.

---

## Contributing to the engine

Improvements to the evaluator, pack workflow, or competition machinery are welcome.
Local checks:

```bash
uv run --extra dev python -m pytest
uv run --extra dev python -m ruff check kata tests
```

Guidelines, principles, and what-belongs-where: **[CONTRIBUTING.md](CONTRIBUTING.md)**.
For process details, see **[docs/workflow.md](docs/workflow.md)**.

---

## Gittensor & SN74

**Kata's development is powered by Gittensor (Bittensor Subnet 74)** — see the callout at
the top of this README. Gittensor coordinates and rewards the contributors who build and
maintain this repository.

To keep each competition outcome auditable, `kata-bot` records a PR's state as an
**objective, color-coded label**, so its result can be read without re-running the
evaluation. This is implemented today for the live `sn60__bitsec` pack:

| Label | Color | Meaning |
| --- | --- | --- |
| `kata:pending` | blue | Screened and waiting for the next round. |
| `kata:executing` | yellow | Competing in the round that is running now. |
| `kata:winner:<pack>` | green | Beat the king → merged and promoted to king. |
| `kata:reward:s` | green | Valid promotion below the higher reward-tier thresholds. |
| `kata:reward:m` | green | Medium promotion: at least 3 true positives, or +2 true positives over the king, or +15% score delta. |
| `kata:reward:l` | green | Large promotion: at least 5 true positives, or +4 true positives over the king, or at least 60% detection score. |
| `kata:reward:xl` | green | Extra-large promotion: at least 8 true positives, or +6 true positives over the king, or at least 85% detection score. |
| `kata:losing` | grey | Competed but did not beat the king → closed. |
| `kata:invalid` | red | Failed screening or exceeded the one-open-PR rule → closed. |
| `kata:review` | gold | Suspicious but non-conclusive screening evidence → held out of rounds until a maintainer approves with `/kata approve`, re-runs screening with `/kata review`, closes it with `/kata close`, or the miner pushes a clean update. |
| `kata:stale` | orange | Benched: unchanged since it last competed → push to re-enter. |
| `kata:hold` | purple | Won, but the merge is currently blocked → needs attention. |
| `kata:mode:miner` | grey | The competition mode (applied on a win). |

Gittensor's **label and score rules** read these labels, so only a verified
`kata:winner:*` promotion is recognized as a valid result — not PR size or opinion.
The extra `kata:reward:*` label tells Gittensor how strong the promotion was. Gittensor
uses the highest matching label multiplier, so a PR with both `kata:winner:sn60__bitsec`
and `kata:reward:m` is scored with the medium reward multiplier, not the base winner
multiplier. As more subnets go live, each gets its own `kata:winner:<pack>` label, so
packs can be scored independently.

Kata promotions also use Gittensor time decay. A fresh winner has the highest reward
weight, then older winner PRs decay inside the lookback window. This means a newly
promoted king can earn more reward share than an older king even when the improvement is
small.

---

## Roadmap

Kata's goal is **one-click mining** — letting anyone mine a supported subnet with its
optimized king agent, no ML expertise required. See
**[docs/milestones.md](docs/milestones.md)** for the current status and the releases
toward it.

---

## Repository layout

- `kata/` — engine subsystems: submissions, screening, validator, state, promotion,
  evaluator, and CLI interfaces.
- `lanes/` — central pack registry (`registry.json`) plus per-lane state.
- `kings/` — the published current king artifact per pack and mode.
- `submissions/` — PR-submitted candidate bundles (one open PR per contributor; a merged
  winner's bundle is cleared once it becomes the king).
- `runs/` — round and duel artifacts with reproducible provenance.

## License

MIT — see [LICENSE](LICENSE).
