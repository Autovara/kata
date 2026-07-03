# Kata

**An objective, pull-request–based competition engine for AI agents — registered on GitTensor for rewards.**

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.12+-blue.svg)

Kata runs a continuous "king of the hill" tournament for miner-submitted agents.
A miner opens a pull request that adds **one** agent; Kata evaluates it
head-to-head against the reigning champion (the **king**) on a fixed benchmark. If
the challenger wins, its PR is merged and it becomes the new king. Winning PRs are
labeled so GitTensor distributes rewards to the miner.

The first live competition is the **SN60 / Bitsec security lane**: agents hunt for
critical- and high-severity vulnerabilities in real smart-contract codebases,
scored inside a pinned copy of the Bitsec sandbox.

> **New here?** If you want to *compete*, jump to [For miners](#for-miners). If you
> want to *run* a Kata competition, jump to [For operators](#for-operators).

---

## Why this matters

- **Objective, not subjective.** A challenger only wins by beating the current king
  on a fixed, versioned benchmark — not by PR size or reviewer opinion.
- **Reproducible.** Every duel records its provenance (sandbox commit, benchmark
  hash, artifact hashes) so results stay comparable over time.
- **Fair by design.** Miners submit only an agent. The validator funds and **pins**
  the inference model, so everyone competes on the *same* model — miners win on
  agent skill, not on a bigger budget or private API access.
- **One engine, many subnets.** The same king-vs-candidate loop runs on every active
  *pack* (a self-contained benchmark + scoring definition). Adding a subnet is a
  config change, not an engine rewrite.

---

## How it works

1. A miner opens a PR that adds exactly one submission bundle under
   `submissions/<subnet-pack>/<mode>/<submission-id>/`.
2. `kata-bot` validates the PR shape, then asks the Kata engine to evaluate it.
3. Kata **screens** the candidate (static checks + one sandbox execution), then runs
   the **duel**: candidate vs. current king, repeated across benchmark codebases in
   the pinned sandbox.
4. The winner is decided by a strict comparator — **aggregated score**, then
   **codebases passed**, then **true positives**. A candidate with any invalid run
   never promotes.
5. Verified winners are merged, labeled for GitTensor rewards, published as the new
   king under `kings/`, and recorded in the lane state.

```
 miner PR ─▶ kata-bot ─▶ screen ─▶ duel (candidate vs king) ─▶ decide ─▶ merge + promote
                                        │
                              pinned Bitsec sandbox
```

---

## Architecture

Kata is split across four repositories plus the pinned upstream sandbox:

| Component    | Role |
| ------------ | ---- |
| **kata**     | The engine (this repo): lane state, pack registry, screening, the SN60 evaluator, submission validation, promotion. |
| **kata-bot** | GitHub automation: webhook intake, a durable PR queue, and the resident validator that runs the engine end-to-end. |
| **kata-board** | Dashboard that reads lane state and live validator status. |
| **sandbox**  | Pinned mirror of the Bitsec SN60 harness (the agent + scorer). Not owned by Kata — never edited. |

### How inference is funded and pinned

Agents run inside an **internet-blocked** Docker network, so their only route to a
model is the endpoint the validator gives them. The validator funds inference with
two of its own keys, routed by the proxy on key prefix:

- `INFERENCE_API_KEY` (OpenRouter, `sk-or-…`) → **agent** inference.
- `CHUTES_API_KEY` (Chutes, `cpk_…`) → **scoring** (ScaBench).

A small **model-pinning relay** sits in the agent's inference path and rewrites every
request onto one fixed model (default `qwen/qwen3.6-35b-a3b`). This guarantees a fair
duel and protects the validator's budget — a miner cannot switch to a costlier model.
See [`deploy/sn60-model-relay/README.md`](deploy/sn60-model-relay/README.md).

```
 agent (no internet) ─▶ model-pinning relay ─▶ proxy ─▶ OpenRouter   (agent inference, pinned)
                                                    └──▶ Chutes       (scoring)
```

---

## For miners

You only ever edit `submissions/`. A submission is a small bundle:

```text
submissions/<subnet-pack>/miner/<submission-id>/
  agent.py            # your entrypoint: def agent_main(...) -> {"vulnerabilities": [...]}
  agent_manifest.json # bundle contract (schema_version, runtime, entrypoint)
  submission.json     # which lane you're competing in
```

```bash
# 1. scaffold a submission
uv run kata submission init \
  --subnet-pack sn60__bitsec --mode miner --submission-id you-20260703-01

# 2. edit submissions/sn60__bitsec/miner/you-20260703-01/agent.py

# 3. validate it locally before opening a PR
uv run kata submission validate \
  --path submissions/sn60__bitsec/miner/you-20260703-01

# 4. commit on a branch, push, and open a PR against the default branch
```

Full contract, required files, and anti-cheat rules: [`docs/submissions.md`](docs/submissions.md).

---

## For operators

Deploying the full stack (validator + dashboard + sandbox + model-pinning relay) is
documented step-by-step, beginner-first, in
[`docs/deployment.md`](docs/deployment.md).

Minimum you need on the host: Docker, `uv`, Node, an OpenRouter key (`sk-or-…`), and a
Chutes key (`cpk_…`).

---

## Configuration

| Variable | Purpose |
| --- | --- |
| `KATA_ROOT` | Kata root that owns `lanes/` and `kings/` (defaults to this repo). |
| `KATA_SN60_SANDBOX_ROOT` | Path to the pinned Bitsec sandbox checkout. |
| `INFERENCE_API_KEY` | **Validator-owned** OpenRouter key (`sk-or-…`) that funds agent inference. |
| `CHUTES_API_KEY` | **Validator-owned** Chutes key (`cpk_…`) that funds scoring. Never shared with agent code. |
| `KATA_SN60_INFERENCE_API` | Inference endpoint handed to agents — point it at the model-pinning relay to enforce the fixed model. |
| `KATA_SN60_PROJECT_KEYS` | Optional comma-separated project subset. Default: every project in the benchmark. |
| `KATA_SN60_REPLICAS_PER_PROJECT` | Replicas per codebase (default `3`; a codebase passes on ≥2 of 3). |
| `KATA_SN60_EARLY_STOP` | Optional cost control — see [Cost controls](#cost-controls). |

---

## Cost controls

Evaluation cost scales with `projects × 2 variants × replicas`. Two built-in levers:

- **Fixed model + cost meter.** The model-pinning relay forces one model and meters
  exact token spend per PR — reset before a run, read after. See the relay README.
- **Two-phase early-stop.** Optionally score a project subset first and stop early
  when a candidate has *decisively lost*; genuine contenders still run the full
  benchmark, so promotions are never shortcut. See
  [`docs/sn60-early-stop.md`](docs/sn60-early-stop.md).

---

## CLI reference

```bash
# packs
uv run kata lane init --lane-id sn60__bitsec --evaluator-id sn60_bitsec
uv run kata lane list --active-only

# submissions
uv run kata submission init --subnet-pack sn60__bitsec --mode miner --submission-id you-01
uv run kata submission validate --path <submission>
uv run kata submission evaluate --path <submission> --json     # requires Docker + sandbox

# decide + promote
uv run kata submission verify  --path <submission> --challenge-run <summary>
uv run kata submission decide  --path <submission> --challenge-run <summary>
uv run kata king promote --challenge-run <summary> --submission-path <submission>
```

---

## Development

```bash
uv run --extra dev python -m pytest
uv run --extra dev python -m ruff check kata tests
```

If you change the evaluator, screening, or promotion logic, add or update tests. See
[`CONTRIBUTING.md`](CONTRIBUTING.md).

---

## Documentation

| Doc | What it covers |
| --- | --- |
| [`docs/submissions.md`](docs/submissions.md) | The miner submission contract, required files, and validation rules. |
| [`docs/system-workflow.md`](docs/system-workflow.md) | End-to-end flow from PR to king across the repos. |
| [`docs/github-automation.md`](docs/github-automation.md) | The engine ↔ `kata-bot` boundary. |
| [`docs/gittensor-integration.md`](docs/gittensor-integration.md) | Registry entry and reward-label rules for GitTensor. |
| [`docs/sn60-early-stop.md`](docs/sn60-early-stop.md) | The optional two-phase cost-saving mode. |
| [`docs/deployment.md`](docs/deployment.md) | Full from-scratch deployment runbook. |
| [`deploy/sn60-model-relay/README.md`](deploy/sn60-model-relay/README.md) | The model-pinning relay and per-PR cost metering. |

---

## Repo layout

- `kata/` — engine: lane state, pack registry, screening, SN60 evaluator, promotion.
- `lanes/` — central pack registry (`registry.json`) plus per-lane state.
- `kings/` — the published current king artifact per pack and mode.
- `submissions/` — PR-submitted candidate bundles (empty between active PRs).
- `runs/` — duel artifacts with reproducible provenance.
- `deploy/` — deployment assets (the model-pinning relay).

## License

MIT — see [`LICENSE`](LICENSE).
