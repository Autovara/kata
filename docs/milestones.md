# Roadmap & Milestones

**The goal: one-click mining.** Anyone should be able to pick a subnet and mine it with
a proven, optimized agent — no ML expertise, no hand-tuning. Kata gets there by
crowdsourcing that agent through open competition: contributors compete, and the winner
(the **king**) becomes the ready-to-run agent for that subnet.

The roadmap below moves from "we can crown the best agent for one subnet" to "anyone can
mine any supported subnet in one click."

> **Two subnets, two roles.** Kata's *development* is powered by **Gittensor (Bittensor
> Subnet 74)**, which coordinates and rewards contributors to this repository (see the
> README). The *competition targets* are the subnets Kata builds agents for — one is live
> today, **SN60 / Bitsec**, and this roadmap is about adding more of them.

---

## Current status — v0.1: the competition engine

**One subnet is live: SN60 (`sn60__bitsec`, miner mode).** It is the only pack
registered and active in `lanes/registry.json`, and it runs the full loop end-to-end in
production. Working today:

- **Full competition loop** — submit → screen → duel → decide → verify → promote —
  driven through the pack registry.
- **A real king** — the current best SN60 agent is always published under `kings/`.
- **Isolated, fair execution** — agents run in an internet-blocked sandbox on one fixed
  model, so the king and every challenger are judged identically.
- **Strict, objective promotion** — a challenger wins only by beating the king on
  SN60-style metrics: detection score, true positives, precision, F1 score, then
  fewer invalid/error evaluations.
- **GitHub automation** — webhook intake, a durable PR queue, and a resident service
  that runs the engine, comments results, and applies outcome labels.
- **Reproducible provenance** — benchmark and artifact hashes on every duel, with a
  freshness check that re-runs a stale result instead of merging it.
- **Dashboard** — live evaluation status and current-king state.

---

## Releases toward one-click mining

### v0.2 — Run the king

Turn the winning agent into something a miner can actually run.

- Package and publish the current king so any user can mine SN60 with it directly.
- A single command to fetch the king and start mining.

### v0.3 — More subnets

Prove the engine is subnet-agnostic in practice, not just in design.

- Add subnets beyond SN60 via the pack registry (new evaluator, new benchmark).
- Run multiple subnets side by side, each with its own king and isolated state.
- Per-subnet Gittensor labels so packs score independently.

### v0.4 — Guided mining

Remove the setup burden.

- A simple flow to choose a subnet and start mining with its king.
- Minimal configuration and clear, guided setup.

### v1.0 — One-click mining

The goal.

- Pick any supported subnet and mine it with its optimized king agent in one click.
- No ML expertise required to participate.

---

## Ongoing (every release)

- Harden submission validation and anti-cheat checks.
- Strengthen provenance and freshness guarantees as subnet count grows.
- Improve dashboard history and per-subnet leaderboards.

## Proposing a milestone

Open an issue describing the change and the problem it solves. Any change to the
evaluator, screening, or promotion logic should come with tests that prove the new
behavior — see [CONTRIBUTING.md](../CONTRIBUTING.md).
