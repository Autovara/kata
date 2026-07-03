# SN60 two-phase early-stop

Cuts duel cost by scoring a **phase-1 project subset first** and short-circuiting
only when the candidate has **decisively lost** — a promotion always runs the full
benchmark. Opt-in; off by default.

## How it decides

1. Split the projects into phase 1 (a stable, seed-shuffled subset) and phase 2.
2. Run king + candidate on phase 1.
3. Stop early **only** if the candidate has already lost:
   - it produced an **invalid replica run** — a guaranteed loss, since any invalid
     run anywhere makes the promotion gate reject it; or
   - it **trails the king by ≥ margin** passed codebases in phase 1 — a decisive
     statistical loss.
4. Otherwise (candidate ahead, or borderline) run phase 2 and decide on the full set.

Wins and borderline duels never stop early, so every promotion is vetted on the
complete benchmark and the full zero-invalid-run gate. On a rare borderline flip the
outcome stays with the incumbent king, which is the safe direction.

The phase split is seeded on the king+candidate artifact hashes: identical across
reruns of the same pairing (so freshness fingerprints stay stable) and not sorted by
difficulty. Because only losses stop early, there is no gaming advantage to the split.

Each duel writes `early_stop.json` next to `duel_summary.json` recording the phase-1
counts, gap, decision, and reason.

## Enable / configure

| Env var                        | Default        | Meaning                                                  |
| ------------------------------ | -------------- | -------------------------------------------------------- |
| `KATA_SN60_EARLY_STOP`         | off            | Set `1`/`true` to enable two-phase early-stop            |
| `KATA_SN60_EARLY_STOP_PHASE1`  | half (rounded up) | Number of projects scored in phase 1                  |
| `KATA_SN60_EARLY_STOP_MARGIN`  | `6`            | Phase-1 passed-codebase deficit that counts as a loss    |

Example (32 projects, phase 1 of 16, decisive at a 6-codebase deficit):

```
KATA_SN60_EARLY_STOP=1
KATA_SN60_EARLY_STOP_PHASE1=16
KATA_SN60_EARLY_STOP_MARGIN=6
```

A candidate that is clearly worse than the king is decided on ~16 projects instead of
32; genuine contenders still run all 32.
