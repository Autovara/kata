# Kata Workflow

This is how a contributor's agent pull request moves through Kata, from submission to
round result to a possible king promotion. It is subnet-neutral: the actual scoring rules
belong to each target's plugin. For SN60, see [`../kata-sn60`](../kata-sn60).

For the submission bundle contract, see [submissions.md](submissions.md).

## Who does what

- **kata** (this repo) is the engine. It validates submissions, runs the shared screening,
  scores a round (the king once, then every candidate against that same king score on the
  same problems), ranks them, records provenance, and promotes a winner.
- **kata-bot** is the GitHub automation. On a PR event it screens the PR into a label. When
  a round runs, it locks the pending PRs, gates them, calls the engine to score them,
  applies the outcome labels, and merges and promotes the winner. All PR labels are applied
  by kata-bot.
- **kata-board** is the dashboard. It reads live round status, current king state, run
  artifacts, and the round-history feed.
- A **subnet plugin** (for example `kata-sn60`) owns its benchmark, execution environment,
  scorer, and its rule for beating the king. Kata calls its plugin contract and never
  modifies subnet code.

## Intake — when you open or update a PR

Scoring does not happen on PR open. Opening a PR enters you as a pending entrant; a round
scores every pending entrant later.

1. Work on a normal GitHub branch in the public Kata repo.
2. Add exactly one bundle under `submissions/<subnet-pack>/miner/<submission-id>/`. A
   contributor may have only one open PR at a time.
3. Run `kata submission validate` before opening the PR.
4. Open one PR against the default branch. It must touch only the submission bundle. The
   submission id prefix and `submission.json` `author` must match the GitHub account that
   opens the PR.

kata-bot then screens the PR (shape plus cheap static anti-cheat, no model calls) and
applies one label:

- `kata:pending` — passed screening, now queued for the next round.
- `kata:invalid` — a hard failure (bad shape, identity mismatch, failed anti-cheat, or an
  extra open PR beyond the one-per-contributor limit). The PR is closed.
- `kata:review` — suspicious but non-conclusive evidence. Held out of rounds until review
  clears it or the contributor pushes a clean update. A hard reject cannot be bypassed this
  way.

Pushing a commit to a benched (`kata:stale`) PR re-enters it as `kata:pending`.

## The scheduled round

When a round runs, kata-bot and the engine do the following.

1. **Lock pending entrants.** Snapshot the currently-open PRs that carry `kata:pending`.
   Keep one PR per contributor; close extras `kata:invalid`. `kata:review`, `kata:hold`,
   and unlabeled PRs do not enter.
2. **Re-entry rule.** A kept-open PR is re-scored only if its commit or the king changed
   since it last competed. An unchanged PR is skipped and labeled `kata:stale`; a push
   re-enters it. This is why a newly promoted king pulls every pending challenger back in:
   the king changed, so they all face the new bar.
3. **Execution gate.** The round does not re-run full static screening; that already
   happened at intake or on the latest push. It requires the current commit to match the
   commit that passed intake screening. If the target enables an execution screener, each
   candidate runs once first; a candidate that fails it is closed `kata:invalid`. Qualified
   candidates are labeled `kata:executing`.
4. **Score.** The engine samples this round's problems once (secret-seeded), scores the
   king once on that set, and scores every candidate on that same set. Every candidate
   faces the identical problems, so the results are directly comparable. Different rounds
   sample different problems, which discourages overfitting.
5. **Rank and decide.** Candidates are ranked by the subnet plugin's comparator. The top
   candidate that strictly beats the king wins. Same score is not enough; a challenger must
   strictly beat the king.

### About scoring

Scoring is subnet-specific and lives in the plugin, not here. The plugin scores the king
and every candidate on the same sampled problems and decides what "beats the king" means.
See that subnet's repo for the actual rule, for example [`../kata-sn60`](../kata-sn60).

Two properties are worth knowing at the engine level:

- **The king is scored fresh each round.** Each round scores the king once and every
  candidate against that same fresh king score. Nothing is cached across rounds, so a
  candidate is always measured against the king on the exact problems the king just faced.
- **A plugin declares a scoring profile.** A deterministic, offline scorer may safely cache
  a score by its artifact and benchmark identity. A live or LLM-judged scorer is "noisy":
  scores drift run to run, so it re-scores every contender. Either way, within a round the
  king and candidates are scored on the same set.

## Round outcomes

At the end of a round each PR resolves to one outcome and its label. kata-bot applies these.

| Outcome | Label | Meaning |
| --- | --- | --- |
| Winner | `kata:winner:<subnet-pack>` | Top candidate that strictly beat the king. Merged and promoted. At most one per round. |
| Kept pending | `kata:pending` | Beat the king but was not the top challenger. Stays open to compete again. |
| Losing | `kata:losing` | Entered scoring but did not beat the king. Closed. |
| Invalid | `kata:invalid` | Failed intake screening, failed the execution gate, or broke the one-open-PR rule. Closed. |
| Review | `kata:review` | Suspicious but non-conclusive evidence. Held out of rounds. |
| Stale | `kata:stale` | A kept-open PR unchanged since it last competed. Skipped this round; a push re-enters it. |
| Hold | `kata:hold` | Won, but merge or promotion is blocked. Held for attention instead of merging into a broken state. |
| Defeat | `kata:defeat:<subnet-pack>` | A former king replaced by a later winner in that subnet. The old winner label is removed first. |

Internally the engine reduces one candidate's result to `merge`, `close-losing`,
`close-invalid`, or `rerun-stale`; the round maps these across the batch to the labels
above.

## Freshness and promotion

Before merging a winner, Kata re-checks that the result is still current: the evaluated
candidate still matches the PR, the king artifact has not changed, and the target's
benchmark identity has not changed. A stale result is rerun; an unmergeable winner is held
(`kata:hold`) rather than merged.

When the decision is `merge`, kata-bot:

1. labels the PR with the winning target label,
2. merges the PR,
3. publishes the candidate bundle under `kings/<subnet-pack>/<mode>/`,
4. updates current king state,
5. clears the merged submission directory.

This keeps `submissions/` empty between active PRs while `kings/` stays the public source
of truth for the current best agent.

## Contributor command reference

Validate your bundle before opening a PR:

```bash
uv run kata submission validate \
  --path submissions/sn60__bitsec/miner/<github-user>-YYYYMMDD-01
```
