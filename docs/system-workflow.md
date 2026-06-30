# Kata Workflow

This system uses three repos.

- `Kata`
  - receives miner submission PRs
  - validates challenger agents
  - runs benchmark evaluation
  - decides whether a PR should close, rerun, or merge
- `kata-benchmarks`
  - stores benchmark packs for each target repo
  - stores frontier state for each repo lane
  - stores the current benchmark source of truth
- `kata-bot`
  - listens to PR events
  - calls Kata commands
  - comments on PRs
  - closes, reruns, or merges based on Kata results

So the competition happens through PRs in `Kata`, the benchmark state
lives in `kata-benchmarks`, and GitHub automation lives in `kata-bot`.

Current MVP note:

- SN74 may list many repos upstream
- Kata currently activates one repo-pack first:
  `e35ventura__taopedia-articles`
- more repo-packs can be added later by extending the benchmark registry

This is the workflow in order.

1. A maintainer selects a target repo.

2. A benchmark pack is prepared for that repo in `kata-benchmarks`.
   That pack contains pinned tasks and checks.

3. Kata initializes the lane for that repo and mode.
   Today this still seeds baseline/frontier lane artifacts from the old prompt
   bootstrap path, but challenger submissions already use the `agent.py`
   contract.

4. A miner opens a PR to `Kata` with one challenger agent submission.

5. The bot asks Kata to check the PR shape first.
   The PR should only touch one submission directory and only allowed
   submission files.

6. If the PR is invalid, the bot closes it.

7. If the PR is valid, the bot asks Kata to evaluate the lane on the
   same benchmark tasks:
   - baseline artifact
   - frontier artifact
   - challenger agent

8. The evaluation uses the same repo snapshot, same tasks, same agent command,
   and same checks.
   The challenger artifact is the variable.

9. The challenger only wins if it beats the current frontier by the required
   promotion margin.

10. If holdout tasks are configured, the challenger must also hold up there.

11. Before promotion, the bot asks Kata to check freshness.
    If the frontier changed after the evaluation, the old result is stale.

12. If the result is stale, it must be rerun against the current frontier.

13. If the challenger is valid, fresh, and stronger than the frontier, the bot
    promotes it and it becomes the new frontier.

14. After that, the next miner must beat this new frontier.

15. The final decision for a PR is reduced by Kata to one of these actions:
    - `close-invalid`
    - `close-losing`
    - `rerun-stale`
    - `merge`

So the system is a winner-take-all loop for each repo:

1. prepare benchmark
2. initialize frontier
3. accept challenger PR
4. validate it
5. evaluate it
6. check freshness
7. replace frontier only if the challenger really wins

Current boundary:

- challenger agent submission
- validation
- evaluation
- scoring
- decision output

Next step:

- convert the seeded frontier/baseline lane artifacts fully from prompt-backed
  files to agent-backed files so the entire lane is agent-based end to end
