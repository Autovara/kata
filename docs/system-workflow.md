# PromptForge Workflow

This system uses three repos.

- `PromptForge`
  - receives miner submission PRs
  - validates submissions
  - runs evaluation
  - decides what the PR result should be
- `promptforge-benchmarks`
  - stores benchmark packs for each target repo
  - stores frontier state for each repo lane
  - stores the baseline prompt and current frontier prompt
- `promptforge-bot`
  - listens to PR events
  - calls PromptForge commands
  - comments on PRs
  - closes, reruns, or merges based on PromptForge results

So the competition happens through PRs in `PromptForge`, the benchmark state
lives in `promptforge-benchmarks`, and GitHub automation lives in
`promptforge-bot`.

This is the workflow in order.

1. A maintainer selects a target repo.

2. A benchmark pack is prepared for that repo in `promptforge-benchmarks`.
   That pack contains pinned tasks and checks.

3. PromptForge initializes the lane for that repo and mode.
   This creates:
   - `baseline`: fixed control prompt
   - `frontier`: current best prompt

4. A miner opens a PR to `PromptForge` with one challenger prompt submission.

5. The bot asks PromptForge to check the PR shape first.
   The PR should only touch one submission directory and only allowed
   submission files.

6. If the PR is invalid, the bot closes it.

7. If the PR is valid, the bot asks PromptForge to evaluate three prompts on the same
   benchmark lane:
   - baseline
   - frontier
   - candidate

8. The evaluation uses the same repo snapshot, same tasks, same agent command,
   and same checks.
   The prompt is the thing being compared.

9. The candidate only wins if it beats the current frontier by the required
   promotion margin.

10. If holdout tasks are configured, the candidate must also hold up there.

11. Before promotion, the bot asks PromptForge to check freshness.
    If the frontier changed after the evaluation, the old result is stale.

12. If the result is stale, it must be rerun against the current frontier.

13. If the candidate is valid, fresh, and stronger than the frontier, the bot
    promotes it and it becomes the new frontier.

14. After that, the next miner must beat this new frontier.

15. The final decision for a PR is reduced by PromptForge to one of these actions:
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

- submission
- validation
- evaluation
- scoring
- decision output

Next step:

- keep full GitHub automation in `promptforge-bot`
