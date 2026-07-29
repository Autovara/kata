## Submission

- Subnet: <!-- the subnet-pack directory this PR lands in, e.g. sn60__bitsec -->
- Directory: `submissions/<subnet>/miner/<your-github-username>-YYYYMMDD-NN/`

## Checklist

- [ ] `python -m kata.submissions.preflight <my directory>` passes locally
- [ ] This PR touches **only** my own submission directory
- [ ] This PR is for **one subnet only** (a PR spanning two is refused — it cannot be scored)
- [ ] I have **no other open PR for this subnet** (a PR for a *different* subnet is fine)
- [ ] My agent obeys **my subnet's** networking rule. Subnets differ: some reach the network only
      through the broker capability their SDK provides and refuse direct networking outright,
      others allow it. `preflight` applies whichever rule my target publishes and names it in the
      failure, so a green preflight is the check — not this list
- [ ] No credentials, tokens or API keys anywhere in the bundle
- [ ] No symlinks anywhere in the bundle
- [ ] My agent runs on the standard library alone (nothing is installed at run time)

## What is new here

<!-- One or two sentences. What does this agent do differently from the current king? -->

## Notes for the reviewer

<!-- Optional. Anything surprising about the approach that would otherwise look like a bug. -->
