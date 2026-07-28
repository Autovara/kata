# Submissions

**This is where miners enter.** One PR, one subnet, under that subnet's directory:

```
submissions/sn60__bitsec/miner/<your-submission-id>/     # an SN60 agent
submissions/sn22__desearch/miner/<your-submission-id>/   # an SN22 agent
```

Your submission id is yours to pick; convention is `<handle>-<yyyymmdd>-<nn>`.

## The rules that decide whether your PR is accepted

**One open PR per subnet, per contributor.** You may hold one open SN60 entry *and* one open SN22
entry at the same time — they are separate competitions with separate kings. A second open PR in
the *same* subnet is closed as a duplicate; push to your existing PR instead.

**One subnet per PR.** A PR that touches two subnets' directories is refused. It cannot be scored
(which king would it challenge?), so split it.

**Your PR's subnet is decided by where it lands**, not by anything you declare. The bot reads the
changed paths. A PR that touches no `submissions/` directory is not an entry at all — that is how
ordinary engine and docs PRs against this repo pass through untouched.

## What each subnet expects

The competition rules, the scoring signals and the protocol are the subnet's own:

| Subnet | Directory | Where the rules live |
|---|---|---|
| SN60 (Bitsec) | `sn60__bitsec/miner/` | [`kata-sn60`](https://github.com/Autovara/kata-sn60) |
| SN22 (Desearch) | `sn22__desearch/miner/` | [`kata-sn22`](https://github.com/Autovara/kata-sn22) |

Each subnet ships a reference submission in its directory here. It is *valid rather than good* —
the starting point to beat, not a template to copy unchanged.
