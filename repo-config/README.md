# repo-config

The reviewed configuration of this repository, as data.

GitHub settings drift. Someone adds a label by hand, a branch protection rule gets relaxed during an
incident and never restored, a webhook is re-pointed at a staging host. None of that shows up in a
diff, and all of it changes how the competition behaves — a missing `kata:lane:<subnet>` label
means that subnet's submissions route nowhere, and a relaxed `main` means the promotion history can be rewritten.

So the configuration lives here, in version control, and a tool reports the difference between it
and reality:

```bash
# Report only. Reads GitHub, writes nothing, exits non-zero if anything drifted.
kata-bot provision-repo --config repo-config --repo Autovara/kata

# Apply. Requires an explicit flag, and never deletes anything it did not create.
kata-bot provision-repo --config repo-config --repo Autovara/kata --apply
```

| File | What it pins |
|---|---|
| `repository.json` | Repository-level settings: merge strategy, issues, auto-merge |
| `labels.json` | Every label the bot manages, with its colour and description |
| `branch-protection.json` | What may write to `main` |
| `webhook.json` | Which events reach the resident, and how |

Each file carries a `rationale` block. A setting whose reason nobody remembers is a setting that
gets "cleaned up" in six months, and several of these look wrong until you know why:
`required_pull_request_reviews` is `null` because the bot merges unattended, and `enforce_admins` is
`false` so a rollback does not require unprotecting the branch first.

## What is deliberately absent

**The webhook secret and every token.** `webhook.json` names the environment variables the values
arrive in; it does not contain them. A configuration file is reviewed, committed and copied around,
and it has to stay safe to do all three with. The secret reaches the resident through systemd
credentials, and the provisioning tool reads it from the environment at apply time.

## Applying it

The tool configures a repository; it does not create one. That is deliberate — creating a public
repository under an organisation is an outward-facing act that should be a human's, taken once.

1. Run `provision-repo` in report mode and read the plan.
2. Run it with `--apply`.
3. Install the bot's GitHub App or webhook, then re-run in report mode to confirm zero drift.

## One repository, every subnet

`repository.json` declares `lane_ids` — every competition this repository takes submissions for.
Each one needs its `kata:lane:<subnet>` label defined in `labels.json`, and `load_config` refuses a
configuration that is missing one: that subnet's PRs would never be routed, and the lane would look
idle rather than misconfigured.

Adding a subnet means adding its lane id here and its label there, in the same commit.
