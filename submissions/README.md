# Submissions

**This is where miners enter.** One PR, one subnet, under that subnet's directory:

```
submissions/sn60__bitsec/miner/<your-github-username>-YYYYMMDD-NN/     # an SN60 agent
submissions/sn22__desearch/miner/<your-github-username>-YYYYMMDD-NN/   # an SN22 agent
```

You submit an agent by opening a pull request. The lane runs your agent and the reigning **king** on
the same challenge and promotes yours only if it is measurably better. That is the whole contract;
everything below is detail.

## The rules, in full

1. **One submission directory per pull request.** Exactly one. A PR that edits anything outside its
   own directory is closed as invalid — the bot cannot tell which agent you meant to enter.
2. **One subnet per pull request.** A PR touching two `submissions/<subnet>/` directories is
   refused: each subnet is a separate competition with its own king, so there is no answer to which
   one it entered.
3. **One open PR per contributor, per subnet.** A second open submission from the same account *in
   the same subnet* is refused, not queued — push to your existing PR instead. A PR for a
   **different** subnet is fine, and expected: you can compete in every subnet at once.
4. **No secrets in plaintext, ever.** Your agent holds a short-lived capability, never a provider
   key: it asks a trusted broker to do a named thing, and the broker spends the key. A plaintext
   credential anywhere in your bundle is a rejection, and you should assume anything committed to a
   public repository is compromised whether or not it is later removed.

   **SN22 is the exception that proves the rule.** SN22 miners fund their own evaluation, so an SN22
   bundle contains a `sealed_inference_key` file. That file is *ciphertext*: your four provider keys
   encrypted to one specific attested room's public key and bound to your exact bundle. Nobody but
   that room can read it, and it is useless with any other agent. See
   [`docs/SN22-PROTOCOL.md`](../docs/SN22-PROTOCOL.md) §1 for how to produce it — and note that the
   sealing tool never accepts a key as a command-line value.
5. **Everything must be committed.** The lane runs your bundle as it appears in the PR. There is no
   install step and no dependency resolution — the standard library plus your subnet's SDK is what
   you have, and the image ships no package manager to change that.
6. **No symlinks.** Anywhere in the bundle.

**Your PR's subnet is decided by where it lands**, not by anything you declare. The bot reads the
changed paths. A PR that touches no `submissions/` directory is not an entry at all — that is how
ordinary engine and documentation PRs against this repository pass through untouched.

## Before you open the PR

```bash
python tools/check_submission.py submissions/<subnet>/miner/<your-dir>
python tools/check_submission.py --all
```

Offline, no dependencies, and it checks every layout rule the bot would close your PR for. CI runs
the same script on every PR, so a green local run is a green check. It cannot tell you whether your
agent is any *good* — only that the layout will not be the reason it is rejected.

## Where to start

Copy the reigning **King**, under `kings/<subnet>/<mode>/agent.py`. It is a complete working agent,
deliberately **valid rather than good** — the starting point to beat, not a template to ship
unchanged. Copy it and replace the strategy.

There is no separate example submission. A shipped example is a second thing to keep correct, and it
drifts: miners would be copying one agent while being scored against another. `submissions/` holds
miners' entries and nothing else.

## What happens after you open it

1. The bot labels the PR `kata:lane:<subnet>` + `kata:pending`.
2. Deterministic screening runs. It is free and offline; a failure closes the PR as `kata:invalid`
   with the reason in a comment.
3. When your PR reaches the head of that subnet's queue, the lane runs your agent and the reigning
   king on the same challenge, in randomized order, with identical quotas.
4. The result is published with every ranked signal and the reason the comparison was decided where
   it was.
5. You win (`kata:winner`, merged), you lose (`kata:losing`, closed), or the challenge is returned to
   pending because the shared infrastructure was incomplete for one of you.

A `kata:stale` label means the king changed while you were queued and your PR needs a re-run against
the new incumbent. You do not need to do anything; the lane re-runs it.

## What each subnet expects

The task protocol, the scoring signals and the screening rules are the **subnet's own** — Kata does
not invent them, and does not modify them:

| Subnet | Directory | Protocol | Rules live in |
|---|---|---|---|
| SN60 (Bitsec) | `sn60__bitsec/miner/` | — | [`kata-sn60`](https://github.com/Autovara/kata-sn60) |
| SN22 (Desearch) | `sn22__desearch/miner/` | [`docs/SN22-PROTOCOL.md`](../docs/SN22-PROTOCOL.md) | [`kata-sn22`](https://github.com/Autovara/kata-sn22) |

## Getting a decision reviewed

Open an issue. Do not re-open a closed PR or open a second one in the same subnet — that trips the
one-open-PR rule and delays you further. The published result carries the challenge's benchmark
identity, which is what a reviewer needs to reproduce the comparison.
