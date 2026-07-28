# The SN22 submission protocol, version 1

> **This describes the version-1 sandbox path, which is no longer what you submit.**
>
> The sealed room runs **version 2**: you subclass `Agent` from `kata_sn22_sdk`, implement
> `smart_scraper` and `twitter_search`, and stream your prose through `emit`. There is no stdin
> task, no stdout document and no `sn22_relay` import — the image's harness handles all three, so
> every contestant's answer is framed identically.
>
> **Start from the reference agent:**
> [`submissions/sn22__desearch/miner/example-20260727-01/agent.py`](../submissions/sn22__desearch/miner/example-20260727-01/agent.py).
> It answers all four pools and is documented line by line.
>
> The two biggest differences to know before you read further:
>
> * **You never hold a provider key.** `self.broker` spends the credentials you sealed to your
>   bundle, inside the trusted runner. There is no API key in your environment and no method that
>   returns one.
> * **Emit your prose; do not return it.** Upstream's streaming penalty counts tokens per emitted
>   chunk, so an agent that computes one string and returns it is penalised for something unrelated
>   to answer quality.
>
> What remains true below: the failure classes, the static screen, and the fact that a version this
> lane does not implement is **rejected, not interpreted leniently**. The rest describes the local
> calibration sandbox, which still speaks version 1. This page is replaced wholesale once the two
> paths converge.

This is the complete contract between your agent and the version-1 sandbox. It is versioned: an
agent declaring a `protocol_version` this lane does not implement is **rejected, not interpreted
leniently** — a lenient read of an unknown schema is how a field silently stops being checked.

The authoritative implementation is `kata_sn22/protocol.py` in the plugin repository, and the
version-2 one is `kata_sn22/protocol_v2.py` plus the `kata_sn22_sdk` package. This document
describes the former; where they disagree, the code is right and this is a bug.

## Input: one task on stdin

```json
{
  "protocol_version": 1,
  "task_id": "t000",
  "query": "bittensor subnet emissions schedule",
  "search_type": "ai_search",
  "ai_mode": "fast",
  "result_type": "both",
  "relay": {"endpoint": "sn22-relay://<challenge>", "capability": "sn22cap_<32 hex>"},
  "limits": {
    "max_wall_seconds": 120,
    "max_provider_calls": 8,
    "max_tokens": 20000,
    "max_results": 5
  }
}
```

| Field | Notes |
|---|---|
| `search_type` | `ai_search` or `x_search` |
| `ai_mode` | `fast`, `balanced` or `deep`. Present only for `ai_search`, and always present for it |
| `result_type` | `summary`, `links` or `both`. `links` means no summary is scored |
| `relay` | Your only way out. Also in the environment as `SN22_RELAY_ENDPOINT` / `SN22_RELAY_CAPABILITY`, which is where `sn22_relay` reads them from by default |
| `limits.max_results` | **Both a request and a ceiling.** Return exactly this many results: fewer takes the upstream count penalty, more is a contract violation |

The same fields arrive in the environment for convenience:
`SN22_PROTOCOL_VERSION`, `SN22_TASK_ID`, `SN22_RELAY_ENDPOINT`, `SN22_RELAY_CAPABILITY`, plus
`PYTHONPATH` pointing at the run directory. Nothing else is there — the environment is constructed
from nothing rather than filtered, so there is no provider key to find.

## Output: one JSON document on stdout

```json
{
  "protocol_version": 1,
  "task_id": "t000",
  "summary": "Emissions are distributed per subnet according to validator weights.",
  "results": [
    {"doc_id": "doc-emissions-1", "title": "Bittensor emissions schedule explained",
     "snippet": "Emissions are distributed per subnet..."}
  ],
  "citations": [
    {"doc_id": "doc-emissions-1", "claim": "emissions follow validator weights"}
  ],
  "usage": {"provider_calls": 1, "tokens": 250, "elapsed_seconds": 1.2}
}
```

Hard limits, checked before anything is scored:

| Limit | Value | What happens |
|---|---|---|
| Response size | 256 KiB | `excess_output` — checked on **bytes**, before parsing |
| Results per task | `limits.max_results` | `excess_output` |
| Citations per task | 40 | `excess_output` |
| Any text field | 8000 characters | `excess_output` |
| `task_id` | must equal the requested one | `invalid_schema` |
| `doc_id` | `^[a-z0-9][a-z0-9._:-]{0,127}$`, no repeats within `results` | `invalid_schema` |
| `usage.*` | non-negative, finite | `invalid_schema` |

Nothing is coerced, defaulted or repaired. A repaired response is one you did not produce.

## Failure classes

A failure is **classified**, never scored as a merely poor answer — otherwise a crash and a bad
answer would both score 0.0 and a broken agent would look mediocre.

| Class | Cause | Counts against you |
|---|---|---|
| `timeout` | exceeded `max_wall_seconds` | yes |
| `invalid_schema` | unparseable or contract-violating output | yes |
| `excess_output` | over a size or shape ceiling | yes |
| `excess_calls` | blew a tool or token quota | yes |
| `crashed` | non-zero exit with no parseable output | yes |
| `provider_unavailable` | **shared infrastructure fault** | **no** — the task is excluded |

A provider outage hits whichever contestant happened to run during it, so it is never charged to a
candidate. The lane refuses to decide a promotion at all when the shared infrastructure was
incomplete for either side.

## The relay

You never open it yourself. The lane writes **`sn22_relay.py`** into the run directory and puts that
directory on `PYTHONPATH`, so the whole search API is:

```python
import sn22_relay

results = sn22_relay.search("my query", limit=5)   # [{"doc_id", "title", "snippet"}, ...]
left    = sn22_relay.quota()                        # {"used", "max_calls", "remaining"} — free
```

`sn22_relay.RelayError` is raised for every refusal, with one message for all of them. That is
deliberate: an agent that could tell "quota exhausted" from "unknown capability" from "expired"
could map the lane's state one probe at a time. Catch it and answer with what you already have — a
crash is an `invalid_run` on signal 5, an empty answer is merely a poor one on signal 2.

Under the hood it is a **unix socket** in the run directory, not an HTTP endpoint. That is what lets
the sandbox keep no network namespace at all while search still works, and it is why no submission
has any legitimate reason to import `socket`, `requests`, `httpx` or `urllib` — the screen rejects
all four, and there is nothing for them to reach.

The relay serves the round's **sealed corpus**: a frozen snapshot, immutable for the duration of the
challenge. An identical request from you and from the king returns identical content — that is what
makes the pairing fair, and it is true by construction rather than by hoping the web held still.

Your capability is bound to one lane, one challenge, one *variant* and one *task*, and it expires.
Presenting it for another task, reusing it after the challenge, or asking the relay to spend past
your reservation are all refused, and the refusal messages are deliberately uninformative — they will
not tell you which of those you did.

Per-task quotas (`max_provider_calls`, `max_tokens`) are enforced by the relay, not by trusting your
`usage` block.

## Environment and execution

- Run as uid 65534 under `bwrap`, with no network namespace, no capabilities, and one writable
  directory (your `HOME`/`TMPDIR`).
- `/srv`, `/home`, `/root` and `/etc` are **absent from the mount namespace**, not present and
  denied. A path-traversal bug in your agent has nothing to traverse to.
- The interpreter and entry file are fixed by the lane. A submission cannot choose what gets
  executed.
- Memory, process count, file size and core dumps are rlimit-bounded.

If the host cannot isolate a submission, the lane **refuses to run it** rather than running it
unconfined. A submission that could not be confined has not been evaluated.

## The static screen

Deterministic, offline, free, and run before anything is executed or paid for. It rejects:

- a missing `agent.py`, or one that is a symlink or not a regular file;
- an `agent.py` over 1 MB;
- source containing `import socket`, `import requests`, `import httpx`, `urllib.request`,
  `http.client` or `import subprocess` — under `relay_only` these reach nothing, so their presence
  says the submission expects to contact providers itself.

It is a screen, not a sandbox: it matches named modules. The sandbox is what actually stops you.

## How the quality signal is computed

`sn22_weighted_quality` is the **pinned upstream Desearch score**, not an approximation of it. The
adapter is a port of `Desearch-ai/subnet-22` at commit `bea9712f…`, and the plugin repository carries
executed evidence that it computes what the real upstream computes over recorded cases.

What that means for you:

- **Pool weights.** AI search 0.90 / X search 0.10; within AI search fast 0.60, balanced 0.20, deep
  0.20. A challenge normalizes over the categories it actually drew.
- **AI quality** is content relevance 0.60 + summary relevance 0.40, except for a `links` request,
  which is content only.
- **Penalties multiply.** Count shortfall, duplicate results, malformed results, domain-filter
  violations, out-of-range dates, sort order, and summary structure. Any one of them at 1.0 zeroes
  the task.
- **Summary structure** requires bold-not-`#` headers and at least one supported source. Your
  `citations` are what supplies those sources: cite a document you did not return and the task takes
  the full penalty.
- **Timing penalties are NOT applied.** Latency is signal 7, measured by the lane's own clock. It is
  deliberately not folded into quality as well.
