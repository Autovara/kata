# The SN22 submission protocol, version 2

This is the complete contract between your agent and the lane.

Start by copying the reigning King:
[`kings/sn22__desearch/miner/agent.py`](../kings/sn22__desearch/miner/agent.py).
It answers all four pools, it is documented line by line, and every place it is deliberately lazy is
marked. Beating it should be easy — and it is literally the thing you have to beat, so there is no
separate example that might drift away from what you are actually scored against.

```python
from kata_sn22_sdk import Agent, AiSearchResult, ScraperTextRole, XSearchResult, cite


class Submission(Agent):
    async def smart_scraper(self, synapse, emit):
        results = self.broker.web_search(synapse.prompt, count=synapse.count)
        sources = [cite(r, [r.get("snippet", "")]) for r in results]
        emit(ScraperTextRole.FINAL_SUMMARY, "...")
        return AiSearchResult(search_results=sources)

    async def twitter_search(self, synapse):
        return XSearchResult(results=self.broker.x_search(synapse.query, count=synapse.count))
```

Exactly one `Agent` subclass per submission. Two would make "which one runs" a question answered by
definition order.

---

## 1. You fund your own evaluation

**You seal four provider credentials to your bundle. The validator holds none.**

| Provider | Your agent spends it on | The validator spends it on |
|---|---|---|
| ScrapingDog | web search | independently fetching the pages you returned |
| Apify | X search | independently re-scraping the tweets you returned |
| OpenAI | your final summary (`gpt-4.1-nano`) | nothing |
| Chutes | nothing | the fixed judge that grades you |

All four are required. A production epoch covers all four pools, and demanding the full set at
sealing time is what turns *"you fail on pool three, an hour in"* into *"your submission is rejected
at intake"*.

**An invalid, unauthorized, out-of-credit, expired or rate-limited key scores you ZERO.** Not "less"
— zero, for the whole four-pool epoch. There is no validator key to fall back on, because the
validator does not have one. This applies to the King too: whoever holds the crown keeps paying to
defend it.

Note the asymmetry in the table. Your agent never reaches Chutes — an agent that could call the
judge could grade its own work. The validator never reaches your OpenAI key.

### Sealing your credentials

```bash
uv run --extra seal python kata_seal_multi.py \
  --room https://<approved-room-url> \
  --credential-profile sn22-miner-funded-v1 \
  --providers scrapingdog,apify,openai,chutes \
  --key-env scrapingdog=SCRAPINGDOG_API_KEY \
  --key-env apify=APIFY_API_KEY \
  --key-env openai=OPENAI_API_KEY \
  --key-env chutes=CHUTES_API_KEY \
  --bundle ./my-submission \
  --measurement <approved-room-measurement>
```

Get the room URL and the measurement from the lane's current activation notes. The tool:

1. fetches the room's public key and **verifies its attestation is a genuine TEE** matching
   `--measurement`, so you cannot be tricked into sealing to a room somebody else controls;
2. binds the credential set to your bundle;
3. seals it and writes `sealed_inference_key` into the bundle, atomically, at `0600`.

Add that file to your PR.

**No key is ever a command-line value** — only the name of an environment variable, a `0600` file, or
a hidden prompt. Command lines are world-readable in the process list.

**The seal covers your whole bundle.** Editing `agent.py` after sealing invalidates it, and the room
will refuse the credential. Reseal after any change.

---

## 2. What you are asked: four pools, 60 tasks

| Pool | Tools | Share of the score | Time budget |
|---|---|---|---|
| `ai_search:fast` | Web Search | 0.54 | 15s |
| `ai_search:balanced` | Web or Twitter | 0.18 | 15s |
| `ai_search:deep` | Web or Twitter | 0.18 | 30s |
| `x_search` | Basic X search | 0.10 | 15s |

15 tasks each. `ai_search:fast` is more than half the score — a submission that only improves the
deep pool is optimising 18% of its result.

`smart_scraper` answers the three AI pools; `twitter_search` answers Basic X. A submission that
implements only one still runs: the other returns an empty answer and loses that pool. That is a
decision, not a saving — every pool is weighted.

Some tasks are **deep-scored** and you are not told which. Working hardest on the ones you could
identify is exactly what the sample exists to prevent.

---

## 3. What your agent can do

`self.broker` is the whole outward surface. Three operations, and **there is no API key on it and no
method that returns one**:

```python
self.broker.web_search(query, count=10)   # -> [ {title, link, snippet}, ... ]
self.broker.x_search(query, count=10)     # -> [ raw tweet objects ]
self.broker.final_summary(messages)       # -> str
self.broker.quota()                       # -> what is left, per operation
```

You name an **operation**, never a URL. There is no parameter for a host, a model or an Apify actor —
not because they are validated away, but because the client cannot express them. The model for
`final_summary` is fixed for everyone: one contestant summarising with a frontier model and another
with a small one would be a comparison of budgets.

Every contestant gets the same per-operation quota. `quota()` is free and does not consume one; an
agent that cannot see its own quota either wastes it or hoards it.

Anything the broker refuses raises `BrokerError` — one class for refused, unreachable and
unintelligible alike. An agent that could tell them apart could map the room's state one probe at a
time, and none of them changes the useful response, which is to answer with what you have.

---

## 4. How a source earns anything: you must cite it

The validator **fetches every link you return, itself**, and then checks two things:

1. every string in `highlights` appears **in order** in its own copy of the page;
2. every string in `highlights` appears **in order** in your own `text`.

A source that fails either is **dropped before it is judged** — it does not score badly, it does not
score at all. `cite()` attaches that evidence:

```python
sources = [cite(result, [result["snippet"]]) for result in results]
```

So:

- **quote contiguous, real spans of the page.** Reassembling a page's vocabulary into a sentence
  nobody wrote fails the ordering check, which is precisely what it is for;
- **say the same thing in `text`.** Pasting real excerpts beside an answer written from somewhere
  else fails the second direction;
- only what survives is sent to the judge, and it is judged on the **excerpts**. You are graded on
  what you proved you read.

A returned source with no evidence is worth nothing, however good it is.

**Tweets are compared field by field** against the validator's own re-scrape. Return them exactly as
the provider gave them; an "improved" tweet scores zero rather than less.

---

## 5. Emit your prose; do not return it

Upstream miners stream, and the streaming penalty counts tokens per emitted chunk.

```python
emit(ScraperTextRole.INTRO, "...")
emit(ScraperTextRole.FINAL_SUMMARY, "...")
```

`texts`, `text_chunks` and `completion` are all derived from what you emitted. `texts["summary"]` is
what the groundedness judge reads, so that is the one worth getting right.

**Emitting nothing for a task that asked for a summary is a full penalty.** Emitting nothing for an
`ONLY_LINKS` task is correct — there is no summary to judge, and writing one spends your money on
something nobody grades.

Write the summary with **bold headers, not `#`** (a `#` header takes the full structure penalty), and
with markdown links to sources you actually returned. The judge follows those links to decide which
source to check each claim against, so a claim cited to the wrong source fails even when it is true.

---

## 6. Return exactly `synapse.count` results

Fewer takes the count penalty. Duplicates take the duplicate penalty, so padding a short list with
copies of what you have is worse than returning less. Malformed results — a missing title, link or
snippet — take the schema penalty in proportion.

For `sort="Latest"` X tasks, results not in descending time order are an **immediate zero** for that
task. The reference agent trusts the provider's order; checking it is the first thing worth adding.

---

## 7. How you win

One number decides the duel: **`sn22_combined_score`**, produced by the pinned upstream's own
aggregation over both contestants' four pool tuples. Higher wins.

**A tie keeps the King.** There are no tie-breakers and no indifference band — matching the King is
not beating it.

Because the score is normalised across both contestants, your number depends on who you are up
against. A strong King is genuinely harder to beat than a weak one; that is the competition working.

---

## 8. Testing before you submit

The local sandbox serves `web_search` over a unix socket, so you can iterate offline. `x_search` and
`final_summary` exist only in the room and say so plainly rather than returning something empty that
would read as a bad answer.

Run the lane's own suite against your bundle to check it loads, frames a valid answer for all four
pools, and survives every upstream penalty — see `kata-sn22/README.md`, *Testing locally*.

---

## 9. Reading a failure

| What you see | What it means | What to do |
|---|---|---|
| `credential_missing` / `credential_invalid` / `credential_unauthorized` | your sealed key is absent, unreadable, or rejected | reseal with a working key |
| `credential_payment_required` / `credential_insufficient` | out of credit at that provider | top up and resubmit |
| `credential_rate_limited` / `credential_expired` | still limited after bounded retries, or expired mid-round | wait or rotate, then resubmit |
| `infrastructure` | not your fault — a room, a quote or a provider outage | nothing; the duel is deferred and re-run |

The first two groups score you **zero**. The last does not score you at all.

You will never see a provider's own error text. A provider rejecting a request quotes that request,
and the request carried your key.

---

## 10. What the image gives you, and what it does not

Your agent runs in a container with:

- Python, `kata_sn22_sdk`, and the harness that imports your `agent.py`;
- **no package installer** — `pip`, `apt`, `curl` and `wget` are deleted at build time;
- **no network except the broker**, on an egress-blocked internal network;
- a read-only bundle, a non-root user, all Linux capabilities dropped, and memory/CPU/PID limits;
- **no provider key anywhere** — not in the environment, argv, `/proc` or any file.

So: standard library plus `kata_sn22_sdk`. Nothing is installed at run time and there is nothing to
install it with. A dependency you need has to be code you ship in your bundle.

If your agent raises, times out or returns the wrong type, the harness writes a well-formed empty
answer and a diagnostic to stderr. You lose that task; you do not break the round. Your stderr is
kept for the operator and is never scored — an agent that could influence its score by what it
printed would be scoring itself.
