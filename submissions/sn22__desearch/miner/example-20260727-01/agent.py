#!/usr/bin/env python3
"""A reference SN22 agent: valid rather than good.

It does the things every submission must do, and nothing else:

1. read one task from stdin and answer on stdout, in protocol version 1;
2. search through ``sn22_relay`` — the lane puts that module in the run directory, and it is the
   ONLY way out. The sandbox has no network namespace, so there is nothing else to reach and no
   reason for a submission to import ``socket`` or ``urllib`` (both of which the screen rejects);
3. return exactly ``limits.max_results`` results — fewer takes the upstream count penalty, more is
   a contract violation;
4. **supply evidence for every source**, which is the part worth understanding before anything else.

**How a source earns anything.** The validator fetches every page you return, itself, and checks
that your ``highlights`` appear IN ORDER in its own copy of that page AND in your own ``text``
about it. A source that fails either check is dropped before it is ever judged — it does not score
badly, it does not score at all. So:

* quote CONTIGUOUS, REAL spans of the page. Reassembling a page's vocabulary into a sentence nobody
  wrote fails the ordering check, which is exactly what it is for;
* say the same thing in ``text`` that your highlights say. Pasting real excerpts beside an answer
  written from somewhere else fails the second direction of the check;
* only what survives is sent to the judge, and it is judged on the EXCERPTS, not the page — you are
  graded on what you proved you read.

**What a citation costs.** A citation counts only when you actually returned that source and that
source passed evidence. Citing a URL you did not return is free to write and earns nothing, and
citing a source whose excerpts did not check out is worse than citing nothing at all.

Its retrieval strategy is one relay call with the query verbatim. Beating that is the starting
point, not the goal — a real agent reformulates, searches more than once, ranks what comes back,
and quotes the passages that actually answer the question rather than the first lines of the page.
This one has a whole spare quota it never touches.

Standard library only, plus ``sn22_relay``. The sandbox installs nothing.
"""
from __future__ import annotations

import json
import sys
import time

import sn22_relay

PROTOCOL_VERSION = 1

#: How many excerpts to claim per source. More is not better: EVERY one must be found, in order, in
#: the validator's own copy of the page, so each extra highlight is another chance to fail evidence.
HIGHLIGHTS_PER_SOURCE = 1


def read_task() -> dict:
    """The task arrives on stdin. Refuse a version this agent does not implement rather than
    guessing at it — a lenient read of an unknown schema is how a field stops being checked."""
    document = json.loads(sys.stdin.read())
    if document.get("protocol_version") != PROTOCOL_VERSION:
        raise SystemExit(f"unsupported protocol_version {document.get('protocol_version')!r}")
    return document


def search(query: str, limit: int) -> list[dict]:
    """One relay search, with failure answered rather than raised.

    A crash is an ``invalid_run`` and counts against you on signal 5; an empty answer is merely a
    bad one on signal 2. When the relay refuses — quota gone, capability expired, challenge closed —
    the useful move is to answer with what you have.
    """
    try:
        return sn22_relay.search(query, limit=limit)
    except sn22_relay.RelayError:
        return []


def highlights_for(item: dict) -> list[str]:
    """The excerpts this agent is willing to stand behind for one source.

    It uses the snippet the provider returned, which is genuinely FROM the page — that is the whole
    reason it can pass evidence. A better agent fetches or reads more of the page and quotes the
    passage that actually answers the question; a worse one invents a sentence and scores nothing.
    """
    snippet = str(item.get("snippet") or "").strip()
    return [snippet[:400]] if len(snippet) >= 24 else []


def build_summary(query: str, results: list[dict]) -> str:
    """A summary the upstream structure check accepts, with its sources cited inline.

    Bold headers rather than ``#`` (a ``#`` header is the full penalty). The markdown links are not
    decoration: the groundedness judge reads them to decide which source it should check each value
    against, so a value cited to the wrong source fails even when it is true.
    """
    if not results:
        return f"**{query}**\n\nNo relevant sources were retrieved for this query."
    lines = [f"**{query}**", ""]
    for index, item in enumerate(results, 1):
        title = str(item.get("title") or item["link"])
        snippet = str(item.get("snippet") or "").strip()
        lines.append(f"- {title} [{index}]({item['link']}): {snippet[:200]}".rstrip(": "))
    return "\n".join(lines)


def main() -> int:
    started = time.monotonic()
    task = read_task()
    limits = task.get("limits") or {}
    max_results = int(limits.get("max_results") or 5)
    query = str(task.get("query") or "")

    found = search(query, max_results)

    # Exactly the requested count, de-duplicated. A repeated link is an `invalid_schema` rejection,
    # and padding a list with copies takes the full duplicate penalty upstream — so there is no
    # version of "fill the quota with what I have" that pays.
    results: list[dict] = []
    seen: set[str] = set()
    for item in found:
        link = str(item.get("link") or "")
        if not link.startswith(("http://", "https://")) or link in seen:
            continue
        seen.add(link)
        highlights = highlights_for(item)
        results.append({
            "link": link,
            "title": str(item.get("title") or link)[:8000],
            "snippet": str(item.get("snippet") or "")[:8000],
            # The evidence. Without it this source is dropped before it is judged.
            "highlights": highlights[:HIGHLIGHTS_PER_SOURCE],
            # ...and the same claim in the agent's own words, so the second direction of the
            # evidence check passes too. Saying something DIFFERENT here fails it.
            "text": " ".join(highlights[:HIGHLIGHTS_PER_SOURCE]),
        })
        if len(results) >= max_results:
            break

    # Cite ONLY what was returned, and only what carries evidence. A citation to a source that did
    # not survive the evidence check earns nothing and drags precision (signal 3) down with it.
    #
    # Citing everything retrieved is the naive choice and it COSTS precision: a result that was
    # returned but is not actually relevant is a citation that fails. Deciding which of your
    # results you are willing to stand behind is the first thing worth improving here — and note
    # that citing nothing scores precision 1.0 but loses at quality and coverage first, so silence
    # is not the answer either.
    citations = [{"link": item["link"], "claim": f"supports: {query}"}
                 for item in results if item["highlights"]]

    json.dump({
        "protocol_version": PROTOCOL_VERSION,
        "task_id": task["task_id"],
        "summary": build_summary(query, results),
        "results": results,
        # X search is answered with tweets rather than pages; this reference does not implement it.
        # The validator re-scrapes every tweet you claim and compares it field by field, so an
        # edited tweet scores zero rather than less.
        "tweets": [],
        "citations": citations,
        # Reported honestly. It is not what you are ranked on — cost comes from the relay's own
        # billing — but a large gap between this and the relay's record is worth a reviewer's time.
        "usage": {"provider_calls": 1 if found else 0,
                  "tokens": 0,
                  "elapsed_seconds": round(time.monotonic() - started, 3)},
    }, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
