#!/usr/bin/env python3
"""A reference SN22 agent: valid rather than good.

It answers **all four pools** — AI search in fast, balanced and deep mode, and Basic X search — and
does nothing clever in any of them. That is the point: it is the floor, not the target. Beating it
should be easy, and every place it is obviously lazy is marked.

    from kata_sn22_sdk import Agent, AiSearchResult, ScraperTextRole, XSearchResult

    class Submission(Agent):
        async def smart_scraper(self, synapse, emit): ...
        async def twitter_search(self, synapse): ...

**You never hold a credential.** ``self.broker`` spends the keys you sealed to your bundle, inside
the trusted runner, on your behalf. There is no API key in your environment and no method that
returns one — so there is nothing to leak, and nothing you can point at a host of your choosing.

**Emit your prose; do not return it.** Upstream miners stream, and the streaming penalty counts
tokens per emitted chunk. ``emit(role, text)`` records what a streamed answer would have streamed,
and the harness derives ``completion``, ``texts`` and ``text_chunks`` from it. An agent that computed
one string and returned it takes that penalty for a difference that has nothing to do with quality.

**How a source earns anything: you must CITE it.** The validator fetches every link you return,
itself, and checks that your ``highlights`` appear **in order** in its own copy of the page *and* in
your own ``text`` about it. A source that fails either is dropped before it is judged — it does not
score badly, it does not score at all. ``cite()`` attaches that evidence, and a source returned
without it is worth nothing however good it is.

This agent quotes the provider's snippet, which genuinely came from the page. That is the laziest
thing that can pass. Reading more of the page and quoting the passage that actually answers the
question is where the marks are.

**Return exactly ``synapse.count``.** Fewer takes the count penalty. Duplicates take the duplicate
penalty, so padding with copies of what you have is worse than returning less.

**``ONLY_LINKS`` means no summary is graded.** Writing one anyway spends your own money on something
nobody reads.

Standard library plus ``kata_sn22_sdk``. Nothing is installed at run time, and there is no installer
in the image to do it with.
"""
from __future__ import annotations

from kata_sn22_sdk import (
    Agent,
    AiSearchResult,
    BrokerError,
    ScraperTextRole,
    XSearchResult,
    cite,
)

#: How many sources to describe in the summary. Not a scoring rule — a legibility one: the
#: groundedness judge reads the links to decide which source to check each claim against, and a wall
#: of forty is harder to ground than a well-chosen five.
SOURCES_IN_SUMMARY = 5


class Submission(Agent):
    """One search, one summary, no reformulation. The whole quota goes unused."""

    async def smart_scraper(self, synapse, emit) -> AiSearchResult:
        """Answer one AI-search task.

        A real agent reformulates the prompt, searches more than once, ranks what comes back, and
        quotes the passages that actually answer the question. This one issues the prompt verbatim
        and keeps whatever order the provider returned — and it still has almost its entire search
        quota left when it stops.
        """
        results = self._search(synapse.prompt, synapse.count)

        # Exactly the requested count, de-duplicated by link. A repeated link takes the duplicate
        # penalty, so there is no version of "fill the quota with what I have" that pays.
        sources = [self._cite(item) for item in self._distinct(results, synapse.count)]

        if not synapse.wants_summary:
            # ONLY_LINKS: nothing to emit. The AI quality split reweights to (1.0, 0.0), so a
            # summary here is graded by nobody and paid for by you.
            return AiSearchResult(search_results=sources)

        emit(ScraperTextRole.INTRO, self._intro(synapse.prompt, sources))
        emit(ScraperTextRole.SEARCH_SUMMARY, self._sources_block(sources))
        emit(ScraperTextRole.FINAL_SUMMARY, self._final_summary(synapse, sources))
        return AiSearchResult(search_results=sources)

    async def twitter_search(self, synapse) -> XSearchResult:
        """Answer one Basic X-search task.

        Tweets are returned exactly as the provider gave them. The validator re-scrapes each one and
        compares it field by field, so an "improved" tweet scores zero rather than less.

        Note what this does NOT do: ``sort="Latest"`` is scored on ordering, and results not in
        descending time order are an immediate zero for the task. This agent trusts the provider's
        order. Checking it is the first thing worth adding.
        """
        try:
            tweets = self.broker.x_search(synapse.query, count=synapse.count)
        except BrokerError:
            # ONE error class covers refused, unreachable and unintelligible. An empty answer is a
            # bad answer; an uncaught exception is an invalid run and costs more than the pool.
            return XSearchResult(results=[])
        return XSearchResult(results=tweets[:synapse.count])

    # ---- helpers -------------------------------------------------------------------------------

    def _search(self, query: str, count: int) -> list:
        try:
            return self.broker.web_search(query, count=count)
        except BrokerError:
            return []

    @staticmethod
    def _distinct(results: list, count: int) -> list:
        seen: set = set()
        out: list = []
        for item in results:
            link = str(item.get("link") or item.get("url") or "")
            if not link.startswith(("http://", "https://")) or link in seen:
                continue
            seen.add(link)
            out.append(item)
            if len(out) >= count:
                break
        return out

    @staticmethod
    def _cite(item: dict) -> dict:
        """Attach the evidence without which this source scores nothing.

        The snippet is used because it is a real span of the page — that is the whole reason it can
        pass the ordering check. An invented sentence fails, which is exactly what the check is for.
        """
        snippet = str(item.get("snippet") or "").strip()
        return cite(item, [snippet] if len(snippet) >= 24 else [])

    @staticmethod
    def _intro(prompt: str, sources: list) -> str:
        return f"Searching for: {prompt}\nFound {len(sources)} sources.\n\n"

    @staticmethod
    def _sources_block(sources: list) -> str:
        lines = []
        for item in sources[:SOURCES_IN_SUMMARY]:
            title = str(item.get("title") or item.get("link") or "").strip()
            snippet = str(item.get("snippet") or "").strip()
            lines.append(f"- {title}: {snippet[:200]}".rstrip(": "))
        return "\n".join(lines) + "\n\n" if lines else ""

    def _final_summary(self, synapse, sources: list) -> str:
        """The block the groundedness judge reads.

        Bold headers rather than ``#`` — a ``#`` header takes the full structure penalty. The
        markdown links are not decoration: the judge follows them to decide which source to check
        each claim against, so a claim cited to the wrong source fails even when it is true.

        This agent restates the snippets it was given. That is the laziest thing that can pass
        groundedness, because a snippet genuinely came from the page. Reading more of the page and
        answering the actual question is where the marks are.
        """
        if not sources:
            return f"**{synapse.prompt}**\n\nNo relevant sources were retrieved."
        lines = [f"**{synapse.prompt}**", ""]
        for index, item in enumerate(sources[:SOURCES_IN_SUMMARY], 1):
            link = str(item.get("link") or item.get("url") or "")
            title = str(item.get("title") or link).strip()
            snippet = str(item.get("snippet") or "").strip()
            lines.append(f"- [{title}]({link}) [{index}]: {snippet[:200]}".rstrip(": "))
        return "\n".join(lines)
