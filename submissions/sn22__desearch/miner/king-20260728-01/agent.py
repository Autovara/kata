#!/usr/bin/env python3
"""The seeded SN22 King: the floor every challenger has to clear.

This is deliberately the simplest agent that is **valid**, not a good one. It exists so the lane has
an incumbent on day one, and so the first miner to do something obviously smarter promotes. Nothing
here is a strategy; every method is the least work that avoids a penalty.

Read it as a checklist of the five ways an SN22 agent scores zero for reasons unrelated to how good
its answers are. The King avoids all five and does nothing else:

1. **An uncited source is dropped, not marked down.** The validator fetches every link itself and
   checks that each highlight appears, in order, both in its own copy of the page and in your own
   ``text`` about it. ``cite()`` attaches that evidence. Without it a perfect source is worth zero.
2. **Prose is emitted, not returned.** The streaming penalty counts tokens per emitted chunk.
   Computing one string and returning it takes the full penalty for a difference that has nothing to
   do with quality.
3. **Return exactly ``synapse.count``.** Fewer takes the count penalty; duplicates take the
   duplicate penalty, so padding with copies is worse than returning less.
4. **A raised exception is an invalid run**, which costs more than the pool it was in. Every broker
   call is wrapped; an empty answer is merely a bad one.
5. **``#`` headers take the full structure penalty.** Bold text does not.

Where the marks actually are, none of which the King attempts: reformulating the prompt and
searching more than once (it uses one query and leaves nearly its whole quota unspent), ranking what
comes back rather than trusting the provider's order, quoting the passage that answers the question
rather than the snippet, and checking that ``sort="Latest"`` results really are in descending time
order — X tasks sorted by recency score zero outright if they are not.

Standard library plus ``kata_sn22_sdk``. There is no package installer in the image.
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

#: How many sources the summary describes. Not a scoring rule — a legibility one. The groundedness
#: judge follows the links to decide which source to check each claim against, and forty of them is
#: harder to ground than a well-chosen handful.
SOURCES_IN_SUMMARY = 5

#: A highlight has to be long enough to be a real span of the page rather than a common phrase that
#: would match by accident. Below this the King cites nothing for that source and accepts the loss,
#: which is honest; a highlight that fails the ordering check drops the source entirely.
MIN_HIGHLIGHT_CHARS = 24


class Submission(Agent):
    """One search, one summary, no reformulation."""

    async def smart_scraper(self, synapse, emit) -> AiSearchResult:
        """Answer one AI-search task in any of the three modes.

        The King issues the prompt verbatim, keeps whatever order the provider returned, and quotes
        the snippet it was given. It stops with almost its entire search quota unspent.
        """
        try:
            results = self.broker.web_search(synapse.prompt, count=synapse.count)
        except BrokerError:
            # One error class covers refused, unreachable and unintelligible. Returning nothing
            # scores badly; letting this propagate would invalidate the whole run.
            results = []

        sources = [self._cite(item) for item in self._distinct(results, synapse.count)]

        if not synapse.wants_summary:
            # ONLY_LINKS. The AI quality split reweights to (1.0, 0.0), so a summary written here is
            # graded by nobody and paid for out of the contestant's own sealed credentials.
            return AiSearchResult(search_results=sources)

        emit(ScraperTextRole.INTRO, self._intro(synapse.prompt, sources))
        emit(ScraperTextRole.SEARCH_SUMMARY, self._sources_block(sources))
        emit(ScraperTextRole.FINAL_SUMMARY, self._final_summary(synapse.prompt, sources))
        return AiSearchResult(search_results=sources)

    async def twitter_search(self, synapse) -> XSearchResult:
        """Answer one Basic X-search task.

        Tweets are returned exactly as the provider gave them. The validator re-scrapes each one and
        compares it field by field, so an "improved" tweet scores zero rather than less — this is
        the one place where doing more is strictly worse.
        """
        try:
            tweets = self.broker.x_search(synapse.query, count=synapse.count)
        except BrokerError:
            return XSearchResult(results=[])
        return XSearchResult(results=tweets[:synapse.count])

    # ---- helpers -------------------------------------------------------------------------------

    @staticmethod
    def _distinct(results: list, count: int) -> list:
        """At most ``count`` results, each with a distinct usable link."""
        seen: set[str] = set()
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
        """Attach the evidence without which this source is worth nothing.

        The provider's snippet is used precisely because it is a real span of the page — that is why
        it can survive the ordering check. An invented sentence fails it, which is what the check
        exists for.
        """
        snippet = str(item.get("snippet") or "").strip()
        return cite(item, [snippet] if len(snippet) >= MIN_HIGHLIGHT_CHARS else [])

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

    @staticmethod
    def _final_summary(prompt: str, sources: list) -> str:
        """The block the groundedness judge reads.

        Bold rather than ``#``, and every claim carries the markdown link it came from: the judge
        follows those links to decide which source to check a claim against, so a true claim cited
        to the wrong source still fails.

        Restating the snippets is the laziest thing that can pass groundedness, because a snippet
        genuinely came from the page. Reading further into the page and answering the question that
        was actually asked is where a challenger takes this apart.
        """
        if not sources:
            return f"**{prompt}**\n\nNo relevant sources were retrieved."
        lines = [f"**{prompt}**", ""]
        for index, item in enumerate(sources[:SOURCES_IN_SUMMARY], 1):
            link = str(item.get("link") or item.get("url") or "")
            title = str(item.get("title") or link).strip()
            snippet = str(item.get("snippet") or "").strip()
            lines.append(f"- [{title}]({link}) [{index}]: {snippet[:200]}".rstrip(": "))
        return "\n".join(lines)
