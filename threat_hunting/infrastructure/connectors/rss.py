"""RSS/Feed connector for news and blog monitoring."""

from __future__ import annotations

from collections.abc import AsyncIterator

import feedparser

from threat_hunting.core.contracts.services import CollectionContext, ParsedData, RawPayload
from threat_hunting.core.domain.entities import FindingDraft
from threat_hunting.core.domain.enums import SourceType
from threat_hunting.infrastructure.connectors.base import BaseConnector


class RssConnector(BaseConnector):
    """Collects intelligence from RSS/Atom feeds."""

    name = "rss"
    source_type = SourceType.FEED.value

    async def connect(self) -> None:
        self._connected = True

    async def collect(self, context: CollectionContext) -> AsyncIterator[RawPayload]:
        feeds = self._config.get("feeds", ["https://feeds.feedburner.com/TheHackersNews"])
        for feed_url in feeds:
            content = ""
            if self._transport:
                try:
                    response = await self._transport.get(feed_url)
                    content = response.text
                except Exception:
                    pass
            yield RawPayload(
                data={"feed_content": content, "feed_url": feed_url},
                source_uri=feed_url,
            )

    def parse(self, payload: RawPayload) -> ParsedData:
        feed_content = payload.data.get("feed_content", "")
        entries = []
        if feed_content:
            parsed_feed = feedparser.parse(feed_content)
            for entry in parsed_feed.entries[:20]:
                entries.append({
                    "title": entry.get("title", ""),
                    "summary": entry.get("summary", ""),
                    "link": entry.get("link", ""),
                })
        content = " ".join(f"{e['title']} {e['summary']}" for e in entries)
        return ParsedData(fields={"entries": entries}, content=content, metadata={"feed_url": payload.source_uri})

    def normalize(self, parsed: ParsedData) -> FindingDraft:
        entries = parsed.fields.get("entries", [])
        title = entries[0]["title"] if entries else "RSS Feed Collection"
        draft = self._default_normalize(ParsedData(fields={"title": title}, content=parsed.content), "title")
        draft.connector = self.name
        draft.source = SourceType.FEED
        draft.tags.append("rss")
        return draft
