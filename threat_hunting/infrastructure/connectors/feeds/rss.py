"""
RSS Feed Connector
==================

Collects threat intelligence from RSS/Atom feeds published by:
    - Security blogs (Krebs on Security, Schneier on Security, etc.)
    - Vendor threat intel feeds (Microsoft MSRC, CISA, CERT, etc.)
    - News aggregators (The Hacker News, Dark Reading, etc.)

Collection strategy:
    - Fetches each configured feed URL.
    - Parses entries using feedparser.
    - Filters entries by keyword match (if keywords are configured).
    - Each matching entry becomes a Finding.

Configuration: Add feed URLs to config/settings.yaml (connectors.rss.feeds).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, AsyncIterator

import structlog

from threat_hunting.core.domain.entities.finding import Finding, FindingStatus
from threat_hunting.core.domain.ports.connectors import ConnectorHealthStatus
from threat_hunting.core.domain.value_objects.category import Category
from threat_hunting.core.domain.value_objects.source import SourceType
from threat_hunting.infrastructure.connectors.base import BaseConnector

logger = structlog.get_logger(__name__)

DEFAULT_FEEDS = [
    "https://krebsonsecurity.com/feed/",
    "https://feeds.feedburner.com/TheHackersNews",
    "https://www.bleepingcomputer.com/feed/",
    "https://www.darkreading.com/rss.xml",
    "https://www.cisa.gov/uscert/ncas/alerts.xml",
]


class RSSConnector(BaseConnector):
    """RSS/Atom feed connector for threat intelligence blogs and news."""

    connector_id = "rss"
    connector_name = "RSS Feed Connector"
    source_type = SourceType.NEWS.value

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._feeds: list[str] = self._config.get("feeds", DEFAULT_FEEDS)

    async def collect(self) -> AsyncIterator[dict]:
        """Fetch and parse all configured RSS feeds."""
        import feedparser  # type: ignore[import-untyped]

        for feed_url in self._feeds:
            self._logger.info("rss_fetching", url=feed_url)
            try:
                response = await self._get(feed_url)
                feed = feedparser.parse(response.text)
                for entry in feed.entries:
                    entry["_feed_url"] = feed_url
                    entry["_feed_title"] = feed.feed.get("title", feed_url)
                    yield dict(entry)
            except Exception as exc:
                self._logger.warning("rss_fetch_error", url=feed_url, error=str(exc))

    async def parse(self, raw_item: dict) -> dict:
        """Extract structured data from an RSS entry."""

        def _parse_date(entry: dict) -> datetime:
            import email.utils
            try:
                published = entry.get("published") or entry.get("updated") or ""
                if published:
                    return datetime(*email.utils.parsedate(published)[:6], tzinfo=timezone.utc)
            except Exception:
                pass
            return datetime.now(timezone.utc)

        return {
            "id": raw_item.get("id") or raw_item.get("link"),
            "title": raw_item.get("title", "Untitled Feed Entry"),
            "summary": raw_item.get("summary", ""),
            "link": raw_item.get("link"),
            "feed_url": raw_item.get("_feed_url"),
            "feed_title": raw_item.get("_feed_title"),
            "published_at": _parse_date(raw_item),
            "author": raw_item.get("author"),
            "tags": [t.get("term", "") for t in raw_item.get("tags", []) if isinstance(t, dict)],
        }

    async def normalize(self, parsed_item: dict) -> Finding:
        """Convert a parsed RSS entry into a Finding."""
        return Finding(
            title=parsed_item["title"][:512],
            description=parsed_item.get("summary", "")[:4096],
            source=SourceType.NEWS,
            connector=self.connector_id,
            category=Category.OSINT,
            status=FindingStatus.NORMALIZED,
            source_id=parsed_item.get("id"),
            source_url=parsed_item.get("link"),
            source_published_at=parsed_item.get("published_at"),
            raw_data=str(parsed_item),
            normalized_data={
                "platform": "rss",
                "feed_title": parsed_item.get("feed_title"),
                "feed_url": parsed_item.get("feed_url"),
                "author": parsed_item.get("author"),
            },
            tags=["rss", "news"] + [t for t in parsed_item.get("tags", []) if t],
        )

    async def health(self) -> ConnectorHealthStatus:
        """Check RSS feed reachability (first feed only)."""
        if not self._feeds:
            return ConnectorHealthStatus(healthy=False, message="No feeds configured")
        try:
            import time
            start = time.perf_counter()
            await self._get(self._feeds[0])
            latency = (time.perf_counter() - start) * 1000
            return ConnectorHealthStatus(
                healthy=True, message="RSS feed reachable", latency_ms=latency
            )
        except Exception as exc:
            return ConnectorHealthStatus(healthy=False, message=str(exc))
