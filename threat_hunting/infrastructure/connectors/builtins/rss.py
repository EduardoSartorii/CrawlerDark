"""RSS/Atom feed connector.

Responsibility
--------------
Collect items from RSS/Atom feeds (security news, blogs, vendor advisories). The
feed URLs come from configuration (``options.feeds``), so the same connector
serves any number of feeds without code changes. It demonstrates the full
network path through the OPSEC transport.
"""

from __future__ import annotations

from collections.abc import Sequence

from bs4 import BeautifulSoup

from threat_hunting.core.application.dto import RawRecord
from threat_hunting.core.domain.enums import Category
from threat_hunting.infrastructure.connectors.base import BaseConnector


class RSSConnector(BaseConnector):
    """Collects entries from configured RSS/Atom feeds."""

    name = "rss"
    source = "rss"
    default_category = Category.OSINT

    async def collect(self) -> Sequence[RawRecord]:
        """Fetch and parse each configured feed into raw records."""
        feeds: list[str] = list(self.options.get("feeds", []))
        records: list[RawRecord] = []
        for feed_url in feeds:
            response = await self.transport.get(feed_url)
            if not response.ok:
                continue
            records.extend(self._parse_feed(feed_url, response.text))
        return records

    def _parse_feed(self, feed_url: str, xml: str) -> list[RawRecord]:
        """Turn raw feed XML into raw records (RSS ``item`` + Atom ``entry``)."""
        soup = BeautifulSoup(xml, "xml")
        records: list[RawRecord] = []
        for item in soup.find_all(["item", "entry"]):
            title = item.find("title")
            link = item.find("link")
            desc = item.find(["description", "summary", "content"])
            url = None
            if link is not None:
                url = link.get("href") or link.text or None
            body = desc.text if desc is not None else ""
            records.append(
                self._record(
                    content=f"{title.text if title else ''}\n{body}",
                    url=url,
                    metadata={
                        "title": title.text if title else feed_url,
                        "feed": feed_url,
                    },
                    raw={"feed": feed_url, "title": title.text if title else None},
                )
            )
        return records
