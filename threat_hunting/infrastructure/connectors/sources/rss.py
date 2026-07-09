"""RSS / news / blog connector.

Responsibility
--------------
Fetch and parse RSS/Atom feeds (security news, blogs, vendor advisories) into
raw items using BeautifulSoup's XML parser. Demonstrates a feed/news connector
and the use of ``BeautifulSoup4``/``lxml`` behind the OPSEC transport.
"""

from __future__ import annotations

from collections.abc import Iterable

from threat_hunting.core.application.ports.connector import ConnectorMeta
from threat_hunting.core.domain.entities.raw_item import RawItem
from threat_hunting.core.domain.enums import Category, SourceType
from threat_hunting.infrastructure.connectors.base import BaseConnector

_DEFAULT_FEEDS = (
    "https://feeds.feedburner.com/TheHackersNews",
    "https://www.bleepingcomputer.com/feed/",
)


class RSSConnector(BaseConnector):
    """Collects items from configured RSS/Atom feeds."""

    meta = ConnectorMeta(
        name="rss",
        source=SourceType.RSS,
        category=Category.OSINT,
        description="RSS/Atom feed collector for security news and blogs.",
        groups=["news", "osint"],
    )

    def __init__(self, transport=None, feeds: tuple[str, ...] = _DEFAULT_FEEDS) -> None:
        super().__init__(transport=transport)
        self._feeds = feeds

    def collect(self) -> Iterable[RawItem]:
        """Yield entries parsed from each configured feed."""
        from bs4 import BeautifulSoup  # lazy import keeps core import-light

        for feed in self._feeds:
            response = self._transport.get(feed)
            if not response.ok or not response.text:
                continue
            soup = BeautifulSoup(response.text, "xml")
            for entry in soup.find_all(["item", "entry"]):
                title = entry.find("title")
                link = entry.find("link")
                description = entry.find(["description", "summary", "content"])
                yield RawItem(
                    connector=self.meta.name,
                    source=feed,
                    url=(link.get("href") if link and link.get("href") else (link.text if link else "")),
                    title=title.text if title else "",
                    content=description.text if description else (title.text if title else ""),
                    payload={"feed": feed},
                )
