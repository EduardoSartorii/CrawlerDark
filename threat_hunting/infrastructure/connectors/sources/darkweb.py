"""Dark web (.onion) connector.

Responsibility
--------------
Crawl configured ``.onion`` leak/marketplace pages through a SOCKS5 (Tor)
transport and turn page text into raw items. Demonstrates a dark-web connector
whose OPSEC profile is expected to route via Tor (``socks5://127.0.0.1:9050``).
The connector itself contains no proxy logic — that is entirely the OPSEC
layer's responsibility, selected by profile.
"""

from __future__ import annotations

from collections.abc import Iterable

from threat_hunting.core.application.ports.connector import ConnectorMeta
from threat_hunting.core.domain.entities.raw_item import RawItem
from threat_hunting.core.domain.enums import Category, SourceType
from threat_hunting.infrastructure.connectors.base import BaseConnector


class DarkWebConnector(BaseConnector):
    """Collects text from configured ``.onion`` pages via a Tor OPSEC profile."""

    meta = ConnectorMeta(
        name="darkweb",
        source=SourceType.DARK_WEB,
        category=Category.DARK_WEB,
        description="Tor .onion leak-site/marketplace crawler.",
        groups=["darkweb", "leak"],
    )

    def __init__(self, transport=None, onion_urls: tuple[str, ...] = ()) -> None:
        super().__init__(transport=transport)
        self._urls = onion_urls

    def collect(self) -> Iterable[RawItem]:
        """Yield the text content of each configured onion page."""
        from bs4 import BeautifulSoup

        for url in self._urls:
            response = self._transport.get(url)
            if not response.ok or not response.text:
                continue
            soup = BeautifulSoup(response.text, "lxml")
            text = soup.get_text(" ", strip=True)
            title = soup.title.text if soup.title else url
            yield RawItem(
                connector=self.meta.name,
                source=url,
                url=url,
                title=title,
                content=text,
                payload={"onion": url},
            )
