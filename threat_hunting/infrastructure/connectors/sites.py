"""Generic HTTP/API connector for sites, blogs, and paste sites."""

from __future__ import annotations

from collections.abc import AsyncIterator

from bs4 import BeautifulSoup

from threat_hunting.core.contracts.services import CollectionContext, ParsedData, RawPayload
from threat_hunting.core.domain.entities import FindingDraft
from threat_hunting.core.domain.enums import HealthStatus, SourceType
from threat_hunting.infrastructure.connectors.base import BaseConnector


class HttpSiteConnector(BaseConnector):
    """Reusable HTTP site connector for blogs, sites, and paste sites."""

    name: str = "sites"
    source_type: str = SourceType.SITE.value

    async def connect(self) -> None:
        await super().connect()
        self._connected = True

    async def collect(self, context: CollectionContext) -> AsyncIterator[RawPayload]:
        urls = self._config.get("urls", [])
        if not urls and context.keywords:
            urls = [f"https://example.com/search?q={kw}" for kw in context.keywords[:3]]

        for url in urls:
            if self._transport:
                response = await self._transport.get(url)
                yield RawPayload(
                    data={"html": response.text, "url": url, "status": response.status_code},
                    source_uri=url,
                )
            else:
                yield RawPayload(data={"url": url, "content": f"Simulated content for {url}"}, source_uri=url)

    def parse(self, payload: RawPayload) -> ParsedData:
        html = payload.data.get("html", "")
        if html:
            soup = BeautifulSoup(html, "lxml")
            title = soup.title.string if soup.title else ""
            text = soup.get_text(separator=" ", strip=True)[:5000]
            return ParsedData(
                fields={"title": title or payload.source_uri, "content": text, "url": payload.source_uri},
                content=text,
                metadata={"source_uri": payload.source_uri},
            )
        return ParsedData(
            fields=payload.data,
            content=str(payload.data.get("content", "")),
            metadata={"source_uri": payload.source_uri},
        )

    def normalize(self, parsed: ParsedData) -> FindingDraft:
        return self._default_normalize(parsed)
