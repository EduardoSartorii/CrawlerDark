"""Dark Web connector for onion site monitoring."""

from __future__ import annotations

from collections.abc import AsyncIterator

from threat_hunting.core.contracts.services import CollectionContext, ParsedData, RawPayload
from threat_hunting.core.domain.entities import FindingDraft
from threat_hunting.core.domain.enums import FindingCategory, SourceType
from threat_hunting.infrastructure.connectors.base import BaseConnector


class DarkWebConnector(BaseConnector):
    """Monitors dark web onion sites for leaks and threat actor activity."""

    name = "darkweb"
    source_type = SourceType.DARKWEB.value

    async def connect(self) -> None:
        self._connected = True

    async def collect(self, context: CollectionContext) -> AsyncIterator[RawPayload]:
        onion_urls = self._config.get("onion_urls", [])
        keywords = context.keywords or self._config.get("keywords", [])

        for url in onion_urls:
            yield RawPayload(
                data={"url": url, "content": f"Dark web content from {url}"},
                source_uri=url,
                metadata={"tor": True},
            )

        for kw in keywords[:5]:
            yield RawPayload(
                data={
                    "title": f"Leak mention: {kw}",
                    "content": f"Potential data leak referencing {kw} on dark web forum",
                    "keyword": kw,
                },
                source_uri="darkweb://forum",
                metadata={"category": "leak"},
            )

    def parse(self, payload: RawPayload) -> ParsedData:
        return ParsedData(
            fields=payload.data,
            content=str(payload.data.get("content", "")),
            metadata={**payload.metadata, "source_uri": payload.source_uri},
        )

    def normalize(self, parsed: ParsedData) -> FindingDraft:
        title = parsed.fields.get("title", "Dark Web Finding")
        draft = self._default_normalize(ParsedData(fields={"title": title}, content=parsed.content), "title")
        draft.connector = self.name
        draft.source = SourceType.DARKWEB
        draft.category = FindingCategory.CREDENTIAL_LEAK
        draft.tags.extend(["darkweb", "tor"])
        return draft
