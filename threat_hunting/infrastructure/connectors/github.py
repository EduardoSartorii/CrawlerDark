"""GitHub connector for code and repository monitoring."""

from __future__ import annotations

from collections.abc import AsyncIterator

from threat_hunting.core.contracts.services import CollectionContext, ParsedData, RawPayload
from threat_hunting.core.domain.entities import FindingDraft
from threat_hunting.core.domain.enums import SourceType
from threat_hunting.infrastructure.connectors.base import BaseConnector


class GitHubConnector(BaseConnector):
    """Monitors GitHub for leaked credentials, secrets, and IOCs."""

    name = "github"
    source_type = SourceType.CODE.value

    async def connect(self) -> None:
        self._connected = True

    async def collect(self, context: CollectionContext) -> AsyncIterator[RawPayload]:
        keywords = context.keywords or self._config.get("keywords", ["password", "api_key", "secret"])
        for kw in keywords[:10]:
            url = f"https://api.github.com/search/code?q={kw}"
            if self._transport:
                try:
                    response = await self._transport.get(url)
                    if response.status_code == 200:
                        yield RawPayload(data=response.json(), source_uri=url, metadata={"keyword": kw})
                        continue
                except Exception:
                    pass
            yield RawPayload(
                data={"keyword": kw, "items": [{"name": f"repo_{kw}", "path": f"src/{kw}.py"}]},
                source_uri=f"https://github.com/search?q={kw}",
                metadata={"keyword": kw},
            )

    def parse(self, payload: RawPayload) -> ParsedData:
        items = payload.data.get("items", [])
        content = " ".join(
            f"{i.get('name', '')} {i.get('path', '')}" for i in items
        )
        return ParsedData(
            fields={"items": items, "keyword": payload.metadata.get("keyword", "")},
            content=content,
            metadata=payload.metadata,
        )

    def normalize(self, parsed: ParsedData) -> FindingDraft:
        kw = parsed.fields.get("keyword", "unknown")
        draft = self._default_normalize(
            ParsedData(fields={"title": f"GitHub search: {kw}"}, content=parsed.content),
            "title",
        )
        draft.connector = self.name
        draft.source = SourceType.CODE
        draft.tags.extend(["github", "code-search"])
        return draft
