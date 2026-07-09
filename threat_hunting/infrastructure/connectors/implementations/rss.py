"""RSSConnector — coleta feeds RSS/Atom (news, blogs, CERTs)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from ....core.domain.builders import FindingBuilder
from ....core.domain.entities import Finding
from ....core.domain.value_objects import Category, Severity, SourceRef
from ...parsers.rss_parser import RSSParser
from ..base import BaseConnector
from ..registry import register_connector


@register_connector("rss")
class RSSConnector(BaseConnector):
    default_category = "NEWS"

    def __init__(self, *, options: dict[str, Any] | None = None, http=None) -> None:  # type: ignore[no-untyped-def]
        super().__init__(options=options, http=http)
        self._parser = RSSParser()

    async def collect(self) -> AsyncIterator[dict[str, Any]]:  # type: ignore[override]
        url = str(self.options.get("url"))
        max_items = int(self.options.get("max_items", 30))
        if self.http is None:
            raise RuntimeError("RSSConnector requires HTTP client")
        response = await self.http.get(url)
        items = await self._parser.parse(response.content)
        for item in items[:max_items]:
            yield item

    async def parse(self, payload: Any) -> dict[str, Any]:
        return payload if isinstance(payload, dict) else {}

    async def normalize(self, parsed: dict[str, Any]) -> Finding:
        title = str(parsed.get("title") or "(no title)").strip()
        description = str(parsed.get("description") or "").strip()
        link = parsed.get("link") or self.options.get("url")
        source = SourceRef(
            source=self.name,
            connector=self.name,
            url=link,
            collected_at=parsed.get("published_at") or None,  # type: ignore[arg-type]
        )
        return (
            FindingBuilder()
            .title(title[:400])
            .description(description[:2000])
            .source(source)
            .category(Category.NEWS)
            .severity(Severity.INFO)
            .raw(parsed)
            .normalized({"title": title, "description": description, "url": link})
            .build()
        )

    async def health(self) -> bool:
        return bool(self.options.get("url"))
