"""GenericHTTPConnector — scraping simples com seletores CSS."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from bs4 import BeautifulSoup

from ....core.domain.builders import FindingBuilder
from ....core.domain.entities import Finding
from ....core.domain.value_objects import Category, Severity, SourceRef
from ..base import BaseConnector
from ..registry import register_connector


@register_connector("generic_http")
class GenericHTTPConnector(BaseConnector):
    async def collect(self) -> AsyncIterator[dict[str, Any]]:  # type: ignore[override]
        if self.http is None:
            raise RuntimeError("GenericHTTPConnector requires HTTP client")
        url = str(self.options.get("url", ""))
        if not url:
            return
        response = await self.http.get(url)
        yield {"url": url, "html": response.text}

    async def parse(self, payload: Any) -> dict[str, Any]:
        html = payload.get("html", "") if isinstance(payload, dict) else ""
        soup = BeautifulSoup(html, "lxml")
        selectors: dict[str, Any] = self.options.get("selectors") or {}
        result: dict[str, Any] = {"url": payload.get("url") if isinstance(payload, dict) else None}
        for field, sel in selectors.items():
            el = soup.select_one(str(sel))
            result[field] = el.get_text(" ", strip=True) if el else ""
        # Fallback body
        result.setdefault("body", soup.get_text(" ", strip=True))
        return result

    async def normalize(self, parsed: dict[str, Any]) -> Finding:
        title = str(parsed.get("title") or self.options.get("url") or "(page)")[:400]
        body = str(parsed.get("body") or "")[:4000]
        source = SourceRef(source="http", connector=self.name, url=parsed.get("url"))
        return (
            FindingBuilder()
            .title(title)
            .description(body[:2000])
            .source(source)
            .category(Category.OTHER)
            .severity(Severity.INFO)
            .raw(parsed)
            .tag("scrape")
            .build()
        )

    async def health(self) -> bool:
        return bool(self.options.get("url"))
