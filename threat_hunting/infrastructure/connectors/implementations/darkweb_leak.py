"""DarkwebLeakConnector — scraping de leak sites .onion.

Assume perfil OPSEC ``tor`` (SOCKS5 → 127.0.0.1:9050). Cada URL representa
a home page do site de vazamento de um threat actor.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from bs4 import BeautifulSoup

from ....core.domain.builders import FindingBuilder
from ....core.domain.entities import Finding
from ....core.domain.value_objects import Category, Severity, SourceRef
from ..base import BaseConnector
from ..registry import register_connector


@register_connector("darkweb_leak")
class DarkwebLeakConnector(BaseConnector):
    async def collect(self) -> AsyncIterator[dict[str, Any]]:  # type: ignore[override]
        if self.http is None:
            raise RuntimeError("DarkwebLeakConnector requires HTTP client")
        onions: list[str] = list(self.options.get("onion_urls") or [])
        max_items = int(self.options.get("max_items", 10))
        for onion in onions:
            try:
                response = await self.http.get(onion)
            except Exception:  # noqa: BLE001
                continue
            soup = BeautifulSoup(response.text, "lxml")
            for i, h in enumerate(soup.find_all(["h1", "h2", "h3"])):
                if i >= max_items:
                    break
                title = h.get_text(strip=True)
                if not title:
                    continue
                yield {"onion": onion, "title": title, "text": soup.get_text(" ", strip=True)[:2000]}

    async def parse(self, payload: Any) -> dict[str, Any]:
        return payload if isinstance(payload, dict) else {}

    async def normalize(self, parsed: dict[str, Any]) -> Finding:
        onion = parsed.get("onion", "")
        title = parsed.get("title", "(darkweb entry)")[:400]
        source = SourceRef(source="darkweb", connector=self.name, url=onion)
        return (
            FindingBuilder()
            .title(f"Darkweb: {title}")
            .description(parsed.get("text", "")[:1500])
            .source(source)
            .category(Category.DARKWEB)
            .severity(Severity.HIGH)
            .raw(parsed)
            .tag("darkweb", "leak-site", "onion")
            .build()
        )

    async def health(self) -> bool:
        return bool(self.options.get("onion_urls"))
