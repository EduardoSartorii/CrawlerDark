"""PasteSiteConnector — scraping de agregadores de pastes públicos.

Ideal para Pastebin-like que expõem "latest". Cada seed é uma URL de listagem.
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


@register_connector("paste_site")
class PasteSiteConnector(BaseConnector):
    async def collect(self) -> AsyncIterator[dict[str, Any]]:  # type: ignore[override]
        if self.http is None:
            raise RuntimeError("PasteSiteConnector requires HTTP client")
        seeds: list[str] = list(self.options.get("seeds") or [])
        max_items = int(self.options.get("max_items", 20))
        for seed in seeds:
            try:
                response = await self.http.get(seed)
            except Exception:  # noqa: BLE001
                continue
            soup = BeautifulSoup(response.text, "lxml")
            seen = 0
            for a in soup.find_all("a", href=True):
                href = a["href"]
                title = a.get_text(strip=True)
                if not title or len(title) < 4:
                    continue
                yield {"seed": seed, "url": href, "title": title}
                seen += 1
                if seen >= max_items:
                    break

    async def parse(self, payload: Any) -> dict[str, Any]:
        return payload if isinstance(payload, dict) else {}

    async def normalize(self, parsed: dict[str, Any]) -> Finding:
        title = parsed.get("title", "(paste)")[:400]
        seed = parsed.get("seed", "")
        source = SourceRef(source="paste_site", connector=self.name, url=parsed.get("url"))
        return (
            FindingBuilder()
            .title(f"Paste: {title}")
            .description(f"Paste candidate from {seed}")
            .source(source)
            .category(Category.LEAK)
            .severity(Severity.LOW)
            .raw(parsed)
            .tag("paste", "leak")
            .build()
        )

    async def health(self) -> bool:
        return bool(self.options.get("seeds"))
