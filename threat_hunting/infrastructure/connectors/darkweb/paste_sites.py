"""
Paste Sites Connector
=====================

Monitors public paste sites for leaked credentials, source code, IOCs,
and other sensitive information.

Monitored sources (configurable):
    - Pastebin (public API)
    - paste.ee
    - ghostbin.com
    - privatebin instances
    - Other configured paste URLs

OPSEC:
    - Uses the 'standard' OPSEC profile by default.
    - Dark web paste sites use the 'darkweb' profile (TOR proxy).
    - Rate limiting prevents IP bans.

Detection:
    - Each paste is passed through the Detection Engine.
    - Pastes matching credential/card/IOC patterns are scored HIGH.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, AsyncIterator

import structlog

from threat_hunting.core.domain.entities.finding import Finding, FindingStatus
from threat_hunting.core.domain.ports.connectors import ConnectorHealthStatus
from threat_hunting.core.domain.value_objects.category import Category
from threat_hunting.core.domain.value_objects.source import SourceType
from threat_hunting.infrastructure.connectors.base import BaseConnector

logger = structlog.get_logger(__name__)

PASTEBIN_PUBLIC_API = "https://scrape.pastebin.com/api_scraping.php"
PASTEBIN_ITEM_API = "https://scrape.pastebin.com/api_scrape_item.php"


class PasteSitesConnector(BaseConnector):
    """
    Connector for monitoring public paste sites.

    Collects recent public pastes and checks for sensitive content.
    """

    connector_id = "paste"
    connector_name = "Paste Sites Connector"
    source_type = SourceType.PASTE.value

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._limit: int = self._config.get("limit", 100)
        self._include_raw: bool = self._config.get("include_raw", True)

    async def collect(self) -> AsyncIterator[dict]:
        """Fetch recent pastes from Pastebin scraping API."""
        try:
            response = await self._get(
                PASTEBIN_PUBLIC_API,
                params={"limit": self._limit},
            )
            pastes: list[dict] = response.json()

            for paste_meta in pastes:
                item = dict(paste_meta)
                # Optionally fetch raw content for deep analysis.
                if self._include_raw and paste_meta.get("key"):
                    try:
                        raw_response = await self._get(
                            PASTEBIN_ITEM_API,
                            params={"i": paste_meta["key"]},
                        )
                        item["_raw_content"] = raw_response.text
                    except Exception:
                        item["_raw_content"] = None
                yield item

        except Exception as exc:
            self._logger.warning("paste_collection_error", error=str(exc))

    async def parse(self, raw_item: dict) -> dict:
        """Parse a paste item into structured data."""
        return {
            "id": raw_item.get("key"),
            "title": raw_item.get("title") or "Untitled Paste",
            "content": raw_item.get("_raw_content") or "",
            "url": f"https://pastebin.com/{raw_item.get('key', '')}",
            "author": raw_item.get("user") or "anonymous",
            "size": raw_item.get("size"),
            "expire": raw_item.get("expire"),
            "syntax": raw_item.get("syntax"),
            "hits": raw_item.get("hits"),
            "published_at": datetime.fromtimestamp(
                int(raw_item.get("date", 0) or 0), tz=timezone.utc
            ),
        }

    async def normalize(self, parsed_item: dict) -> Finding:
        """Convert a parsed paste into a Finding."""
        content = parsed_item.get("content", "")
        title = parsed_item.get("title", "Untitled Paste")
        return Finding(
            title=f"[Paste] {title}"[:512],
            description=content[:2048],
            source=SourceType.PASTE,
            connector=self.connector_id,
            category=Category.PASTE,
            status=FindingStatus.NORMALIZED,
            source_id=parsed_item.get("id"),
            source_url=parsed_item.get("url"),
            source_published_at=parsed_item.get("published_at"),
            raw_data=content,
            normalized_data={
                "platform": "pastebin",
                "author": parsed_item.get("author"),
                "syntax": parsed_item.get("syntax"),
                "size": parsed_item.get("size"),
            },
            metadata={
                "hits": parsed_item.get("hits"),
                "expire": parsed_item.get("expire"),
            },
            tags=["paste", "pastebin"],
        )

    async def health(self) -> ConnectorHealthStatus:
        """Check Pastebin API availability."""
        try:
            import time
            start = time.perf_counter()
            await self._get(PASTEBIN_PUBLIC_API, params={"limit": "1"})
            latency = (time.perf_counter() - start) * 1000
            return ConnectorHealthStatus(
                healthy=True, message="Pastebin API reachable", latency_ms=latency
            )
        except Exception as exc:
            return ConnectorHealthStatus(healthy=False, message=str(exc))
