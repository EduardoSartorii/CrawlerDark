"""feeds connector.

Responsibility
--------------
Generic threat intel feed ingestion

Inherits BaseConnector (via SimpleConnector). Discovered automatically by
ConnectorRegistry — Core is never modified.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any, ClassVar

from threat_hunting.connectors.common import SimpleConnector
from threat_hunting.connectors.registry import register_connector
from threat_hunting.core.domain.enums import FindingCategory


@register_connector
class FeedsConnector(SimpleConnector):
    """Generic threat intel feed ingestion."""

    name: ClassVar[str] = "feeds"
    category_group: ClassVar[str] = "feeds"
    default_category: ClassVar[FindingCategory] = FindingCategory.IOC
    default_source: ClassVar[str] = "feeds"
    opsec_profile_name: ClassVar[str] = "default"

    def _demo_samples(self) -> list[dict[str, Any]]:
        return [
            {
                "title": "[feeds] Generic threat intel feed ingestion",
                "description": (
                    "Generic threat intel feed ingestion. Sample IOCs for pipeline validation: "
                    "user@corp-demo.com 198.51.100.42 malware.example "
                    "CVE-2024-12345 wallet 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
                ),
                "url": "https://example.local/feeds/item/1",
                "author": "feeds-collector",
                "tags": ["feeds", "feeds", "demo"],
                "category": "ioc",
                "severity": "medium",
            }
        ]

    async def _fetch(self) -> AsyncIterator[dict[str, Any]]:
        # Live mode: if endpoint/token provided in options, subclasses may override.
        endpoint = self._options.get("endpoint")
        if endpoint and self._transport is not None:
            try:
                response = await self.http_get(endpoint)
                data = response.json() if hasattr(response, "json") else {}
                items = data if isinstance(data, list) else data.get("items") or data.get("data") or [data]
                for item in items:
                    if isinstance(item, dict):
                        yield item
                return
            except Exception as exc:
                self._log.warning("connector.live_fetch_failed", error=str(exc))
        async for item in super()._fetch():
            yield item
