"""
URLhaus Connector
=================

Collects malicious URL data from URLhaus (abuse.ch).
URLhaus tracks URLs hosting malware, phishing pages, and exploit kits.

API documentation: https://urlhaus-api.abuse.ch/
No API key required for public endpoints.

Collection strategy:
    - Downloads the recent URLs CSV/JSON feed.
    - Filters by status (online, offline, unknown).
    - Each URL becomes a Finding with category=MALWARE or PHISHING.
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

URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/"


class URLhausConnector(BaseConnector):
    """URLhaus malicious URL connector."""

    connector_id = "urlhaus"
    connector_name = "URLhaus Connector"
    source_type = SourceType.FEED.value

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._status_filter: list[str] = self._config.get(
            "status_filter", ["online", "unknown"]
        )

    async def collect(self) -> AsyncIterator[dict]:
        """Fetch recent malicious URLs from URLhaus."""
        response = await self._post(URLHAUS_API + "urls/recent/", data={"limit": "1000"})
        data = response.json()

        if data.get("query_status") != "ok":
            self._logger.warning("urlhaus_query_failed", status=data.get("query_status"))
            return

        for url_entry in data.get("urls", []):
            if url_entry.get("url_status") in self._status_filter or not self._status_filter:
                yield url_entry

    async def parse(self, raw_item: dict) -> dict:
        """Parse a URLhaus URL entry."""
        return {
            "id": raw_item.get("id"),
            "url": raw_item.get("url"),
            "url_status": raw_item.get("url_status"),
            "host": raw_item.get("host"),
            "date_added": raw_item.get("date_added"),
            "threat": raw_item.get("threat"),
            "blacklists": raw_item.get("blacklists", {}),
            "reporter": raw_item.get("reporter"),
            "tags": raw_item.get("tags", []),
            "payloads": raw_item.get("payloads", []),
        }

    async def normalize(self, parsed_item: dict) -> Finding:
        """Convert a parsed URLhaus entry into a Finding."""
        threat = parsed_item.get("threat", "malware_download")
        category = Category.PHISHING if "phishing" in threat.lower() else Category.MALWARE

        return Finding(
            title=f"[URLhaus] {threat}: {parsed_item.get('url', '')[:96]}",
            description=(
                f"Malicious URL detected by URLhaus. "
                f"Host: {parsed_item.get('host', 'unknown')}. "
                f"Status: {parsed_item.get('url_status', 'unknown')}. "
                f"Threat: {threat}."
            ),
            source=SourceType.FEED,
            connector=self.connector_id,
            category=category,
            status=FindingStatus.NORMALIZED,
            source_id=str(parsed_item.get("id", "")),
            source_url=f"https://urlhaus.abuse.ch/url/{parsed_item.get('id', '')}/",
            raw_data=str(parsed_item),
            normalized_data={
                "platform": "urlhaus",
                "url": parsed_item.get("url"),
                "host": parsed_item.get("host"),
                "url_status": parsed_item.get("url_status"),
                "threat": threat,
                "payloads": parsed_item.get("payloads", []),
            },
            metadata={
                "reporter": parsed_item.get("reporter"),
                "blacklists": parsed_item.get("blacklists"),
                "date_added": parsed_item.get("date_added"),
            },
            tags=["urlhaus", "malicious_url", threat.lower()]
            + [str(t) for t in (parsed_item.get("tags") or []) if t],
        )

    async def health(self) -> ConnectorHealthStatus:
        """Check URLhaus API availability."""
        try:
            import time
            start = time.perf_counter()
            await self._post(URLHAUS_API + "urls/recent/", data={"limit": "1"})
            latency = (time.perf_counter() - start) * 1000
            return ConnectorHealthStatus(
                healthy=True, message="URLhaus API reachable", latency_ms=latency
            )
        except Exception as exc:
            return ConnectorHealthStatus(healthy=False, message=str(exc))
