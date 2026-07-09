"""
ThreatFox Connector
===================

Collects recent IOCs from ThreatFox (abuse.ch) via the public API.
ThreatFox provides malware IOCs: URLs, domains, IPs, hashes.

API documentation: https://threatfox.abuse.ch/api/
No API key required for public endpoints.

Collection strategy:
    - Fetches IOCs added in the last N days (configurable, default=1).
    - Each IOC is normalized into a Finding with category=IOC.
    - The Extractor stage enriches the Finding with typed Indicator objects.
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

THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"


class ThreatFoxConnector(BaseConnector):
    """
    ThreatFox IOC feed connector.

    Returns recent IOCs from the ThreatFox platform by abuse.ch.
    """

    connector_id = "threatfox"
    connector_name = "ThreatFox Connector"
    source_type = SourceType.FEED.value

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._days_back: int = self._config.get("days_back", 1)

    async def collect(self) -> AsyncIterator[dict]:
        """Fetch recent IOCs from ThreatFox API."""
        payload = {"query": "get_iocs", "days": self._days_back}
        response = await self._post(THREATFOX_API, json=payload)
        data = response.json()

        if data.get("query_status") != "ok":
            self._logger.warning(
                "threatfox_query_failed", status=data.get("query_status")
            )
            return

        for ioc in data.get("data", []):
            yield ioc

    async def parse(self, raw_item: dict) -> dict:
        """Extract structured fields from a ThreatFox IOC record."""
        return {
            "id": raw_item.get("id"),
            "ioc": raw_item.get("ioc"),
            "ioc_type": raw_item.get("ioc_type"),
            "threat_type": raw_item.get("threat_type"),
            "threat_type_desc": raw_item.get("threat_type_desc"),
            "malware": raw_item.get("malware"),
            "malware_alias": raw_item.get("malware_alias"),
            "malware_printable": raw_item.get("malware_printable"),
            "confidence_level": raw_item.get("confidence_level", 50),
            "first_seen": raw_item.get("first_seen"),
            "last_seen": raw_item.get("last_seen"),
            "reporter": raw_item.get("reporter"),
            "reference": raw_item.get("reference"),
            "tags": raw_item.get("tags", []),
        }

    async def normalize(self, parsed_item: dict) -> Finding:
        """Convert a parsed ThreatFox IOC into a Finding."""
        malware = parsed_item.get("malware_printable") or parsed_item.get("malware", "Unknown")
        ioc_type = parsed_item.get("ioc_type", "unknown")
        ioc_value = parsed_item.get("ioc", "")

        confidence = (parsed_item.get("confidence_level", 50)) / 100.0

        return Finding(
            title=f"[ThreatFox] {malware} IOC: {ioc_type} — {ioc_value[:64]}",
            description=(
                f"Threat type: {parsed_item.get('threat_type_desc', 'unknown')}. "
                f"Malware family: {malware}. "
                f"IOC: {ioc_value}. "
                f"Reporter: {parsed_item.get('reporter', 'unknown')}."
            ),
            source=SourceType.FEED,
            connector=self.connector_id,
            category=Category.IOC,
            status=FindingStatus.NORMALIZED,
            confidence=confidence,
            source_id=str(parsed_item.get("id", "")),
            source_url=parsed_item.get("reference"),
            raw_data=str(parsed_item),
            normalized_data={
                "platform": "threatfox",
                "ioc": ioc_value,
                "ioc_type": ioc_type,
                "malware": malware,
                "threat_type": parsed_item.get("threat_type"),
                "confidence": parsed_item.get("confidence_level"),
            },
            metadata={
                "reporter": parsed_item.get("reporter"),
                "first_seen": parsed_item.get("first_seen"),
                "last_seen": parsed_item.get("last_seen"),
            },
            tags=["threatfox", "ioc", malware.lower().replace(" ", "_")]
            + [t for t in (parsed_item.get("tags") or []) if isinstance(t, str)],
        )

    async def health(self) -> ConnectorHealthStatus:
        """Check ThreatFox API availability."""
        try:
            import time
            start = time.perf_counter()
            await self._post(THREATFOX_API, json={"query": "get_iocs", "days": 0})
            latency = (time.perf_counter() - start) * 1000
            return ConnectorHealthStatus(
                healthy=True, message="ThreatFox API reachable", latency_ms=latency
            )
        except Exception as exc:
            return ConnectorHealthStatus(healthy=False, message=str(exc))
