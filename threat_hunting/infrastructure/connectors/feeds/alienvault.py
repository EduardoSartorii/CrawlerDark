"""
AlienVault OTX Connector
========================

Collects threat intelligence from AlienVault Open Threat Exchange (OTX).
OTX provides Pulses — curated threat intelligence packages containing IOCs,
TTPs, and contextual information.

API documentation: https://otx.alienvault.com/api
Requires: ALIENVAULT_OTX_API_KEY

Collection strategy:
    - Fetches subscribed pulses modified in the last N days.
    - Each pulse is normalized into a Finding.
    - Indicators within the pulse become Indicator entities (via Extractor).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, AsyncIterator

import structlog

from threat_hunting.core.domain.entities.finding import Finding, FindingStatus
from threat_hunting.core.domain.exceptions.domain_exceptions import ConnectorError
from threat_hunting.core.domain.ports.connectors import ConnectorHealthStatus
from threat_hunting.core.domain.value_objects.category import Category
from threat_hunting.core.domain.value_objects.source import SourceType
from threat_hunting.infrastructure.connectors.base import BaseConnector

logger = structlog.get_logger(__name__)

OTX_API = "https://otx.alienvault.com/api/v1"


class AlienVaultOTXConnector(BaseConnector):
    """
    AlienVault OTX pulse connector.
    """

    connector_id = "alienvault"
    connector_name = "AlienVault OTX Connector"
    source_type = SourceType.FEED.value

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._api_key: str = self._config.get("api_key", "")
        self._days_back: int = self._config.get("days_back", 1)
        self._subscribed_only: bool = self._config.get("subscribed_pulses", True)

    async def connect(self) -> None:
        """Validate API key and set authorization header."""
        if not self._api_key:
            raise ConnectorError(
                "AlienVault OTX requires ALIENVAULT_OTX_API_KEY",
                context={"connector": self.connector_id},
            )
        await super().connect()
        if self._session:
            self._session.headers.update({"X-OTX-API-KEY": self._api_key})

    async def collect(self) -> AsyncIterator[dict]:
        """Fetch subscribed pulses from OTX."""
        since = (datetime.now(timezone.utc) - timedelta(days=self._days_back)).isoformat()
        page = 1

        while True:
            response = await self._get(
                f"{OTX_API}/pulses/subscribed",
                params={"modified_since": since, "limit": 50, "page": page},
            )
            data = response.json()
            pulses: list[dict] = data.get("results", [])

            if not pulses:
                break

            for pulse in pulses:
                yield pulse

            if not data.get("next"):
                break
            page += 1

    async def parse(self, raw_item: dict) -> dict:
        """Parse an OTX Pulse into structured data."""
        indicators = raw_item.get("indicators", [])
        return {
            "id": raw_item.get("id"),
            "name": raw_item.get("name", "Untitled Pulse"),
            "description": raw_item.get("description", ""),
            "author": raw_item.get("author", {}).get("username", "unknown"),
            "tlp": raw_item.get("tlp", "white"),
            "tags": raw_item.get("tags", []),
            "malware_families": raw_item.get("malware_families", []),
            "attack_ids": raw_item.get("attack_ids", []),
            "industries": raw_item.get("industries", []),
            "indicators": [
                {"type": i.get("type"), "indicator": i.get("indicator"), "description": i.get("description")}
                for i in indicators
            ],
            "indicator_count": len(indicators),
            "references": raw_item.get("references", []),
            "created": raw_item.get("created"),
            "modified": raw_item.get("modified"),
        }

    async def normalize(self, parsed_item: dict) -> Finding:
        """Convert a parsed OTX Pulse into a Finding."""
        category = Category.IOC
        if any("ransomware" in (t.lower() if isinstance(t, str) else "") for t in parsed_item.get("tags", [])):
            category = Category.RANSOMWARE
        elif any("phishing" in (t.lower() if isinstance(t, str) else "") for t in parsed_item.get("tags", [])):
            category = Category.PHISHING

        return Finding(
            title=f"[OTX] {parsed_item['name']}"[:512],
            description=parsed_item.get("description", "")[:4096],
            source=SourceType.FEED,
            connector=self.connector_id,
            category=category,
            status=FindingStatus.NORMALIZED,
            source_id=str(parsed_item.get("id", "")),
            source_url=f"https://otx.alienvault.com/pulse/{parsed_item.get('id', '')}",
            raw_data=str(parsed_item),
            normalized_data={
                "platform": "alienvault_otx",
                "pulse_name": parsed_item.get("name"),
                "author": parsed_item.get("author"),
                "tlp": parsed_item.get("tlp"),
                "indicator_count": parsed_item.get("indicator_count", 0),
                "malware_families": parsed_item.get("malware_families"),
                "attack_ids": parsed_item.get("attack_ids"),
                "indicators": parsed_item.get("indicators", []),
            },
            metadata={
                "industries": parsed_item.get("industries"),
                "references": parsed_item.get("references"),
            },
            tags=["alienvault", "otx", "pulse"]
            + [str(t) for t in parsed_item.get("tags", [])],
        )

    async def health(self) -> ConnectorHealthStatus:
        """Check OTX API availability."""
        try:
            import time
            start = time.perf_counter()
            await self._get(f"{OTX_API}/user/me")
            latency = (time.perf_counter() - start) * 1000
            return ConnectorHealthStatus(
                healthy=True, message="OTX API reachable", latency_ms=latency
            )
        except Exception as exc:
            return ConnectorHealthStatus(healthy=False, message=str(exc))
