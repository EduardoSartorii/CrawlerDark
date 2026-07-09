"""
AlienVault OTX Connector.

Collects pulses (threat intel bundles) from AlienVault Open Threat Exchange.
OTX is a collaborative threat intelligence platform with millions of IOCs.

Collection Strategy:
    - Subscribes to pulses from followed users and groups
    - Fetches pulses modified since last run (incremental)
    - Extracts all indicator types from pulse indicator sets
"""

from __future__ import annotations

import json
from typing import Any

from ...core.domain.entities.finding import Finding
from ...core.domain.value_objects import ThreatCategory
from ...core.domain.value_objects.source_type import SourceType
from .base import BaseConnector, CollectionContext, ConnectorHealth, ConnectorStatus


class AlienVaultOTXConnector(BaseConnector):
    """
    AlienVault OTX pulse connector.

    Config keys:
        api_key: str — OTX API key (required)
        modified_since: str — ISO datetime for incremental pulls (optional)
        limit: int — max pulses to fetch (default: 50)
    """

    connector_id = "alienvault_otx"
    source_type = SourceType.ALIENVAULT_OTX
    group = "feeds"
    description = "AlienVault Open Threat Exchange (OTX) connector"
    version = "1.0.0"

    _API_BASE = "https://otx.alienvault.com/api/v1"

    async def connect(self) -> None:
        api_key = self._config.get("api_key")
        if not api_key:
            raise ValueError("AlienVault OTX requires 'api_key' in config")
        self._headers = {"X-OTX-API-KEY": api_key}
        self.log.info("otx.connected")

    async def collect(self, ctx: CollectionContext) -> None:
        """Fetch subscribed pulses from OTX."""
        limit = ctx.metadata.get("limit", self._config.get("limit", 50))
        modified_since = self._config.get("modified_since", "")

        params: dict[str, Any] = {"limit": limit}
        if modified_since:
            params["modified_since"] = modified_since

        try:
            resp = await self.http.get(
                f"{self._API_BASE}/pulses/subscribed",
                params=params,
                headers=self._headers,
            )
            if resp.status_code != 200:
                ctx.errors.append(f"OTX API error: {resp.status_code}")
                return

            data = resp.json()
            ctx.raw_items = data.get("results", [])
            self.log.info("otx.fetched", count=len(ctx.raw_items))

        except Exception as exc:
            ctx.errors.append(f"OTX collection failed: {exc}")
            self.log.error("otx.collect_failed", error=str(exc))

    async def parse(self, ctx: CollectionContext) -> None:
        """Extract pulse and indicator data."""
        for pulse in ctx.raw_items:
            ctx.parsed_items.append({
                "id": pulse.get("id", ""),
                "name": pulse.get("name", ""),
                "description": pulse.get("description", ""),
                "author": pulse.get("author_name", ""),
                "created": pulse.get("created", ""),
                "modified": pulse.get("modified", ""),
                "tags": pulse.get("tags", []),
                "tlp": pulse.get("tlp", "white").upper(),
                "malware_families": [m.get("display_name", "") for m in pulse.get("malware_families", [])],
                "attack_ids": [a.get("id", "") for a in pulse.get("attack_ids", [])],
                "industries": pulse.get("industries", []),
                "targeted_countries": pulse.get("targeted_countries", []),
                "indicators": pulse.get("indicators", []),
                "references": pulse.get("references", []),
            })

    async def normalize(self, ctx: CollectionContext) -> None:
        """Convert pulses to Findings."""
        for pulse in ctx.parsed_items:
            ioc_count = len(pulse["indicators"])
            malware = ", ".join(pulse["malware_families"][:3]) or "Unknown"

            title = f"[OTX] {pulse['name'][:200]}"
            description = (
                f"{pulse['description'][:1000]}\n\n"
                f"IOC Count: {ioc_count}\n"
                f"Malware: {malware}\n"
                f"Author: {pulse['author']}\n"
                f"References: {', '.join(pulse['references'][:3])}"
            ).strip()

            finding = Finding.create(
                title=title,
                source="AlienVault OTX",
                connector=self.connector_id,
                category=ThreatCategory.IOC,
                source_type=self.source_type,
                description=description,
                raw_data=json.dumps(pulse),
                tags=["otx", "alienvault"] + pulse["tags"][:10],
            )
            finding.source_id = pulse["id"]
            finding.tlp = pulse["tlp"] if pulse["tlp"] in {"WHITE", "GREEN", "AMBER", "RED"} else "WHITE"
            finding.malware_family = malware if malware != "Unknown" else None
            finding.affected_countries = pulse["targeted_countries"]
            finding.normalized_data = {
                "ioc_count": ioc_count,
                "malware_families": pulse["malware_families"],
                "attack_ids": pulse["attack_ids"],
                "industries": pulse["industries"],
            }
            ctx.findings.append(finding)

    async def close(self) -> None:
        pass

    async def health(self) -> ConnectorHealth:
        try:
            resp = await self.http.get(
                f"{self._API_BASE}/user/me",
                headers=self._headers,
            )
            healthy = resp.status_code == 200
        except Exception as exc:
            return ConnectorHealth(
                connector_id=self.connector_id,
                healthy=False,
                status=ConnectorStatus.ERROR,
                last_error=str(exc),
            )
        return ConnectorHealth(
            connector_id=self.connector_id,
            healthy=healthy,
            status=self._status,
            last_run=self._last_run,
            findings_total=self._total_findings,
        )
