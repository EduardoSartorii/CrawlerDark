"""Enrichment engine — enriches findings via external intelligence APIs."""

from __future__ import annotations

import structlog

from threat_hunting.core.contracts.services import IEnrichmentEngine
from threat_hunting.core.domain.entities import Finding
from threat_hunting.core.domain.enums import IndicatorType

logger = structlog.get_logger(__name__)


class EnrichmentEngine(IEnrichmentEngine):
    """Enriches findings with reputation and context from external sources.

    Adapters for VirusTotal, GreyNoise, AbuseIPDB, Shodan, etc. are
    injected via the integrations layer.
    """

    def __init__(self, integrations: dict | None = None) -> None:
        self._integrations = integrations or {}

    async def enrich(self, finding: Finding) -> Finding:
        enrichment_data: dict = {}

        for indicator in finding.indicators:
            if indicator.type == IndicatorType.IP:
                enrichment_data[indicator.value] = await self._enrich_ip(indicator.value)
            elif indicator.type == IndicatorType.DOMAIN:
                enrichment_data[indicator.value] = await self._enrich_domain(indicator.value)
            elif indicator.type in (IndicatorType.HASH_MD5, IndicatorType.HASH_SHA256):
                enrichment_data[indicator.value] = await self._enrich_hash(indicator.value)

        if enrichment_data:
            finding.metadata["enrichment"] = enrichment_data
            finding.add_timeline_event("enrichment", f"Enriched {len(enrichment_data)} indicators")

        logger.info("enrichment.completed", finding_id=str(finding.id), enriched=len(enrichment_data))
        return finding

    async def _enrich_ip(self, ip: str) -> dict:
        adapter = self._integrations.get("greynoise") or self._integrations.get("abuseipdb")
        if adapter:
            return await adapter.lookup_ip(ip)
        return {"ip": ip, "reputation": "unknown", "source": "local"}

    async def _enrich_domain(self, domain: str) -> dict:
        adapter = self._integrations.get("virustotal")
        if adapter:
            return await adapter.lookup_domain(domain)
        return {"domain": domain, "reputation": "unknown", "source": "local"}

    async def _enrich_hash(self, hash_value: str) -> dict:
        adapter = self._integrations.get("virustotal")
        if adapter:
            return await adapter.lookup_hash(hash_value)
        return {"hash": hash_value, "detections": 0, "source": "local"}
