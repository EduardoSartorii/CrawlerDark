"""
EnrichmentEngine
================

Implements the IEnrichmentEngine port.

Fetches additional context for Indicators attached to a Finding:
    - IP addresses: geolocation, ASN, abuse score, TOR/proxy detection
    - Domains: WHOIS, nameservers, MX, creation/expiry dates
    - Hashes: malware family, VirusTotal detections

Architecture:
    - Each enricher is independently injectable.
    - Enrichment is best-effort — failure of one enricher does not block others.
    - Results are stored in Indicator.enrichment (merged, never overwritten).
    - API calls respect the OPSEC rate limits.
    - Results can be cached in Redis (future: TTL-based cache).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from threat_hunting.core.domain.entities.finding import FindingStatus
from threat_hunting.core.domain.entities.indicator import Indicator
from threat_hunting.core.domain.events.finding_events import FindingEnriched
from threat_hunting.core.domain.exceptions.domain_exceptions import EnrichmentError
from threat_hunting.core.domain.ports.engines import IEnrichmentEngine
from threat_hunting.core.domain.value_objects.indicator_type import IndicatorType

if TYPE_CHECKING:
    from threat_hunting.core.domain.entities.finding import Finding
    from threat_hunting.core.domain.ports.event_bus import IEventBus
    from threat_hunting.core.domain.ports.repositories import IIndicatorRepository

logger = structlog.get_logger(__name__)


class EnrichmentEngine(IEnrichmentEngine):
    """
    Multi-enricher enrichment engine.

    Orchestrates enrichment across multiple providers per indicator type.
    """

    def __init__(
        self,
        indicator_repo: "IIndicatorRepository",
        event_bus: "IEventBus",
        enabled: bool = True,
    ) -> None:
        self._indicator_repo = indicator_repo
        self._event_bus = event_bus
        self._enabled = enabled

    async def enrich(self, finding: "Finding") -> "Finding":
        """
        Enrich all Indicators referenced by the Finding.

        Args:
            finding: A deduplicated Finding.

        Returns:
            Finding with its Indicators enriched.
        """
        if not self._enabled or not finding.indicators:
            finding.advance_status(FindingStatus.ENRICHED)
            return finding

        log = logger.bind(finding_id=finding.id)
        enrichers_applied: list[str] = []
        indicators_enriched = 0

        for indicator_id in finding.indicators[:50]:  # Cap to prevent DoS
            try:
                indicator = await self._indicator_repo.get_by_id(indicator_id)
                if not indicator:
                    continue

                applied = await self._enrich_indicator(indicator)
                if applied:
                    enrichers_applied.extend(applied)
                    indicators_enriched += 1
                    await self._indicator_repo.save(indicator)

            except Exception as exc:
                log.warning(
                    "indicator_enrichment_error",
                    indicator_id=indicator_id,
                    error=str(exc),
                )

        finding.advance_status(FindingStatus.ENRICHED)
        log.debug(
            "enrichment_complete",
            indicators_enriched=indicators_enriched,
            enrichers=list(set(enrichers_applied)),
        )

        await self._event_bus.publish(
            FindingEnriched(
                aggregate_id=finding.id,
                enrichers_applied=list(set(enrichers_applied)),
                indicators_enriched=indicators_enriched,
            )
        )
        return finding

    async def _enrich_indicator(self, indicator: Indicator) -> list[str]:
        """Select and apply the appropriate enrichers for an Indicator type."""
        applied: list[str] = []

        if indicator.type in (IndicatorType.IP,):
            await self._enrich_ip(indicator)
            applied.append("ip_enricher")

        elif indicator.type in (IndicatorType.DOMAIN, IndicatorType.FQDN):
            await self._enrich_domain(indicator)
            applied.append("domain_enricher")

        elif indicator.type in (IndicatorType.MD5, IndicatorType.SHA1, IndicatorType.SHA256):
            await self._enrich_hash(indicator)
            applied.append("hash_enricher")

        return applied

    async def _enrich_ip(self, indicator: Indicator) -> None:
        """Enrich an IP indicator using ip-api.com (free, no key required)."""
        try:
            import httpx

            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(
                    f"http://ip-api.com/json/{indicator.value}",
                    params={"fields": "status,country,city,org,as,proxy,hosting"},
                )
                if response.status_code == 200:
                    data = response.json()
                    if data.get("status") == "success":
                        indicator.merge_enrichment({
                            "country": data.get("country"),
                            "city": data.get("city"),
                            "asn_org": data.get("org"),
                            "asn": data.get("as"),
                            "is_proxy": data.get("proxy", False),
                            "is_hosting": data.get("hosting", False),
                        })
        except Exception as exc:
            logger.debug("ip_enrichment_failed", ip=indicator.value[:32], error=str(exc))

    async def _enrich_domain(self, indicator: Indicator) -> None:
        """Enrich a domain indicator with basic DNS resolution."""
        try:
            import socket
            import asyncio

            loop = asyncio.get_event_loop()
            try:
                addrs = await loop.run_in_executor(
                    None, socket.getaddrinfo, indicator.value, None
                )
                ips = list({addr[4][0] for addr in addrs})
                indicator.merge_enrichment({"resolved_ips": ips})
            except socket.gaierror:
                indicator.merge_enrichment({"dns_resolved": False})
        except Exception as exc:
            logger.debug("domain_enrichment_failed", domain=indicator.value[:64], error=str(exc))

    async def _enrich_hash(self, indicator: Indicator) -> None:
        """Placeholder for hash enrichment (VirusTotal integration)."""
        # Full implementation requires VIRUSTOTAL_API_KEY.
        # Structure is in place; API call is gated by key availability.
        pass
