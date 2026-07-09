"""Enrichment provider port.

Responsibility
--------------
Define the contract for enrichment sources (GreyNoise, VirusTotal, AbuseIPDB,
Shodan, WHOIS, GeoIP, ...). The enrichment engine iterates registered providers
and lets each augment a finding's indicators/metadata. Each provider is a
Strategy, added without touching the engine.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from threat_hunting.core.domain.entities.finding import Finding
from threat_hunting.core.domain.value_objects.indicator import Indicator


@runtime_checkable
class EnrichmentProvider(Protocol):
    """Contract for a single enrichment source."""

    name: str

    def supports(self, indicator: Indicator) -> bool:
        """Return whether this provider can enrich the given indicator type."""
        ...

    def enrich(self, finding: Finding, indicator: Indicator) -> None:
        """Augment ``finding`` in place using data about ``indicator``."""
        ...
