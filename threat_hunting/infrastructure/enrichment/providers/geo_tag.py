"""GeoTagProvider.

Responsibility
--------------
A dependency-free enrichment provider that classifies IPv4 indicators as
private/public and tags the finding accordingly. It demonstrates the provider
contract and gives useful, offline enrichment (private-range detection is a
common triage signal) without needing a GeoIP database or API key.
"""

from __future__ import annotations

import ipaddress

from threat_hunting.core.domain.entities.finding import Finding
from threat_hunting.core.domain.enums import IndicatorType
from threat_hunting.core.domain.value_objects.indicator import Indicator


class GeoTagProvider:
    """Tags IPv4 indicators as private/public/reserved (offline)."""

    name = "geo_tag"

    def supports(self, indicator: Indicator) -> bool:
        """Return whether the indicator is an IPv4 address."""
        return indicator.type is IndicatorType.IPV4

    def enrich(self, finding: Finding, indicator: Indicator) -> None:
        """Add a scope tag/metadata entry describing the IP's address space."""
        try:
            ip = ipaddress.ip_address(indicator.value)
        except ValueError:
            return
        if ip.is_private:
            scope = "private"
        elif ip.is_reserved or ip.is_loopback or ip.is_link_local:
            scope = "reserved"
        else:
            scope = "public"
        finding.add_tag(f"ip:{scope}")
        finding.metadata.setdefault("ip_scopes", {})[indicator.value] = scope
