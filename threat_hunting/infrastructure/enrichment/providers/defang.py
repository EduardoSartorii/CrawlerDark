"""DefangProvider.

Responsibility
--------------
Add a *defanged* (safe-to-share) representation of network indicators to the
finding metadata, so exports/reports never contain live clickable URLs/domains.
This is an operational-safety enrichment that runs entirely offline.
"""

from __future__ import annotations

from threat_hunting.core.domain.entities.finding import Finding
from threat_hunting.core.domain.enums import IndicatorType
from threat_hunting.core.domain.value_objects.indicator import Indicator

_NETWORK_TYPES = {IndicatorType.URL, IndicatorType.DOMAIN, IndicatorType.IPV4}


class DefangProvider:
    """Produces safe defanged strings for network indicators."""

    name = "defang"

    def supports(self, indicator: Indicator) -> bool:
        """Return whether the indicator is a network indicator worth defanging."""
        return indicator.type in _NETWORK_TYPES

    def enrich(self, finding: Finding, indicator: Indicator) -> None:
        """Store a defanged version of the indicator in finding metadata."""
        defanged = (
            indicator.value.replace("http", "hxxp").replace(".", "[.]").replace("@", "[at]")
        )
        finding.metadata.setdefault("defanged", {})[indicator.key] = defanged
