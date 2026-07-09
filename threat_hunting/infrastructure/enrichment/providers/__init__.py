"""Built-in enrichment providers.

These are self-contained (no external API keys) so the platform enriches out of
the box. Network-backed providers (GreyNoise, VirusTotal, AbuseIPDB, Shodan,
Censys, URLHaus, OTX) follow the same protocol and plug in identically.
"""

from threat_hunting.infrastructure.enrichment.providers.geo_tag import GeoTagProvider
from threat_hunting.infrastructure.enrichment.providers.defang import DefangProvider

__all__ = ["GeoTagProvider", "DefangProvider"]
