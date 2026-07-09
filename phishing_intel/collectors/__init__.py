"""Collection layer (secondary flow).

Network-facing collectors used only when the partner did not supply an
artifact (HTML) or to enrich a sample with live PKI/DNS/hosting facts. Every
collector degrades gracefully on failure so the analysis-first pipeline never
depends on collection succeeding.
"""

from phishing_intel.collectors.dns_collector import DNSCollector
from phishing_intel.collectors.html_collector import HTMLCollector
from phishing_intel.collectors.infrastructure_collector import (
    InfrastructureCollector,
)
from phishing_intel.collectors.ssl_collector import SSLCollector

__all__ = [
    "DNSCollector",
    "HTMLCollector",
    "InfrastructureCollector",
    "SSLCollector",
]
