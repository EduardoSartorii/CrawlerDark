"""Infrastructure collector.

Component responsibility
------------------------
Resolve a domain to its hosting facts (IP, ASN, organisation, hosting provider,
country) and emit a
:class:`~phishing_intel.models.infrastructure.InfrastructureInfo`. The output
schema is shaped to be trivially enriched by external providers later (Passive
DNS, SecurityTrails, RiskIQ, WhoisXML, Shodan, CIRCL) without schema changes.

Execution flow
--------------
``InfrastructureCollector.collect(domain)`` ->
  1. DNS-resolve the domain to an A record (via :class:`DNSCollector`).
  2. RDAP/whois lookup of the IP (via ``ipwhois``) for ASN/org/country.
  3. Assemble ``InfrastructureInfo`` (with the DNS records attached).
"""

from __future__ import annotations

from typing import Optional

from ipwhois import IPWhois

from phishing_intel.collectors.dns_collector import DNSCollector
from phishing_intel.logging_config import get_logger
from phishing_intel.models.infrastructure import DNSRecords, InfrastructureInfo

logger = get_logger(__name__)


class InfrastructureCollector:
    """Resolve hosting infrastructure facts for a domain."""

    def __init__(self, dns_collector: Optional[DNSCollector] = None) -> None:
        # Allow dependency injection of the DNS collector for testing.
        self.dns_collector = dns_collector or DNSCollector()

    def _whois_ip(self, ip: str) -> dict:
        """Perform an RDAP lookup of an IP, returning {} on failure."""

        try:
            return IPWhois(ip).lookup_rdap(depth=1)
        except Exception as exc:  # noqa: BLE001 - ipwhois raises many types
            logger.warning("infra.whois_failed", ip=ip, error=str(exc))
            return {}

    def collect(self, domain: str) -> InfrastructureInfo:
        """Resolve infrastructure facts for ``domain``.

        Returns a partially-populated :class:`InfrastructureInfo` even when some
        lookups fail, so downstream correlation can use whatever is available.
        """

        dns_records: DNSRecords = self.dns_collector.collect(domain)
        ip = dns_records.a[0] if dns_records.a else None

        info = InfrastructureInfo(domain=domain, ip=ip, dns=dns_records)

        if ip:
            rdap = self._whois_ip(ip)
            info.asn = rdap.get("asn")
            info.asn_description = rdap.get("asn_description")
            info.country = rdap.get("asn_country_code")
            # The network object carries the most descriptive org/provider name.
            network = rdap.get("network") or {}
            info.organization = network.get("name") or rdap.get("asn_description")
            info.hosting_provider = network.get("name")

        logger.info(
            "infra.collected",
            domain=domain,
            ip=ip,
            asn=info.asn,
            country=info.country,
            provider=info.hosting_provider,
        )
        return info
