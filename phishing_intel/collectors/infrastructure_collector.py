"""
Infrastructure metadata collector.

Aggregates DNS, WHOIS, and ASN data to build complete hosting
infrastructure profile for correlation.

Architectural Responsibility:
    Enriches individual incidents with hosting context and structures
    data for integration with passive DNS and threat intel platforms
    (SecurityTrails, RiskIQ, Shodan, CIRCL).

Flow:
    1. Resolve DNS to obtain IP
    2. Perform WHOIS/RDAP lookup for ASN and organization
    3. Normalize into InfrastructureFinding
"""

from __future__ import annotations

from typing import Any

import structlog
from ipwhois import IPWhois

from phishing_intel.collectors.dns_collector import DNSCollector
from phishing_intel.models.findings import InfrastructureFinding
from phishing_intel.utils import extract_domain

logger = structlog.get_logger(__name__)


class InfrastructureCollector:
    """Hosting infrastructure metadata aggregator."""

    def __init__(self, dns_collector: DNSCollector | None = None) -> None:
        """
        Initialize infrastructure collector.

        Args:
            dns_collector: Optional DNS collector instance.
        """
        self.dns_collector = dns_collector or DNSCollector()

    def collect(self, url: str) -> InfrastructureFinding:
        """
        Build complete infrastructure profile for URL.

        Args:
            url: Target phishing URL.

        Returns:
            Normalized InfrastructureFinding.
        """
        domain = extract_domain(url)
        logger.info("infrastructure_collection_start", domain=domain, url=url)

        dns_data = self.dns_collector.collect(url)
        ips = dns_data.get("resolved_ips", [])

        finding = InfrastructureFinding(domain=domain)

        if ips:
            primary_ip = ips[0]
            finding.ip = primary_ip
            whois_data = self._whois_lookup(primary_ip)
            finding.asn = whois_data.get("asn", "")
            finding.organization = whois_data.get("organization", "")
            finding.hosting_provider = whois_data.get("description", "") or whois_data.get(
                "organization", ""
            )
            finding.country = whois_data.get("country", "")

        logger.info(
            "infrastructure_collection_complete",
            domain=domain,
            ip=finding.ip,
            asn=finding.asn,
        )
        return finding

    def _whois_lookup(self, ip: str) -> dict[str, Any]:
        """
        Perform IP WHOIS lookup for ASN and organization.

        Args:
            ip: IP address string.

        Returns:
            Dictionary with asn, organization, country, description.
        """
        result: dict[str, Any] = {}
        try:
            obj = IPWhois(ip)
            data = obj.lookup_rdap(depth=1)
            result["asn"] = f"AS{data.get('asn', '')}" if data.get("asn") else ""
            result["organization"] = (
                data.get("asn_description", "") or data.get("network", {}).get("name", "")
            )
            result["description"] = data.get("asn_description", "")
            result["country"] = data.get("asn_country_code", "")
        except Exception as exc:
            logger.warning("whois_lookup_failed", ip=ip, error=str(exc))
        return result
