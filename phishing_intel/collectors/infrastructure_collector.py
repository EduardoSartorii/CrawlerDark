"""Infrastructure collector for DNS and RDAP-derived context."""

from __future__ import annotations

from ipwhois import IPWhois

from phishing_intel.collectors.dns_collector import DnsCollector
from phishing_intel.models.infrastructure import InfrastructureFinding
from phishing_intel.utils import extract_domain


class InfrastructureCollector:
    """Collect domain, IP, ASN, organization, provider, and country context."""

    def __init__(self, dns_collector: DnsCollector | None = None) -> None:
        """Create an infrastructure collector with injectable DNS."""

        self.dns_collector = dns_collector or DnsCollector()

    def collect(self, url_or_domain: str) -> InfrastructureFinding:
        """Resolve and enrich a URL or domain using DNS and RDAP."""

        domain = extract_domain(url_or_domain)
        if not domain:
            return InfrastructureFinding()
        ips = self.dns_collector.resolve_a(domain)
        ip = ips[0] if ips else None
        if not ip:
            return InfrastructureFinding(domain=domain)
        try:
            rdap = IPWhois(ip).lookup_rdap(depth=1)
        except Exception:
            rdap = {}
        network = rdap.get("network") or {}
        return InfrastructureFinding(
            domain=domain,
            ip=ip,
            asn=str(rdap.get("asn")) if rdap.get("asn") else None,
            organization=rdap.get("asn_description"),
            hosting_provider=network.get("name") or rdap.get("asn_description"),
            country=network.get("country"),
        )
