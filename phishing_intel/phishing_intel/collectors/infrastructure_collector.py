"""Infrastructure collector for domain, IP, ASN and provider metadata."""

from __future__ import annotations

import socket

from ipwhois import IPWhois

from phishing_intel.collectors.dns_collector import DnsCollector
from phishing_intel.models.infrastructure import InfrastructureProfile


class InfrastructureCollector:
    """Resolve network profile data for phishing sites."""

    def __init__(self, dns_collector: DnsCollector | None = None) -> None:
        self.dns_collector = dns_collector or DnsCollector()

    def collect(self, domain: str) -> InfrastructureProfile:
        """Collect DNS, IP and WHOIS details for a domain."""

        ip = self._resolve_ip(domain)
        asn = None
        organization = None
        provider = None
        country = None
        if ip:
            try:
                whois_data = IPWhois(ip).lookup_rdap(depth=1)
                asn = whois_data.get("asn")
                organization = whois_data.get("asn_description")
                provider = whois_data.get("network", {}).get("name")
                country = whois_data.get("network", {}).get("country")
            except Exception:
                pass

        return InfrastructureProfile(
            domain=domain,
            ip=ip,
            asn=asn,
            organization=organization,
            provider=provider,
            country=country,
            dns=self.dns_collector.collect(domain),
        )

    @staticmethod
    def _resolve_ip(domain: str) -> str | None:
        """Resolve first IP address from domain."""

        try:
            return socket.gethostbyname(domain)
        except Exception:
            return None
