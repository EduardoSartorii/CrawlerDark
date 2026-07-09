"""
DNS resolution collector.

Resolves domain names to IP addresses and extracts DNS records
for infrastructure analysis and IOC enrichment.

Architectural Responsibility:
    Provides network-layer resolution data feeding infrastructure
    correlation and passive DNS integration points.
"""

from __future__ import annotations

import socket
from typing import Any

import dns.resolver
import structlog

from phishing_intel.utils import extract_domain

logger = structlog.get_logger(__name__)


class DNSCollector:
    """DNS resolution and record extraction."""

    def __init__(self, timeout: int = 5) -> None:
        """
        Initialize DNS collector.

        Args:
            timeout: DNS query timeout in seconds.
        """
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    def collect(self, url_or_domain: str) -> dict[str, Any]:
        """
        Resolve DNS records for domain.

        Args:
            url_or_domain: URL or domain name.

        Returns:
            Dictionary with A, AAAA, MX, NS, TXT records and resolved IPs.
        """
        domain = extract_domain(url_or_domain)
        logger.info("dns_collection_start", domain=domain)

        result: dict[str, Any] = {
            "domain": domain,
            "a_records": [],
            "aaaa_records": [],
            "mx_records": [],
            "ns_records": [],
            "txt_records": [],
            "resolved_ips": [],
        }

        record_types = {
            "A": "a_records",
            "AAAA": "aaaa_records",
            "MX": "mx_records",
            "NS": "ns_records",
            "TXT": "txt_records",
        }

        for rtype, key in record_types.items():
            try:
                answers = self.resolver.resolve(domain, rtype)
                if rtype == "MX":
                    result[key] = [str(r.exchange).rstrip(".") for r in answers]
                elif rtype == "TXT":
                    result[key] = [
                        b"".join(r.strings).decode("utf-8", errors="replace") for r in answers
                    ]
                else:
                    result[key] = [str(r).rstrip(".") for r in answers]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                pass
            except dns.exception.DNSException as exc:
                logger.debug("dns_query_failed", domain=domain, rtype=rtype, error=str(exc))

        # Fallback socket resolution for A records
        if not result["a_records"]:
            try:
                ips = socket.getaddrinfo(domain, None, socket.AF_INET)
                result["resolved_ips"] = list({info[4][0] for info in ips})
            except socket.gaierror as exc:
                logger.warning("dns_resolution_failed", domain=domain, error=str(exc))
        else:
            result["resolved_ips"] = result["a_records"]

        logger.info(
            "dns_collection_complete",
            domain=domain,
            ip_count=len(result["resolved_ips"]),
        )
        return result
