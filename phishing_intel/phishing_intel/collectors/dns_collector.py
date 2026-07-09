"""DNS collector used for infrastructure profiling and attribution."""

from __future__ import annotations

import dns.resolver

from phishing_intel.models.infrastructure import DnsRecordSet


class DnsCollector:
    """Resolve key DNS records used during phishing analysis."""

    def __init__(self, lifetime: float = 4.0) -> None:
        self.lifetime = lifetime

    def collect(self, domain: str) -> DnsRecordSet:
        """Resolve A, MX and NS records for a domain."""

        return DnsRecordSet(
            a_records=self._resolve(domain, "A"),
            mx_records=self._resolve(domain, "MX"),
            ns_records=self._resolve(domain, "NS"),
        )

    def _resolve(self, domain: str, rdtype: str) -> list[str]:
        """Resolve one DNS record type and normalize textual output."""

        try:
            answers = dns.resolver.resolve(domain, rdtype, lifetime=self.lifetime)
            return sorted({str(answer).rstrip(".") for answer in answers})
        except Exception:
            return []
