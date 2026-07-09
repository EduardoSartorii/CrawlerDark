"""DNS collector for resolving phishing infrastructure."""

from __future__ import annotations

import dns.resolver


class DnsCollector:
    """Resolve domains to IP addresses for infrastructure analysis."""

    def resolve_a(self, domain: str) -> list[str]:
        """Return IPv4 A records for a domain."""

        answers = dns.resolver.resolve(domain, "A")
        return sorted({answer.to_text() for answer in answers})
