"""DNS collector.

Component responsibility
------------------------
Resolve the common DNS record types for a phishing domain and emit a
:class:`~phishing_intel.models.infrastructure.DNSRecords`. DNS data feeds the
infrastructure collector (A -> IP -> ASN) and future Passive DNS pivots.

Execution flow
--------------
``DNSCollector.collect(domain)`` -> query A/AAAA/MX/NS/TXT/CNAME -> collate ->
return ``DNSRecords``. Each query is independently guarded so a partial failure
(e.g. no MX) still yields the records that did resolve.
"""

from __future__ import annotations

from typing import List

import dns.resolver

from phishing_intel.logging_config import get_logger
from phishing_intel.models.infrastructure import DNSRecords

logger = get_logger(__name__)

# Record types resolved for every domain.
_RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME")


class DNSCollector:
    """Resolve DNS records for a domain."""

    def __init__(self, timeout: float = 5.0) -> None:
        # A dedicated resolver lets us bound query time deterministically.
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    def _query(self, domain: str, record_type: str) -> List[str]:
        """Query a single record type, returning [] on any failure/absence."""

        try:
            answers = self.resolver.resolve(domain, record_type)
            return [rdata.to_text().strip('"') for rdata in answers]
        except Exception as exc:  # noqa: BLE001 - dnspython raises many types
            # NXDOMAIN / NoAnswer / Timeout etc. are all "no data" for us.
            logger.debug("dns.query_empty", domain=domain, type=record_type, error=str(exc))
            return []

    def collect(self, domain: str) -> DNSRecords:
        """Resolve all supported record types for ``domain``."""

        records = {rt: self._query(domain, rt) for rt in _RECORD_TYPES}
        result = DNSRecords(
            domain=domain,
            a=records["A"],
            aaaa=records["AAAA"],
            mx=records["MX"],
            ns=records["NS"],
            txt=records["TXT"],
            cname=records["CNAME"],
        )
        logger.info(
            "dns.collected",
            domain=domain,
            a=len(result.a),
            mx=len(result.mx),
            ns=len(result.ns),
        )
        return result
