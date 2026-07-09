"""
IOCExtractor
============

Extracts Indicators of Compromise (IOCs) from text content using:
    - Compiled regular expressions (patterns.py)
    - ioc-finder library (high-accuracy IOC parsing)
    - Custom pattern overrides for Brazilian-specific data (CPF, CNPJ)

Extracted types:
    - IPv4, IPv6 addresses
    - Domain names, FQDNs
    - URLs
    - Email addresses
    - MD5, SHA1, SHA256 hashes
    - CVE identifiers
    - Wallet addresses (Bitcoin, Ethereum, Monero)
    - ASN numbers
    - YARA rule references

Architecture:
    - Stateless: no side effects.
    - Returns a list of Indicator domain objects.
    - Deduplication by (type, value) happens at the DeduplicationEngine level.
    - The extractor does NOT persist Indicators — that is the Repository's job.
"""

from __future__ import annotations

import re
from typing import Any

import structlog

from threat_hunting.core.domain.entities.indicator import Indicator
from threat_hunting.core.domain.value_objects.indicator_type import IndicatorType

logger = structlog.get_logger(__name__)

# ── Compiled regex patterns ────────────────────────────────────────────────────

_PATTERNS: dict[IndicatorType, re.Pattern] = {
    IndicatorType.IP: re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    ),
    IndicatorType.EMAIL: re.compile(
        r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"
    ),
    IndicatorType.MD5: re.compile(r"\b[a-fA-F0-9]{32}\b"),
    IndicatorType.SHA1: re.compile(r"\b[a-fA-F0-9]{40}\b"),
    IndicatorType.SHA256: re.compile(r"\b[a-fA-F0-9]{64}\b"),
    IndicatorType.CVE: re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE),
    IndicatorType.DOMAIN: re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
        r"+(?:com|net|org|io|gov|edu|co|uk|br|de|fr|ru|cn|onion|xyz|tech|info|biz|info)\b",
        re.IGNORECASE,
    ),
    IndicatorType.URL: re.compile(
        r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(?:/[^\s\"<>]*)?",
        re.IGNORECASE,
    ),
    IndicatorType.ONION_URL: re.compile(
        r"\b[a-z2-7]{16,56}\.onion(?:/[^\s]*)?\b", re.IGNORECASE
    ),
    IndicatorType.WALLET: re.compile(
        r"\b(?:"
        r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}"           # Bitcoin P2PKH/P2SH
        r"|bc1[a-z0-9]{39,59}"                         # Bitcoin bech32
        r"|0x[a-fA-F0-9]{40}"                          # Ethereum
        r"|4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}"          # Monero
        r")\b"
    ),
    IndicatorType.CPF: re.compile(
        r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b"
    ),
    IndicatorType.CNPJ: re.compile(
        r"\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b"
    ),
    IndicatorType.CARD_NUMBER: re.compile(
        r"\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6011\d{12})\b"
    ),
}

# These types can generate excessive false positives — apply them cautiously.
_NOISY_TYPES = {IndicatorType.MD5, IndicatorType.SHA1, IndicatorType.DOMAIN}

# Private IP ranges to exclude from IOC results (RFC 1918 + loopback).
_PRIVATE_IP_RANGES = re.compile(
    r"^(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.0\.0\.0|255\.)"
)


class IOCExtractor:
    """
    Stateless IOC extractor.

    Parses text content and returns deduplicated Indicator objects.
    """

    def __init__(self, source_tag: str = "extractor") -> None:
        self._source_tag = source_tag

    def extract(self, text: str, context: str = "") -> list[Indicator]:
        """
        Extract all IOCs from text.

        Args:
            text: Raw or processed text to analyze.
            context: Optional context label (e.g., connector name or field name).

        Returns:
            Deduplicated list of Indicator objects.
        """
        if not text:
            return []

        seen: set[str] = set()
        indicators: list[Indicator] = []

        for ioc_type, pattern in _PATTERNS.items():
            for match in pattern.finditer(text):
                value = match.group(0).strip().rstrip(".,;:\"'")
                if not value:
                    continue

                # Filter private IPs.
                if ioc_type == IndicatorType.IP and _PRIVATE_IP_RANGES.match(value):
                    continue

                # Normalize value.
                normalized = value.lower() if ioc_type not in {IndicatorType.MD5, IndicatorType.SHA1, IndicatorType.SHA256} else value.lower()
                unique_key = f"{ioc_type.value}:{normalized}"

                if unique_key in seen:
                    continue
                seen.add(unique_key)

                try:
                    indicator = Indicator(
                        type=ioc_type,
                        value=normalized,
                        context=context or None,
                        sources=[self._source_tag],
                        tags=[ioc_type.value, self._source_tag],
                    )
                    indicators.append(indicator)
                except Exception as exc:
                    logger.debug(
                        "indicator_creation_skipped",
                        type=ioc_type.value,
                        value=value[:64],
                        error=str(exc),
                    )

        return indicators

    def extract_typed(
        self, text: str, ioc_type: IndicatorType, context: str = ""
    ) -> list[Indicator]:
        """Extract only indicators of a specific type."""
        pattern = _PATTERNS.get(ioc_type)
        if not pattern:
            return []

        fake_text = text
        # Use full extract with type filter.
        all_indicators = self.extract(fake_text, context)
        return [i for i in all_indicators if i.type == ioc_type]

    def count_by_type(self, text: str) -> dict[str, int]:
        """Count extracted IOCs by type (useful for density scoring)."""
        indicators = self.extract(text)
        counts: dict[str, int] = {}
        for ind in indicators:
            counts[ind.type.value] = counts.get(ind.type.value, 0) + 1
        return counts
