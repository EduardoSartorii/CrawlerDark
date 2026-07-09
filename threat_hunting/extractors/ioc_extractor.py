"""IOC / entity Extractor.

Responsibility
--------------
Extract indicators (emails, IPs, domains, URLs, hashes, CPF, CNPJ, cards,
wallets, Telegram, GitHub) from parsed documents using regex heuristics.
Fully decoupled from connectors — used by the pipeline ExtractorPort.
"""

from __future__ import annotations

import re
from typing import Any

from threat_hunting.core.application.ports import ExtractedEntities, ExtractorPort, ParsedDocument
from threat_hunting.core.domain.enums import IndicatorType

PATTERNS: dict[IndicatorType, re.Pattern[str]] = {
    IndicatorType.EMAIL: re.compile(
        r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
    ),
    IndicatorType.IP: re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    ),
    IndicatorType.URL: re.compile(
        r"https?://[^\s<>\"']+|hxxps?://[^\s<>\"']+", re.IGNORECASE
    ),
    IndicatorType.DOMAIN: re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:[a-zA-Z]{2,})\b"
    ),
    IndicatorType.HASH_MD5: re.compile(r"\b[a-fA-F0-9]{32}\b"),
    IndicatorType.HASH_SHA1: re.compile(r"\b[a-fA-F0-9]{40}\b"),
    IndicatorType.HASH_SHA256: re.compile(r"\b[a-fA-F0-9]{64}\b"),
    IndicatorType.CPF: re.compile(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b"),
    IndicatorType.CNPJ: re.compile(r"\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b"),
    IndicatorType.CARD: re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
    IndicatorType.WALLET: re.compile(
        r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b|0x[a-fA-F0-9]{40}\b"
    ),
    IndicatorType.CVE: re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    IndicatorType.TELEGRAM: re.compile(r"(?:t\.me/|@)([a-zA-Z0-9_]{5,})", re.IGNORECASE),
    IndicatorType.GITHUB: re.compile(
        r"github\.com/([a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.-]+)?)", re.IGNORECASE
    ),
}

# Domains that look like TLDs but are common false positives
DOMAIN_BLOCKLIST = {
    "example.com",
    "localhost",
    "localdomain",
    "schema.org",
    "w3.org",
    "googleapis.com",
}


class IocExtractor(ExtractorPort):
    """Extract IOCs and entities from parsed document text fields."""

    def __init__(self, *, extract_cards: bool = True) -> None:
        self._extract_cards = extract_cards

    async def extract(self, parsed: ParsedDocument) -> ExtractedEntities:
        text = self._collect_text(parsed)
        indicators: list[dict[str, Any]] = []
        seen: set[str] = set()

        for itype, pattern in PATTERNS.items():
            if itype == IndicatorType.CARD and not self._extract_cards:
                continue
            for match in pattern.finditer(text):
                value = match.group(0) if match.lastindex is None else match.group(1) or match.group(0)
                value = value.strip()
                if itype == IndicatorType.DOMAIN:
                    if value.lower() in DOMAIN_BLOCKLIST or "@" in value:
                        continue
                    # Skip if it's part of an email already
                    if re.search(rf"\S+@{re.escape(value)}", text):
                        continue
                if itype == IndicatorType.CARD and not self._luhn_check(re.sub(r"[^\d]", "", value)):
                    continue
                key = f"{itype.value}:{value.lower()}"
                if key in seen:
                    continue
                seen.add(key)
                indicators.append({"type": itype.value, "value": value, "context": None})

        emails = [i["value"] for i in indicators if i["type"] == IndicatorType.EMAIL.value]
        return ExtractedEntities(
            {
                "indicators": indicators,
                "emails": emails,
                "text_length": len(text),
            }
        )

    @staticmethod
    def _collect_text(parsed: ParsedDocument) -> str:
        parts: list[str] = []
        for key in ("title", "description", "body", "content", "text", "html"):
            val = parsed.get(key)
            if isinstance(val, str):
                parts.append(val)
        raw = parsed.get("raw")
        if isinstance(raw, str):
            parts.append(raw)
        elif isinstance(raw, dict):
            parts.append(str(raw))
        return "\n".join(parts)

    @staticmethod
    def _luhn_check(number: str) -> bool:
        if not number.isdigit() or not (13 <= len(number) <= 19):
            return False
        digits = [int(d) for d in number]
        odd = digits[-1::-2]
        even = digits[-2::-2]
        total = sum(odd) + sum(sum(divmod(2 * d, 10)) for d in even)
        return total % 10 == 0


__all__ = ["IocExtractor", "PATTERNS"]
