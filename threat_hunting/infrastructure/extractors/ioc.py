"""Extractor implementations for IOC and entity extraction."""

from __future__ import annotations

import re

from threat_hunting.core.contracts.services import ExtractedData, IExtractor, ParsedData
from threat_hunting.core.domain.enums import IndicatorType

# Regex patterns for common IOC and PII extraction
PATTERNS: dict[IndicatorType, re.Pattern[str]] = {
    IndicatorType.IP: re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    IndicatorType.EMAIL: re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
    IndicatorType.DOMAIN: re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"),
    IndicatorType.HASH_MD5: re.compile(r"\b[a-fA-F0-9]{32}\b"),
    IndicatorType.HASH_SHA256: re.compile(r"\b[a-fA-F0-9]{64}\b"),
    IndicatorType.CPF: re.compile(r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b"),
    IndicatorType.CNPJ: re.compile(r"\b\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}\b"),
    IndicatorType.CARD: re.compile(r"\b(?:\d{4}[- ]?){3}\d{4}\b"),
    IndicatorType.URL: re.compile(r"https?://[^\s<>\"{}|\\^`\[\]]+"),
    IndicatorType.WALLET: re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b"),
}


class IocExtractor(IExtractor):
    """Extracts IOCs, credentials, and PII from parsed content."""

    def extract(self, parsed: ParsedData) -> ExtractedData:
        indicators: list[dict[str, str]] = []
        text = parsed.content

        for indicator_type, pattern in PATTERNS.items():
            for match in pattern.finditer(text):
                indicators.append({"type": indicator_type.value, "value": match.group()})

        entities = {
            "emails": [i["value"] for i in indicators if i["type"] == IndicatorType.EMAIL.value],
            "domains": [i["value"] for i in indicators if i["type"] == IndicatorType.DOMAIN.value],
            "ips": [i["value"] for i in indicators if i["type"] == IndicatorType.IP.value],
        }

        return ExtractedData(parsed=parsed, indicators=indicators, entities=entities)
