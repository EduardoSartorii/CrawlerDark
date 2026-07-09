"""Regex-based IOC and fraud artifact extraction.

Patterns are deterministic and local to the extractor. Business detection rules
remain dynamic and are loaded separately by the detection engine.
"""

from __future__ import annotations

import re

from threat_hunting.core.domain.entities import Finding, Indicator, IndicatorType


class RegexIndicatorExtractor:
    """Extract common IOCs, credentials and fraud entities from finding text."""

    PATTERNS: dict[IndicatorType, re.Pattern[str]] = {
        IndicatorType.IP: re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        IndicatorType.DOMAIN: re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.IGNORECASE),
        IndicatorType.URL: re.compile(r"https?://[^\s'\"]+", re.IGNORECASE),
        IndicatorType.EMAIL: re.compile(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b", re.IGNORECASE),
        IndicatorType.CPF: re.compile(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b"),
        IndicatorType.CNPJ: re.compile(r"\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b"),
        IndicatorType.CARD: re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
        IndicatorType.WALLET: re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}\b"),
    }

    def extract(self, finding: Finding) -> Finding:
        """Return a finding enriched with extracted indicators."""

        text = " ".join(
            [
                finding.title,
                finding.description,
                str(finding.raw_data),
                str(finding.normalized_data),
            ]
        )
        seen = {(indicator.type, indicator.value) for indicator in finding.indicators}
        indicators = list(finding.indicators)
        for indicator_type, pattern in self.PATTERNS.items():
            for match in pattern.findall(text):
                value = str(match).strip(".,;)")
                key = (indicator_type, value)
                if key not in seen:
                    indicators.append(Indicator(type=indicator_type, value=value, confidence=0.7))
                    seen.add(key)
        return finding.model_copy(update={"indicators": indicators})
