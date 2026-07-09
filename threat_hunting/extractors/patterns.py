"""Regex-based artifact extraction strategies."""

from __future__ import annotations

import re
from typing import Any

from threat_hunting.core.domain.entities import Artifact, Indicator, IndicatorType


class PatternExtractor:
    """Extract common IOCs and fraud artifacts from text."""

    PATTERNS: dict[IndicatorType, str] = {
        IndicatorType.EMAIL: r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        IndicatorType.IP: r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        IndicatorType.DOMAIN: r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b",
        IndicatorType.URL: r"https?://[^\s'\"]+",
        IndicatorType.CARD: r"\b(?:\d[ -]*?){13,19}\b",
        IndicatorType.WALLET: r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b",
    }

    def extract(self, payload: dict[str, Any]) -> tuple[list[Artifact], list[Indicator]]:
        """Extract artifacts and indicators from title/description/content fields."""

        text = " ".join(str(payload.get(field, "")) for field in ("title", "description", "content", "raw"))
        artifacts: list[Artifact] = []
        indicators: list[Indicator] = []
        for indicator_type, pattern in self.PATTERNS.items():
            for match in sorted(set(re.findall(pattern, text))):
                artifacts.append(Artifact(type=indicator_type.value, value=match))
                indicators.append(Indicator(type=indicator_type, value=match, confidence=0.6))
        return artifacts, indicators
