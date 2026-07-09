"""Extractor responsible for harvesting indicators from finding payloads."""

from __future__ import annotations

import re

from threat_hunting.core.contracts import StageContext

IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")


class IndicatorExtractor:
    """Extract common IOC evidence from textual fields."""

    def run(self, items: list[dict[str, object]], context: StageContext) -> list[dict[str, object]]:
        """Extract IOC matches from title/description."""
        extracted: list[dict[str, object]] = []
        for item in items:
            description = f"{item.get('title', '')} {item.get('description', '')}"
            indicators = list(item.get("indicators", []))
            for ip in IP_PATTERN.findall(description):
                indicators.append({"type": "ip", "value": ip})
            for email in EMAIL_PATTERN.findall(description):
                indicators.append({"type": "email", "value": email})
            extracted.append({**item, "indicators": indicators})
        return extracted
