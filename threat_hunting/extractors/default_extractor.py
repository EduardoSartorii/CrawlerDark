"""Extractor strategy that maps content fields into indicator-friendly shape."""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any


EMAIL_REGEX = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
DOMAIN_REGEX = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")


class DefaultExtractor:
    """Extract common observables from unstructured text."""

    def process(self, parsed_items: Sequence[dict[str, Any]]) -> Sequence[dict[str, Any]]:
        """Extract emails and domains while preserving item metadata."""
        extracted: list[dict[str, Any]] = []
        for item in parsed_items:
            text = f"{item.get('title', '')} {item.get('description', '')}"
            emails = sorted(set(EMAIL_REGEX.findall(text)))
            domains = sorted(set(DOMAIN_REGEX.findall(text)))
            enriched_item = dict(item)
            enriched_item["extracted"] = {"emails": emails, "domains": domains}
            extracted.append(enriched_item)
        return extracted
