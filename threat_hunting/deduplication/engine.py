"""Hybrid deduplication engine."""

from __future__ import annotations

from collections.abc import Sequence
from difflib import SequenceMatcher

from threat_hunting.core.domain.entities import IndicatorType, Finding


class HybridDeduplicationEngine:
    """Eliminate duplicates using hash, text similarity and key indicators."""

    def __init__(self, similarity_threshold: float = 0.92) -> None:
        self._similarity_threshold = similarity_threshold

    def is_duplicate(self, finding: Finding, existing: Sequence[Finding]) -> bool:
        """Return true when a finding duplicates existing intelligence."""

        for candidate in existing:
            if candidate.content_hash == finding.content_hash:
                return True
            if self._same_key_indicator(finding, candidate):
                return True
            ratio = SequenceMatcher(None, finding.description, candidate.description).ratio()
            if ratio >= self._similarity_threshold:
                return True
        return False

    @staticmethod
    def _same_key_indicator(left: Finding, right: Finding) -> bool:
        key_types = {
            IndicatorType.DOMAIN,
            IndicatorType.EMAIL,
            IndicatorType.CPF,
            IndicatorType.CARD,
            IndicatorType.WALLET,
            IndicatorType.THREAT_ACTOR,
            IndicatorType.CAMPAIGN,
        }
        left_values = {(indicator.type, indicator.value.lower()) for indicator in left.indicators if indicator.type in key_types}
        right_values = {(indicator.type, indicator.value.lower()) for indicator in right.indicators if indicator.type in key_types}
        return bool(left_values.intersection(right_values))
