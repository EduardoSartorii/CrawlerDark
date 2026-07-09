"""Deduplication engine using hash and textual similarity."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from difflib import SequenceMatcher

from threat_hunting.core.domain.entities import Finding


class HashSimilarityDeduplicationEngine:
    """Detect duplicates through fingerprints, shared IOCs, and text similarity."""

    def __init__(self, similarity_threshold: float = 0.92) -> None:
        self.similarity_threshold = similarity_threshold

    def fingerprint(self, finding: Finding) -> str:
        """Return deterministic SHA-256 fingerprint for a finding."""

        return hashlib.sha256(finding.fingerprint_payload().encode("utf-8")).hexdigest()

    def is_duplicate(self, finding: Finding, existing: Iterable[Finding]) -> bool:
        """Return true when a finding duplicates an existing record."""

        finding_fp = self.fingerprint(finding)
        finding_indicators = {(indicator.type.value, indicator.value.lower()) for indicator in finding.indicators}
        for candidate in existing:
            if self.fingerprint(candidate) == finding_fp:
                return True
            candidate_indicators = {(indicator.type.value, indicator.value.lower()) for indicator in candidate.indicators}
            if finding_indicators and finding_indicators == candidate_indicators:
                return True
            similarity = SequenceMatcher(None, finding.description.lower(), candidate.description.lower()).ratio()
            if similarity >= self.similarity_threshold and finding.source == candidate.source:
                return True
        return False
