"""DeduplicationEngine.

Responsibility
--------------
Collapse duplicate findings within a batch (and, optionally, against previously
persisted fingerprints) using an exact-hash pass followed by pairwise
similarity/indicator strategies. When two findings are duplicates, their
indicators/tags are merged into the survivor so no intelligence is lost.

Design
------
The exact-hash pass is O(n); the pairwise pass is O(n²) but only runs on the
hash-survivors, which keeps it tractable for realistic batch sizes.
"""

from __future__ import annotations

from collections.abc import Sequence

from threat_hunting.core.domain.entities.finding import Finding
from threat_hunting.infrastructure.deduplication.strategies import (
    HashStrategy,
    IndicatorStrategy,
    SimilarityStrategy,
)


class DeduplicationEngine:
    """De-duplicates a batch of findings, merging duplicates into survivors."""

    def __init__(
        self,
        *,
        indicator_strategy: IndicatorStrategy | None = None,
        similarity_strategy: SimilarityStrategy | None = None,
        known_fingerprints: set[str] | None = None,
    ) -> None:
        self._hash = HashStrategy()
        self._indicator = indicator_strategy or IndicatorStrategy()
        self._similarity = similarity_strategy or SimilarityStrategy()
        self._known = known_fingerprints if known_fingerprints is not None else set()

    def _merge(self, survivor: Finding, duplicate: Finding) -> None:
        """Fold a duplicate's indicators/tags/artifacts into the survivor."""
        for indicator in duplicate.indicators:
            survivor.add_indicator(indicator)
        for tag in duplicate.tags:
            survivor.add_tag(tag)
        for artifact in duplicate.artifacts:
            survivor.add_artifact(artifact)
        survivor.add_tag("deduplicated")

    def deduplicate(self, findings: Sequence[Finding]) -> tuple[list[Finding], int]:
        """Return ``(unique_findings, removed_count)`` after de-duplication."""
        survivors: list[Finding] = []
        by_hash: dict[str, Finding] = {}
        removed = 0

        for finding in findings:
            fingerprint = self._hash.fingerprint(finding)

            # Cross-run dedup against already-persisted content.
            if fingerprint in self._known:
                removed += 1
                continue

            # Exact-hash dedup within the batch.
            if fingerprint in by_hash:
                self._merge(by_hash[fingerprint], finding)
                removed += 1
                continue

            # Fuzzy dedup against current survivors.
            duplicate_of = self._find_similar(finding, survivors)
            if duplicate_of is not None:
                self._merge(duplicate_of, finding)
                removed += 1
                continue

            by_hash[fingerprint] = finding
            self._known.add(fingerprint)
            survivors.append(finding)

        return survivors, removed

    def _find_similar(self, finding: Finding, survivors: Sequence[Finding]) -> Finding | None:
        """Return an existing survivor considered a duplicate of ``finding``."""
        for survivor in survivors:
            if self._indicator.is_duplicate(finding, survivor) or self._similarity.is_duplicate(
                finding, survivor
            ):
                return survivor
        return None
