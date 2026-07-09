"""
DeduplicationEngine
====================

Implements the IDeduplicationEngine port.

Detects duplicate Findings using a two-stage approach:
    1. Exact hash match — fast O(1) lookup in the hash store.
    2. Fuzzy similarity match — token set ratio on title/description.

Hash strategy:
    - Content hash = xxhash64(connector + source_id + title_normalized)
    - When source_id is available, (connector, source_id) is the primary key.
    - This prevents the same post being collected twice (e.g., scheduler runs).

Similarity strategy:
    - Computes token_set_ratio(a.title + a.description, b.title + b.description).
    - If similarity ≥ threshold, the newer Finding is marked as duplicate.
    - Only compares Findings within the configured TTL window.

When a duplicate is detected:
    - finding.mark_duplicate(original_id) is called.
    - The Finding status becomes DEDUPLICATED.
    - The Finding is still persisted (for audit).
    - Pipeline stages after deduplication are skipped.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog
import xxhash

from threat_hunting.core.domain.entities.finding import FindingStatus
from threat_hunting.core.domain.events.finding_events import FindingDeduplicated
from threat_hunting.core.domain.exceptions.domain_exceptions import DeduplicationError
from threat_hunting.core.domain.ports.engines import IDeduplicationEngine

if TYPE_CHECKING:
    from threat_hunting.core.domain.entities.finding import Finding
    from threat_hunting.core.domain.ports.event_bus import IEventBus
    from threat_hunting.core.domain.ports.repositories import IFindingRepository

logger = structlog.get_logger(__name__)


class DeduplicationEngine(IDeduplicationEngine):
    """
    Two-stage deduplication engine (hash + similarity).
    """

    def __init__(
        self,
        finding_repo: "IFindingRepository",
        event_bus: "IEventBus",
        similarity_threshold: float = 0.85,
    ) -> None:
        self._finding_repo = finding_repo
        self._event_bus = event_bus
        self._threshold = similarity_threshold

    async def deduplicate(self, finding: "Finding") -> "Finding":
        """
        Check for duplicates and mark Finding if one is found.

        Args:
            finding: A correlated Finding.

        Returns:
            The Finding, possibly marked as duplicate.
        """
        log = logger.bind(finding_id=finding.id)
        try:
            # Stage 1: Source ID deduplication (exact match).
            if finding.source_id:
                content_hash = self._compute_source_hash(finding)
                is_dup = await self._finding_repo.exists_by_hash(content_hash)
                if is_dup:
                    log.info("duplicate_detected_hash", hash=content_hash)
                    finding.mark_duplicate("unknown_original")
                    await self._publish_dedup_event(finding)
                    return finding

            # Stage 2: Similarity-based deduplication.
            if self._threshold < 1.0:
                similar = await self._finding_repo.find_similar(finding, self._threshold)
                if similar:
                    original = similar[0]
                    log.info("duplicate_detected_similarity", original_id=original.id)
                    finding.mark_duplicate(original.id)
                    await self._publish_dedup_event(finding)
                    return finding

        except Exception as exc:
            log.error("deduplication_error", error=str(exc))
            raise DeduplicationError(f"Deduplication failed: {exc}") from exc

        finding.advance_status(FindingStatus.DEDUPLICATED)
        return finding

    def _compute_source_hash(self, finding: "Finding") -> str:
        """Compute a stable content hash for the Finding."""
        key = f"{finding.connector}:{finding.source_id}:{finding.title.lower().strip()}"
        return xxhash.xxh64_hexdigest(key.encode())

    async def _publish_dedup_event(self, finding: "Finding") -> None:
        await self._event_bus.publish(
            FindingDeduplicated(
                aggregate_id=finding.id,
                original_finding_id=finding.duplicate_of or "",
            )
        )
