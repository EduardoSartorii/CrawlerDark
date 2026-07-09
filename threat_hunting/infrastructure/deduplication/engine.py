"""Deduplication engine — eliminates duplicate findings."""

from __future__ import annotations

import hashlib
from difflib import SequenceMatcher

import structlog

from threat_hunting.core.contracts.services import IDeduplicationEngine
from threat_hunting.core.domain.entities import Finding

logger = structlog.get_logger(__name__)


class DeduplicationEngine(IDeduplicationEngine):
    """Eliminates duplicates using hash, similarity, and IOC matching."""

    def __init__(self, similarity_threshold: float = 0.85) -> None:
        self._similarity_threshold = similarity_threshold
        self._seen_hashes: set[str] = set()

    def _content_hash(self, finding: Finding) -> str:
        """Generate deduplication hash from finding content."""
        parts = [
            finding.title,
            finding.connector,
            "|".join(sorted(i.value for i in finding.indicators)),
        ]
        return hashlib.sha256("::".join(parts).encode()).hexdigest()

    def _text_similarity(self, a: str, b: str) -> float:
        """Calculate textual similarity ratio."""
        return SequenceMatcher(None, a.lower(), b.lower()).ratio()

    async def deduplicate(self, findings: list[Finding]) -> list[Finding]:
        unique: list[Finding] = []
        seen_content: list[str] = []

        for finding in findings:
            content_hash = self._content_hash(finding)

            if content_hash in self._seen_hashes:
                logger.debug("dedup.hash_match", finding_id=str(finding.id))
                continue

            is_similar = False
            content = f"{finding.title} {finding.description}"
            for seen in seen_content:
                if self._text_similarity(content, seen) >= self._similarity_threshold:
                    is_similar = True
                    break

            if is_similar:
                logger.debug("dedup.similarity_match", finding_id=str(finding.id))
                continue

            # IOC-based dedup
            ioc_set = frozenset((i.type.value, i.value) for i in finding.indicators)
            for existing in unique:
                existing_iocs = frozenset((i.type.value, i.value) for i in existing.indicators)
                if ioc_set and ioc_set == existing_iocs:
                    is_similar = True
                    break

            if not is_similar:
                self._seen_hashes.add(content_hash)
                seen_content.append(content)
                unique.append(finding)

        logger.info("dedup.completed", input=len(findings), output=len(unique))
        return unique
