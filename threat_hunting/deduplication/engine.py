"""Deduplication Engine.

Responsibility
--------------
Eliminate duplicate Findings using content hash, textual similarity,
shared IOCs (domain, email, CPF, card, wallet), threat actor and campaign.
"""

from __future__ import annotations

import re
from difflib import SequenceMatcher

import structlog

from threat_hunting.core.application.ports import DeduplicationEnginePort, UnitOfWorkPort
from threat_hunting.core.domain.entities import Finding
from threat_hunting.core.domain.enums import IndicatorType, RelationshipType
from threat_hunting.core.domain.value_objects import Confidence, Relationship

logger = structlog.get_logger(__name__)

STRONG_IOC_TYPES = {
    IndicatorType.HASH_SHA256,
    IndicatorType.HASH_SHA1,
    IndicatorType.HASH_MD5,
    IndicatorType.CARD,
    IndicatorType.CPF,
    IndicatorType.CNPJ,
    IndicatorType.WALLET,
    IndicatorType.EMAIL,
}


class DeduplicationEngine(DeduplicationEnginePort):
    """Deduplicate Findings.

    Strategy order
    --------------
    1. Exact content_hash match → duplicate
    2. Strong IOC overlap (cards, hashes, CPF, wallets, emails) → duplicate
    3. Textual similarity (title+description) above threshold → duplicate
    4. Otherwise unique; index for future comparisons
    """

    def __init__(
        self,
        uow: UnitOfWorkPort | None = None,
        *,
        similarity_threshold: float = 0.92,
    ) -> None:
        self._uow = uow
        self._similarity_threshold = similarity_threshold
        self._seen_hashes: dict[str, str] = {}  # hash -> finding_id
        self._seen_iocs: dict[str, str] = {}  # ioc_fp -> finding_id
        self._seen_texts: list[tuple[str, str]] = []  # (normalized_text, finding_id)

    async def deduplicate(self, finding: Finding) -> Finding:
        fid = str(finding.id)

        # 1. Content hash
        if finding.content_hash:
            if finding.content_hash in self._seen_hashes:
                return self._mark(finding, self._seen_hashes[finding.content_hash], "content_hash")
            if self._uow is not None:
                try:
                    existing = await self._uow.findings.find_by_content_hash(finding.content_hash)
                    if existing and str(existing.id) != fid:
                        return self._mark(finding, str(existing.id), "content_hash")
                except Exception as exc:
                    logger.debug("dedup.hash_lookup_skipped", error=str(exc))

        # 2. Strong IOC overlap
        for ind in finding.indicators:
            if ind.type in STRONG_IOC_TYPES:
                fp = ind.fingerprint()
                if fp in self._seen_iocs:
                    return self._mark(finding, self._seen_iocs[fp], f"ioc:{ind.type.value}")

        # 3. Textual similarity
        text = self._normalize_text(f"{finding.title} {finding.description}")
        for prev_text, prev_id in self._seen_texts:
            ratio = SequenceMatcher(None, text, prev_text).ratio()
            if ratio >= self._similarity_threshold:
                return self._mark(finding, prev_id, f"similarity:{ratio:.3f}")

        # Index as unique
        if finding.content_hash:
            self._seen_hashes[finding.content_hash] = fid
        for ind in finding.indicators:
            if ind.type in STRONG_IOC_TYPES:
                self._seen_iocs[ind.fingerprint()] = fid
        self._seen_texts.append((text, fid))
        # Bound memory
        if len(self._seen_texts) > 10_000:
            self._seen_texts = self._seen_texts[-5_000:]

        return finding

    def _mark(self, finding: Finding, original_id: str, reason: str) -> Finding:
        finding.mark_duplicate(original_id)
        finding.add_relationship(
            Relationship(
                type=RelationshipType.DUPLICATE_OF,
                source_id=str(finding.id),
                target_id=original_id,
                description=f"Deduplicated via {reason}",
                confidence=Confidence(value=0.95),
            )
        )
        finding.add_tag("duplicate")
        logger.info(
            "dedup.duplicate",
            finding_id=str(finding.id),
            original=original_id,
            reason=reason,
        )
        return finding

    @staticmethod
    def _normalize_text(text: str) -> str:
        text = text.lower().strip()
        text = re.sub(r"\s+", " ", text)
        text = re.sub(r"[^\w\s]", "", text)
        return text


__all__ = ["DeduplicationEngine", "STRONG_IOC_TYPES"]
