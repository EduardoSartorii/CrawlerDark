"""Correlation Engine.

Responsibility
--------------
Automatically correlate Findings by shared domains, IPs, ASNs, certificates,
threat actors, campaigns, emails, wallets, nicknames, GitHub, Telegram,
forum users, IOCs, malware, brand and infrastructure.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Sequence

import structlog

from threat_hunting.core.application.ports import CorrelationEnginePort, UnitOfWorkPort
from threat_hunting.core.domain.entities import Finding
from threat_hunting.core.domain.enums import IndicatorType, RelationshipType
from threat_hunting.core.domain.value_objects import Confidence, Relationship

logger = structlog.get_logger(__name__)

CORRELATABLE_TYPES = {
    IndicatorType.DOMAIN,
    IndicatorType.IP,
    IndicatorType.ASN,
    IndicatorType.CERTIFICATE,
    IndicatorType.EMAIL,
    IndicatorType.WALLET,
    IndicatorType.GITHUB,
    IndicatorType.TELEGRAM,
    IndicatorType.USERNAME,
    IndicatorType.HASH_MD5,
    IndicatorType.HASH_SHA1,
    IndicatorType.HASH_SHA256,
    IndicatorType.URL,
}


class CorrelationEngine(CorrelationEnginePort):
    """Correlate a Finding against existing persisted Findings.

    Uses UnitOfWork to look up Findings sharing IOC values.
    In-memory index also maintained for batch runs without persistence.
    """

    def __init__(self, uow: UnitOfWorkPort | None = None) -> None:
        self._uow = uow
        self._index: dict[str, set[str]] = defaultdict(set)  # ioc_fp -> finding_ids

    def index_finding(self, finding: Finding) -> None:
        """Index a finding for in-memory correlation (batch mode)."""
        fid = str(finding.id)
        for ind in finding.indicators:
            if ind.type in CORRELATABLE_TYPES:
                self._index[ind.fingerprint()].add(fid)

    async def correlate(self, finding: Finding) -> Finding:
        related_ids: set[str] = set()
        correlation_keys: list[str] = []

        for ind in finding.indicators:
            if ind.type not in CORRELATABLE_TYPES:
                continue
            fp = ind.fingerprint()
            # In-memory
            for other_id in self._index.get(fp, set()):
                if other_id != str(finding.id):
                    related_ids.add(other_id)
                    correlation_keys.append(f"{ind.type.value}:{ind.value}")

            # Persistent lookup
            if self._uow is not None:
                try:
                    others: Sequence[Finding] = await self._uow.findings.find_by_indicator(ind.value)
                    for other in others:
                        oid = str(other.id)
                        if oid != str(finding.id):
                            related_ids.add(oid)
                            correlation_keys.append(f"{ind.type.value}:{ind.value}")
                except Exception as exc:
                    logger.debug("correlation.lookup_skipped", error=str(exc))

        # Threat actor / brand / campaign tags
        for tag in finding.tags:
            if tag.name.startswith(("actor:", "campaign:", "brand:", "malware:")):
                correlation_keys.append(tag.name)

        for related_id in related_ids:
            finding.add_relationship(
                Relationship(
                    type=RelationshipType.RELATED_TO,
                    source_id=str(finding.id),
                    target_id=related_id,
                    description="Auto-correlated via shared IOC/entity",
                    confidence=Confidence(value=0.7),
                    metadata={"keys": list(set(correlation_keys))[:20]},
                )
            )

        # Index self for subsequent correlations in same run
        self.index_finding(finding)

        if related_ids:
            finding.add_tag("correlated")
            finding.enrich(
                {
                    "correlation": {
                        "related_count": len(related_ids),
                        "keys": list(set(correlation_keys))[:50],
                    }
                }
            )
            logger.info(
                "correlation.linked",
                finding_id=str(finding.id),
                related=len(related_ids),
            )
        return finding


__all__ = ["CorrelationEngine", "CORRELATABLE_TYPES"]
