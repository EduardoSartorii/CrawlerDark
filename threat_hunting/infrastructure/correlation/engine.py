"""Correlation engine — links related intelligence entities."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import structlog

from threat_hunting.core.contracts.services import ICorrelationEngine
from threat_hunting.core.domain.entities import CorrelationLink, Finding, Relationship

if TYPE_CHECKING:
    from threat_hunting.core.contracts.repositories import ICorrelationRepository, IFindingRepository

logger = structlog.get_logger(__name__)

CORRELATION_TYPES = (
    "domain", "ip", "email", "wallet", "threat_actor",
    "campaign", "github", "telegram", "infrastructure", "ioc",
)


class CorrelationEngine(ICorrelationEngine):
    """Correlates findings across domains, IPs, actors, campaigns, and IOCs."""

    def __init__(
        self,
        correlation_repo: ICorrelationRepository,
        finding_repo: IFindingRepository,
    ) -> None:
        self._correlation_repo = correlation_repo
        self._finding_repo = finding_repo

    async def correlate(self, finding: Finding) -> tuple[Finding, list[dict[str, Any]]]:
        correlations: list[dict[str, Any]] = []
        existing = await self._finding_repo.list_all(limit=500)

        for other in existing:
            if other.id == finding.id:
                continue

            link_types = self._find_links(finding, other)
            for link_type, target_value in link_types:
                confidence = 0.7 if link_type in ("ip", "domain", "email") else 0.5
                link = CorrelationLink(
                    source_id=finding.id,
                    target_id=str(other.id),
                    correlation_type=link_type,
                    confidence=confidence,
                    metadata={"target_value": target_value},
                )
                await self._correlation_repo.save(link)
                finding.relationships.append(
                    Relationship(target_id=str(other.id), relation_type=link_type, target_type="finding")
                )
                correlations.append({
                    "type": link_type,
                    "target_id": str(other.id),
                    "confidence": confidence,
                })

        if correlations:
            finding.add_timeline_event("correlation", f"Found {len(correlations)} correlations")
            finding.metadata["correlations"] = correlations

        logger.info("correlation.completed", finding_id=str(finding.id), links=len(correlations))
        return finding, correlations

    def _find_links(self, a: Finding, b: Finding) -> list[tuple[str, str]]:
        """Find correlation links between two findings."""
        links: list[tuple[str, str]] = []

        a_indicators = {(i.type.value, i.value.lower()) for i in a.indicators}
        b_indicators = {(i.type.value, i.value.lower()) for i in b.indicators}
        common = a_indicators & b_indicators
        for ind_type, value in common:
            links.append((ind_type, value))

        common_tags = set(a.tags) & set(b.tags)
        for tag in common_tags:
            if any(t in tag for t in ("threat_actor", "campaign")):
                links.append((tag.split(":")[0] if ":" in tag else "tag", tag))

        if a.connector == b.connector and a.title.lower() == b.title.lower():
            links.append(("duplicate_candidate", a.title))

        return links
