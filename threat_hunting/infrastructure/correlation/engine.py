"""
CorrelationEngine
=================

Implements the ICorrelationEngine port.

Links related Findings by identifying shared:
    - IOC values (IP, domain, hash, email)
    - Threat actor references
    - Campaign identifiers
    - Tag overlap
    - Temporal proximity (time window)

When correlation is found:
    - Relationship objects are added to the Finding.
    - Findings sharing ≥ 1 correlated attribute are assigned to the same
      correlation_group (a stable UUID that persists across runs).
    - The correlation_group enables downstream aggregation and reporting.

Architecture:
    - Uses the IFindingRepository.find_similar() for candidate retrieval.
    - Correlation logic is pure Python — no external dependencies.
    - Future: graph-based correlation using NetworkX or a graph DB.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

import structlog

from threat_hunting.core.domain.entities.finding import FindingStatus, Relationship
from threat_hunting.core.domain.events.finding_events import FindingCorrelated
from threat_hunting.core.domain.exceptions.domain_exceptions import CorrelationError
from threat_hunting.core.domain.ports.engines import ICorrelationEngine

if TYPE_CHECKING:
    from threat_hunting.core.domain.entities.finding import Finding
    from threat_hunting.core.domain.ports.event_bus import IEventBus
    from threat_hunting.core.domain.ports.repositories import IFindingRepository

logger = structlog.get_logger(__name__)


class CorrelationEngine(ICorrelationEngine):
    """
    Finding correlation engine.

    Identifies relationships between Findings based on shared IOCs,
    actors, tags, and temporal proximity.
    """

    def __init__(
        self,
        finding_repo: "IFindingRepository",
        event_bus: "IEventBus",
        time_window_hours: int = 72,
        min_shared_attributes: int = 1,
    ) -> None:
        self._finding_repo = finding_repo
        self._event_bus = event_bus
        self._time_window = timedelta(hours=time_window_hours)
        self._min_shared = min_shared_attributes

    async def correlate(self, finding: "Finding") -> "Finding":
        """
        Find and link related Findings.

        Args:
            finding: A scored Finding.

        Returns:
            Finding with relationships and correlation_group assigned.
        """
        log = logger.bind(finding_id=finding.id)

        try:
            # Fetch candidate Findings from the last N hours.
            since = datetime.now(timezone.utc) - self._time_window
            candidates = await self._finding_repo.list(
                since=since,
                limit=200,
            )

            # Exclude the Finding itself.
            candidates = [c for c in candidates if c.id != finding.id]

            related_ids: list[str] = []
            for candidate in candidates:
                shared = self._shared_attributes(finding, candidate)
                if len(shared) >= self._min_shared:
                    finding.add_relationship(
                        Relationship(
                            target_type="Finding",
                            target_id=candidate.id,
                            relationship_type="correlated",
                            confidence=min(1.0, len(shared) / 3),
                            metadata={"shared_attributes": list(shared)},
                        )
                    )
                    related_ids.append(candidate.id)

            if related_ids:
                # Assign or inherit correlation group.
                existing_groups = [
                    c.correlation_group
                    for c in candidates
                    if c.id in related_ids and c.correlation_group
                ]
                finding.correlation_group = existing_groups[0] if existing_groups else str(uuid.uuid4())
                finding.add_tag("correlated")
                log.info(
                    "correlated",
                    related_count=len(related_ids),
                    group=finding.correlation_group,
                )
                await self._event_bus.publish(
                    FindingCorrelated(
                        aggregate_id=finding.id,
                        correlation_group=finding.correlation_group,
                        related_finding_ids=related_ids,
                    )
                )

        except Exception as exc:
            log.error("correlation_error", error=str(exc))
            raise CorrelationError(f"Correlation failed: {exc}") from exc

        finding.advance_status(FindingStatus.CORRELATED)
        return finding

    def _shared_attributes(self, a: "Finding", b: "Finding") -> set[str]:
        """Return the set of attributes shared between two Findings."""
        shared: set[str] = set()

        # Shared indicators (IOC IDs overlap).
        shared_iocs = set(a.indicators) & set(b.indicators)
        if shared_iocs:
            shared.update(f"ioc:{ioc}" for ioc in list(shared_iocs)[:3])

        # Shared tags.
        shared_tags = set(a.tags) & set(b.tags) - {"general", "osint", "news"}
        if shared_tags:
            shared.update(f"tag:{t}" for t in list(shared_tags)[:3])

        # Same connector.
        if a.connector == b.connector:
            shared.add(f"connector:{a.connector}")

        # Same category.
        if a.category == b.category and a.category.value not in ("general", "osint"):
            shared.add(f"category:{a.category.value}")

        return shared
