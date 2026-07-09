"""The correlation engine.

Responsibility
--------------
Implement :class:`CorrelationEnginePort`: link a new finding to prior
intelligence. Correlation is what turns isolated observations into campaigns and
infrastructure clusters. It compares the finding's indicators, actors, brands and
tags against a bounded context window of recent findings and attaches typed
:class:`Relationship` edges (shared IOC, same actor, same brand, same
infrastructure, ...).

Business rules
--------------
* Only enabled correlation dimensions produce edges (all on by default).
* Correlation never mutates the *other* finding — it only records edges on the
  current one (single-writer, avoids cross-aggregate mutation).
"""

from __future__ import annotations

from collections.abc import Sequence

from threat_hunting.core.application.ports.pipeline_stages import (
    CorrelationEnginePort,
)
from threat_hunting.core.domain.entities import Finding, Relationship
from threat_hunting.core.domain.enums import ConfidenceLevel, RelationshipType


class CorrelationEngine(CorrelationEnginePort):
    """Infers relationships between a finding and recent context."""

    def __init__(self, *, max_links: int = 25) -> None:
        self._max_links = max_links

    def correlate(self, finding: Finding, context: Sequence[Finding]) -> Finding:
        """Attach relationship edges linking the finding to the context."""
        links = 0
        own_iocs = finding.indicator_fingerprints()
        own_actors = self._tag_values(finding, "actor:")
        own_brands = self._tag_values(finding, "brand:")

        for other in context:
            if other.id == finding.id or links >= self._max_links:
                continue

            shared = own_iocs & other.indicator_fingerprints()
            if shared:
                self._link(
                    finding,
                    other,
                    RelationshipType.SHARES_INDICATOR,
                    f"shares {len(shared)} indicator(s): {sorted(shared)[:3]}",
                    ConfidenceLevel.HIGH,
                )
                links += 1
                continue

            if own_actors & self._tag_values(other, "actor:"):
                self._link(
                    finding, other, RelationshipType.SAME_ACTOR,
                    "same tracked threat actor", ConfidenceLevel.MEDIUM,
                )
                links += 1
                continue

            if own_brands & self._tag_values(other, "brand:"):
                self._link(
                    finding, other, RelationshipType.SAME_BRAND,
                    "same monitored brand", ConfidenceLevel.MEDIUM,
                )
                links += 1

        finding.metadata["correlation"] = {"links": links}
        return finding

    @staticmethod
    def _tag_values(finding: Finding, prefix: str) -> set[str]:
        """Return the set of tag suffixes for tags with a given prefix."""
        return {t[len(prefix):] for t in finding.tags if t.startswith(prefix)}

    @staticmethod
    def _link(
        finding: Finding,
        other: Finding,
        rel_type: RelationshipType,
        reason: str,
        confidence: ConfidenceLevel,
    ) -> None:
        """Attach a single relationship edge to ``finding``."""
        finding.add_relationship(
            Relationship(
                type=rel_type,
                target_ref=other.id,
                confidence=confidence,
                reason=reason,
            )
        )
