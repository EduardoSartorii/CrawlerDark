"""Indicator-based correlation engine."""

from __future__ import annotations

from collections.abc import Sequence

from threat_hunting.core.domain.entities import Finding, Relationship


class IndicatorCorrelationEngine:
    """Create relationships when findings share indicators or entities."""

    def correlate(self, finding: Finding, existing: Sequence[Finding]) -> Finding:
        """Return a finding with relationships to matching findings."""

        current = {(indicator.type, indicator.value.lower()) for indicator in finding.indicators}
        relationships = list(finding.relationships)
        linked_ids = {relationship.target for relationship in relationships}
        for candidate in existing:
            candidate_indicators = {(indicator.type, indicator.value.lower()) for indicator in candidate.indicators}
            overlap = current.intersection(candidate_indicators)
            if overlap and candidate.id not in linked_ids:
                relationships.append(
                    Relationship(
                        source=finding.id,
                        target=candidate.id,
                        kind="shared_indicator",
                        confidence=min(1.0, 0.4 + (len(overlap) * 0.2)),
                        metadata={"overlap": [f"{kind}:{value}" for kind, value in sorted(overlap)]},
                    )
                )
        return finding.model_copy(update={"relationships": relationships})
