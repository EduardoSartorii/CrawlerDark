"""Correlation engine for infrastructure, identity, campaign, and IOC overlap."""

from __future__ import annotations

from collections.abc import Iterable

from threat_hunting.core.domain.entities import Finding, Relationship


class IndicatorCorrelationEngine:
    """Correlate findings through shared indicator values."""

    def correlate(self, finding: Finding, existing: Iterable[Finding]) -> Finding:
        """Add relationships for overlapping indicators."""

        current = {(indicator.type.value, indicator.value.lower()) for indicator in finding.indicators}
        relationships = list(finding.relationships)
        for candidate in existing:
            candidate_values = {(indicator.type.value, indicator.value.lower()) for indicator in candidate.indicators}
            overlap = current.intersection(candidate_values)
            for indicator_type, value in sorted(overlap):
                relationships.append(
                    Relationship(
                        source_ref=str(finding.id),
                        target_ref=str(candidate.id),
                        relationship_type=f"shared_{indicator_type}",
                        confidence=0.8,
                        metadata={"value": value},
                    )
                )
        return finding.model_copy(update={"relationships": relationships})
