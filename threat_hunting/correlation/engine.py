"""Correlation engine that links related findings through shared indicators."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence

from threat_hunting.core.contracts import CorrelationEnginePort
from threat_hunting.domain.entities import ExecutionContext, Finding, Relationship


class IndicatorCorrelationEngine(CorrelationEnginePort):
    """Correlates findings by indicator value and category."""

    def process(self, findings: Sequence[Finding], context: ExecutionContext) -> Sequence[Finding]:
        """Attach relationship links when indicators overlap."""
        indicator_index: dict[str, list[Finding]] = defaultdict(list)
        for finding in findings:
            for indicator in finding.indicators:
                indicator_index[f"{indicator.type}:{indicator.value.lower()}"].append(finding)

        for related_findings in indicator_index.values():
            if len(related_findings) < 2:
                continue
            for finding in related_findings:
                for candidate in related_findings:
                    if candidate.id == finding.id:
                        continue
                    relationship = Relationship(
                        target_type="finding",
                        target_id=str(candidate.id),
                        relation_type="shared_indicator",
                        confidence=0.8,
                    )
                    if relationship not in finding.relationships:
                        finding.relationships.append(relationship)
                finding.touch()
        return findings
