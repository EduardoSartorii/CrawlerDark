"""Enrichment engine that appends internal context to findings."""

from __future__ import annotations

from collections.abc import Sequence

from threat_hunting.core.contracts import EnrichmentEnginePort
from threat_hunting.domain.entities import ExecutionContext, Finding, TimelineEvent


class ContextEnrichmentEngine(EnrichmentEnginePort):
    """Adds pipeline execution metadata as enrichment context."""

    def process(self, findings: Sequence[Finding], context: ExecutionContext) -> Sequence[Finding]:
        """Attach execution context and timeline event."""
        for finding in findings:
            finding.metadata["run_id"] = str(context.run_id)
            finding.metadata["command"] = context.command
            finding.timeline.append(
                TimelineEvent(
                    timestamp=context.started_at,
                    label="enriched",
                    details={"connector": context.connector_name},
                )
            )
            finding.touch()
        return findings
