"""Local enrichment engine."""

from __future__ import annotations

from datetime import UTC, datetime

from threat_hunting.core.domain.entities import Finding, TimelineEvent


class ContextEnrichmentEngine:
    """Add derived context and timeline evidence without external coupling."""

    def enrich(self, finding: Finding) -> Finding:
        """Return a finding enriched with timeline and context metadata."""

        metadata = dict(finding.metadata)
        metadata["indicator_count"] = len(finding.indicators)
        metadata["relationship_count"] = len(finding.relationships)
        timeline = list(finding.timeline)
        timeline.append(
            TimelineEvent(
                timestamp=datetime.now(UTC),
                title="Finding enriched",
                description="Local context enrichment completed.",
            )
        )
        return finding.model_copy(update={"metadata": metadata, "timeline": timeline})
