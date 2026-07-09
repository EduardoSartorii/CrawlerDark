"""Enrichment engine adapters."""

from __future__ import annotations

from typing import Any

from threat_hunting.core.domain.entities import Finding, TimelineEvent


class MetadataEnrichmentEngine:
    """Attach configured contextual enrichment without external coupling."""

    def __init__(self, context: dict[str, Any] | None = None) -> None:
        self.context = context or {}

    def enrich(self, finding: Finding) -> Finding:
        """Return finding with enrichment metadata and timeline event."""

        metadata = {**finding.metadata, "enrichment": self.context}
        timeline = [
            *finding.timeline,
            TimelineEvent(event_type="enriched", description="Finding enriched with configured context."),
        ]
        return finding.model_copy(update={"metadata": metadata, "timeline": timeline})
