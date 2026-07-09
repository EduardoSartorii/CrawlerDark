"""Enrichment engine implementation."""

from __future__ import annotations

from typing import Any

from threat_hunting.core.contracts import StageContext


class ContextEnrichmentEngine:
    """Enrich findings with contextual metadata and tags."""

    def run(self, items: list[dict[str, Any]], context: StageContext) -> list[dict[str, Any]]:
        """Add contextual enrichment generated from execution context."""
        enriched: list[dict[str, Any]] = []
        for item in items:
            metadata = dict(item.get("metadata", {}))
            tags = set(item.get("tags", []))
            metadata["run_id"] = context.run_id
            metadata["connector_name"] = context.connector_name
            metadata["enriched"] = True
            if item.get("score", 0.0) >= 80:
                tags.add("high-priority")
            enriched.append({**item, "metadata": metadata, "tags": sorted(tags)})
        return enriched
