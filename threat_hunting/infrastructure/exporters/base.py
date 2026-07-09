"""
BaseExporter
============

Provides common functionality for all exporters:
    - Batch export with per-item error isolation.
    - Structured logging.
    - Finding-to-dict serialization.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from threat_hunting.core.domain.ports.exporters import IExporter

if TYPE_CHECKING:
    from threat_hunting.core.domain.entities.finding import Finding


class BaseExporter(IExporter):
    """Abstract base for all exporters."""

    exporter_id: str = ""
    exporter_name: str = ""

    def __init__(self) -> None:
        self._logger = structlog.get_logger(__name__).bind(exporter=self.exporter_id)

    async def export_batch(self, findings: list["Finding"]) -> dict[str, bool]:
        """Export a list of Findings, isolating per-item errors."""
        results: dict[str, bool] = {}
        for finding in findings:
            try:
                results[finding.id] = await self.export(finding)
            except Exception as exc:
                self._logger.error("batch_item_failed", finding_id=finding.id, error=str(exc))
                results[finding.id] = False
        return results

    def _finding_to_dict(self, finding: "Finding") -> dict:
        """Serialize a Finding to a plain dict for export."""
        return {
            "id": finding.id,
            "title": finding.title,
            "description": finding.description,
            "source": finding.source.value,
            "connector": finding.connector,
            "category": finding.category.value,
            "severity": finding.severity.value,
            "score": finding.score.value,
            "confidence": finding.score.confidence,
            "status": finding.status.value,
            "tags": finding.tags,
            "indicators": finding.indicators,
            "source_url": finding.source_url,
            "created_at": finding.created_at.isoformat(),
            "updated_at": finding.updated_at.isoformat(),
            "normalized_data": finding.normalized_data,
            "metadata": finding.metadata,
            "matched_rules": finding.matched_rules,
            "relationships": [r.model_dump() for r in finding.relationships],
        }
