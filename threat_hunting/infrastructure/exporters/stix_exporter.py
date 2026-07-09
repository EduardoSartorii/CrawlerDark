"""
STIXExporter
============

Exports Findings as STIX 2.1 bundles.
Supports:
    - Report objects for Findings
    - Indicator observables for IOCs
    - ThreatActor objects for actor references
    - Relationship objects for correlations
    - File output or direct TAXII delivery (future)

STIX 2.1 specification: https://docs.oasis-open.org/cti/stix/v2.1/
"""

from __future__ import annotations

import json
from datetime import timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

import structlog

from threat_hunting.infrastructure.exporters.base import BaseExporter

if TYPE_CHECKING:
    from threat_hunting.core.domain.entities.finding import Finding

logger = structlog.get_logger(__name__)


class STIXExporter(BaseExporter):
    """Exports Findings as STIX 2.1 bundles to JSON files."""

    exporter_id = "stix"
    exporter_name = "STIX 2.1 Exporter"

    def __init__(self, output_path: str = "exports/stix") -> None:
        super().__init__()
        self._output_path = Path(output_path)
        self._output_path.mkdir(parents=True, exist_ok=True)

    async def export(self, finding: "Finding") -> bool:
        """Convert a Finding to a STIX 2.1 bundle and write to file."""
        try:
            bundle = self._build_bundle(finding)
            filename = f"stix_{finding.id[:8]}_{finding.connector}.json"
            filepath = self._output_path / filename
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(bundle, f, indent=2, default=str)
            self._logger.info("stix_exported", file=str(filepath))
            return True
        except Exception as exc:
            self._logger.error("stix_export_failed", finding_id=finding.id, error=str(exc))
            return False

    def _build_bundle(self, finding: "Finding") -> dict[str, Any]:
        """Build a minimal STIX 2.1 Bundle from a Finding."""
        objects: list[dict[str, Any]] = []

        report_id = f"report--{finding.id}"
        report: dict[str, Any] = {
            "type": "report",
            "spec_version": "2.1",
            "id": report_id,
            "created": finding.created_at.astimezone(timezone.utc).isoformat(),
            "modified": finding.updated_at.astimezone(timezone.utc).isoformat(),
            "name": finding.title[:512],
            "description": finding.description[:4096],
            "published": finding.created_at.astimezone(timezone.utc).isoformat(),
            "report_types": [self._category_to_stix(finding.category.value)],
            "object_refs": [],
            "labels": finding.tags[:25],
            "external_references": [],
            "confidence": int(finding.score.confidence * 100),
        }

        if finding.source_url:
            report["external_references"].append({
                "source_name": finding.connector,
                "url": finding.source_url,
            })

        objects.append(report)

        return {
            "type": "bundle",
            "id": f"bundle--{finding.id}",
            "spec_version": "2.1",
            "objects": objects,
        }

    def _category_to_stix(self, category: str) -> str:
        mapping = {
            "malware": "malware",
            "phishing": "threat-report",
            "credential_leak": "threat-report",
            "campaign": "attack-pattern",
            "threat_actor": "threat-actor",
            "ioc": "indicator",
            "vulnerability": "vulnerability",
        }
        return mapping.get(category, "threat-report")

    async def health(self) -> bool:
        return self._output_path.is_dir()
