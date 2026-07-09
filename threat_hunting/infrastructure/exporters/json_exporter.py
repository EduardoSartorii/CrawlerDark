"""
JSON Exporter.

Exports findings to JSON files or stdout.
Useful for integration with any system that consumes JSON.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import structlog

from ...core.domain.entities.finding import Finding
from .base import BaseExporter, ExportResult

logger = structlog.get_logger(__name__)


class JSONExporter(BaseExporter):
    """
    Exports findings to a JSON file or stdout.

    Config keys:
        output_path: str — file path (default: stdout)
        pretty: bool — pretty-print JSON (default: True)
        append: bool — append to existing file (default: False)
    """

    exporter_id = "json"
    name = "JSON Exporter"
    description = "Exports findings to JSON format"

    async def export(self, findings: list[Finding]) -> ExportResult:
        result = ExportResult(destination="json")
        output_path = self._config.get("output_path")
        pretty = self._config.get("pretty", True)
        indent = 2 if pretty else None

        records = [self._serialize(f) for f in findings]

        try:
            json_str = json.dumps(records, indent=indent, default=str)
            if output_path:
                path = Path(output_path)
                path.parent.mkdir(parents=True, exist_ok=True)
                mode = "a" if self._config.get("append") else "w"
                with open(path, mode, encoding="utf-8") as f:
                    f.write(json_str)
                logger.info("json.exported", path=str(path), count=len(findings))
            else:
                print(json_str)

            result.exported_count = len(findings)
        except Exception as exc:
            result.errors.append(str(exc))
            logger.error("json.export_failed", error=str(exc))

        return result

    def _serialize(self, finding: Finding) -> dict[str, Any]:
        return {
            "id": finding.id,
            "title": finding.title,
            "description": finding.description,
            "source": finding.source,
            "source_type": finding.source_type if isinstance(finding.source_type, str) else finding.source_type.value,
            "connector": finding.connector,
            "category": finding.category.value,
            "status": finding.status.value,
            "severity": finding.severity.level.name,
            "score": finding.score.value,
            "confidence": finding.confidence,
            "tlp": finding.tlp,
            "tags": finding.tags,
            "source_url": finding.source_url,
            "threat_actor": finding.threat_actor,
            "campaign": finding.campaign,
            "malware_family": finding.malware_family,
            "affected_brands": finding.affected_brands,
            "affected_domains": finding.affected_domains,
            "indicators": finding.indicator_ids,
            "created_at": finding.created_at.isoformat(),
            "updated_at": finding.updated_at.isoformat(),
        }

    async def health(self) -> bool:
        return True
