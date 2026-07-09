"""
CSV Exporter.

Exports findings to CSV format for consumption by spreadsheet tools,
SIEM imports, and data analysis pipelines.
"""

from __future__ import annotations

import csv
import io
from pathlib import Path
from typing import Any

import structlog

from ...core.domain.entities.finding import Finding
from .base import BaseExporter, ExportResult

logger = structlog.get_logger(__name__)

_CSV_FIELDS = [
    "id", "title", "source", "connector", "category",
    "severity", "score", "confidence", "tlp", "status",
    "source_url", "threat_actor", "campaign", "malware_family",
    "affected_brands", "tags", "created_at",
]


class CSVExporter(BaseExporter):
    """
    Exports findings to CSV.

    Config keys:
        output_path: str — file path (default: stdout)
        fields: list[str] — columns to include
        delimiter: str — CSV delimiter (default: ",")
    """

    exporter_id = "csv"
    name = "CSV Exporter"
    description = "Exports findings to CSV format"

    async def export(self, findings: list[Finding]) -> ExportResult:
        result = ExportResult(destination="csv")
        fields = self._config.get("fields", _CSV_FIELDS)
        delimiter = self._config.get("delimiter", ",")
        output_path = self._config.get("output_path")

        try:
            if output_path:
                path = Path(output_path)
                path.parent.mkdir(parents=True, exist_ok=True)
                with open(path, "w", newline="", encoding="utf-8") as f:
                    self._write_csv(f, findings, fields, delimiter)
                logger.info("csv.exported", path=str(path), count=len(findings))
            else:
                buffer = io.StringIO()
                self._write_csv(buffer, findings, fields, delimiter)
                print(buffer.getvalue())

            result.exported_count = len(findings)
        except Exception as exc:
            result.errors.append(str(exc))
            logger.error("csv.export_failed", error=str(exc))

        return result

    def _write_csv(self, fileobj: Any, findings: list[Finding], fields: list[str], delimiter: str) -> None:
        writer = csv.DictWriter(fileobj, fieldnames=fields, delimiter=delimiter, extrasaction="ignore")
        writer.writeheader()
        for f in findings:
            row = {
                "id": f.id,
                "title": f.title,
                "source": f.source,
                "connector": f.connector,
                "category": f.category.value,
                "severity": f.severity.level.name,
                "score": f"{f.score.value:.2f}",
                "confidence": f"{f.confidence:.2f}",
                "tlp": f.tlp,
                "status": f.status.value,
                "source_url": f.source_url or "",
                "threat_actor": f.threat_actor or "",
                "campaign": f.campaign or "",
                "malware_family": f.malware_family or "",
                "affected_brands": ";".join(f.affected_brands),
                "tags": ";".join(f.tags),
                "created_at": f.created_at.isoformat(),
            }
            writer.writerow(row)

    async def health(self) -> bool:
        return True
