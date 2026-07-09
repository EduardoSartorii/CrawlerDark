"""
CSVExporter
===========

Exports Findings to CSV files for use in spreadsheets, SIEMs, and reporting.
Appends to a daily rolling file (one file per day per connector).
"""

from __future__ import annotations

import csv
import io
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from threat_hunting.infrastructure.exporters.base import BaseExporter

if TYPE_CHECKING:
    from threat_hunting.core.domain.entities.finding import Finding

CSV_FIELDS = [
    "id", "title", "connector", "source", "category",
    "severity", "score", "confidence", "status", "tags",
    "source_url", "created_at", "matched_rules",
]


class CSVExporter(BaseExporter):
    """Exports Findings to CSV files."""

    exporter_id = "csv"
    exporter_name = "CSV File Exporter"

    def __init__(self, output_path: str = "exports/csv") -> None:
        super().__init__()
        self._output_path = Path(output_path)
        self._output_path.mkdir(parents=True, exist_ok=True)

    async def export(self, finding: "Finding") -> bool:
        """Append a Finding row to the daily CSV file."""
        try:
            date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
            filename = f"{date_str}_{finding.connector}.csv"
            filepath = self._output_path / filename
            is_new = not filepath.exists()

            with open(filepath, "a", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
                if is_new:
                    writer.writeheader()
                writer.writerow({
                    "id": finding.id,
                    "title": finding.title,
                    "connector": finding.connector,
                    "source": finding.source.value,
                    "category": finding.category.value,
                    "severity": finding.severity.value,
                    "score": f"{finding.score.value:.2f}",
                    "confidence": f"{finding.score.confidence:.2f}",
                    "status": finding.status.value,
                    "tags": "|".join(finding.tags),
                    "source_url": finding.source_url or "",
                    "created_at": finding.created_at.isoformat(),
                    "matched_rules": "|".join(finding.matched_rules),
                })
            return True
        except Exception as exc:
            self._logger.error("csv_export_failed", finding_id=finding.id, error=str(exc))
            return False

    async def health(self) -> bool:
        return self._output_path.is_dir()
