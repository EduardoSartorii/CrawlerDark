"""CSV exporter.

Responsibility
--------------
Emit a flat, analyst-friendly CSV summary (one row per finding) for spreadsheet
triage. Complex nested fields (indicators, tags) are collapsed to compact
strings. Dependency-free (stdlib ``csv``).
"""

from __future__ import annotations

import csv
from collections.abc import Sequence
from pathlib import Path

from threat_hunting.core.application.ports.exporter import ExportResult
from threat_hunting.core.domain.entities.finding import Finding

_COLUMNS = (
    "id",
    "created_at",
    "connector",
    "source",
    "category",
    "severity",
    "score",
    "confidence",
    "title",
    "tags",
    "indicators",
)


class CsvExporter:
    """Exports findings to a flat CSV file."""

    name = "csv"

    def __init__(self, path: str = "exports/findings.csv") -> None:
        self._path = Path(path)

    def export(self, findings: Sequence[Finding]) -> ExportResult:
        """Write one CSV row per finding and return the result."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=_COLUMNS)
            writer.writeheader()
            for finding in findings:
                writer.writerow(
                    {
                        "id": finding.id,
                        "created_at": finding.created_at.isoformat(),
                        "connector": finding.connector,
                        "source": finding.source,
                        "category": finding.category.value,
                        "severity": finding.severity.value,
                        "score": f"{finding.score.value:.1f}",
                        "confidence": finding.confidence,
                        "title": finding.title,
                        "tags": "|".join(finding.tags),
                        "indicators": "|".join(sorted(finding.indicator_keys)),
                    }
                )
        return ExportResult(
            exporter=self.name, exported=len(findings), destination=str(self._path)
        )
