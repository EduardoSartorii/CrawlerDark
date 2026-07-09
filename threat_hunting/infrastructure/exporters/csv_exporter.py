"""CSV exporter.

Responsibility
--------------
Emit a flat, analyst-friendly CSV summary of findings (one row per finding) for
spreadsheets, ticketing imports and quick triage. Nested collections are
summarised into scalar columns.
"""

from __future__ import annotations

import csv
from collections.abc import Sequence
from pathlib import Path

from threat_hunting.core.application.ports.exporter import ExporterPort
from threat_hunting.core.domain.entities import Finding

_COLUMNS = [
    "id",
    "title",
    "source",
    "connector",
    "category",
    "severity",
    "score",
    "confidence",
    "indicators",
    "tags",
    "created_at",
]


class CsvExporter(ExporterPort):
    """Writes a one-row-per-finding CSV file."""

    name = "csv"

    def __init__(self, output_dir: str | Path = "exports") -> None:
        self._dir = Path(output_dir)

    def supports_auto_export(self) -> bool:
        return False

    def export(self, findings: Sequence[Finding]) -> int:
        self._dir.mkdir(parents=True, exist_ok=True)
        target = self._dir / "findings.csv"
        with target.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=_COLUMNS)
            writer.writeheader()
            for finding in findings:
                writer.writerow(
                    {
                        "id": finding.id,
                        "title": finding.title,
                        "source": finding.source,
                        "connector": finding.connector,
                        "category": finding.category.value,
                        "severity": finding.severity.value,
                        "score": finding.score,
                        "confidence": finding.confidence.value,
                        "indicators": ";".join(
                            i.fingerprint() for i in finding.indicators
                        ),
                        "tags": ";".join(finding.tags),
                        "created_at": finding.created_at.isoformat(),
                    }
                )
        return len(findings)
