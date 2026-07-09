"""Local export adapters for JSON, CSV and STIX-like documents."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from threat_hunting.core.domain.entities import Finding


class JsonExporter:
    """Export findings to newline-delimited JSON."""

    name = "json"

    def __init__(self, path: str = "exports/findings.ndjson") -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def export(self, finding: Finding) -> None:
        """Append one finding to an NDJSON file."""

        with self._path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(finding.model_dump(mode="json"), sort_keys=True) + "\n")


class CsvExporter:
    """Export a compact finding view to CSV."""

    name = "csv"

    def __init__(self, path: str = "exports/findings.csv") -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def export(self, finding: Finding) -> None:
        """Append one finding to CSV."""

        exists = self._path.exists()
        with self._path.open("a", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=["id", "title", "source", "connector", "severity", "score"])
            if not exists:
                writer.writeheader()
            writer.writerow(
                {
                    "id": finding.id,
                    "title": finding.title,
                    "source": finding.source,
                    "connector": finding.connector,
                    "severity": finding.severity.value,
                    "score": finding.score,
                }
            )


class Stix21Exporter(JsonExporter):
    """Export a STIX 2.1 bundle-shaped JSON document."""

    name = "stix21"

    def export(self, finding: Finding) -> None:
        """Append a STIX-like indicator bundle for one finding."""

        bundle = {
            "type": "bundle",
            "spec_version": "2.1",
            "id": f"bundle--{finding.id}",
            "objects": [
                {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": f"indicator--{finding.id}",
                    "name": finding.title,
                    "description": finding.description,
                    "labels": finding.tags,
                    "confidence": int(finding.confidence * 100),
                }
            ],
        }
        with self._path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(bundle, sort_keys=True) + "\n")
