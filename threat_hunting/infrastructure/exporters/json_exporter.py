"""JSON exporter.

Responsibility
--------------
Serialise findings to a JSON file (one document with a ``findings`` array).
Dependency-free and lossless — the full finding model is emitted, making it a
good interchange/backup format.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

from threat_hunting.core.application.ports.exporter import ExportResult
from threat_hunting.core.domain.entities.finding import Finding


class JsonExporter:
    """Exports findings to a JSON document."""

    name = "json"

    def __init__(self, path: str = "exports/findings.json") -> None:
        self._path = Path(path)

    def export(self, findings: Sequence[Finding]) -> ExportResult:
        """Write all findings to the JSON file and return the result."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"findings": [f.model_dump(mode="json") for f in findings]}
        self._path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return ExportResult(
            exporter=self.name, exported=len(findings), destination=str(self._path)
        )
