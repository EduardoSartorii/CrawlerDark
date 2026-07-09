"""JSON exporter.

Responsibility
--------------
Emit findings as a JSON array to a file. The simplest, universally-consumable
export; also the reference implementation of :class:`ExporterPort`.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

from threat_hunting.core.application.ports.exporter import ExporterPort
from threat_hunting.core.domain.entities import Finding


class JsonExporter(ExporterPort):
    """Writes findings to a JSON file."""

    name = "json"

    def __init__(self, output_dir: str | Path = "exports") -> None:
        self._dir = Path(output_dir)

    def supports_auto_export(self) -> bool:
        return False

    def export(self, findings: Sequence[Finding]) -> int:
        self._dir.mkdir(parents=True, exist_ok=True)
        payload = [f.model_dump(mode="json") for f in findings]
        target = self._dir / "findings.json"
        target.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return len(payload)
