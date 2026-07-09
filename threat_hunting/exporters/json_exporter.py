"""JSON exporter adapter."""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

from threat_hunting.core.contracts import ExporterPort
from threat_hunting.domain.entities import ExecutionContext, Finding


class JsonExporter(ExporterPort):
    """Exports findings to newline-delimited JSON file."""

    name = "json"

    def __init__(self, output_path: Path | None = None) -> None:
        self._output_path = output_path or Path("artifacts/findings.jsonl")

    def export(self, findings: Sequence[Finding], context: ExecutionContext) -> None:
        """Write findings as JSON lines."""
        self._output_path.parent.mkdir(parents=True, exist_ok=True)
        with self._output_path.open("a", encoding="utf-8") as handler:
            for finding in findings:
                handler.write(json.dumps(finding.model_dump(mode="json"), ensure_ascii=False) + "\n")
