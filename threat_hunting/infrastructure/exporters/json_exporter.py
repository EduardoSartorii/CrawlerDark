"""
JSONExporter
============

Exports Findings to JSON files on the local filesystem.
One file per Finding, named by ID and timestamp.
Useful for archiving, manual review, and feeding downstream pipelines.

Output path: configured via exporters.json_output_path (default: exports/json/).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from threat_hunting.infrastructure.exporters.base import BaseExporter

if TYPE_CHECKING:
    from threat_hunting.core.domain.entities.finding import Finding


class JSONExporter(BaseExporter):
    """Exports Findings to JSON files."""

    exporter_id = "json"
    exporter_name = "JSON File Exporter"

    def __init__(self, output_path: str = "exports/json") -> None:
        super().__init__()
        self._output_path = Path(output_path)
        self._output_path.mkdir(parents=True, exist_ok=True)

    async def export(self, finding: "Finding") -> bool:
        """Write a single Finding to a JSON file."""
        try:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            filename = f"{timestamp}_{finding.connector}_{finding.id[:8]}.json"
            filepath = self._output_path / filename

            data = self._finding_to_dict(finding)
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False, default=str)

            self._logger.info("exported_json", file=str(filepath))
            return True
        except Exception as exc:
            self._logger.error("json_export_failed", finding_id=finding.id, error=str(exc))
            return False

    async def health(self) -> bool:
        """Check that the output directory is writable."""
        return self._output_path.is_dir() and __import__("os").access(self._output_path, __import__("os").W_OK)
