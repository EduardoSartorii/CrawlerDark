"""Exporter factory.

Responsibility
--------------
Build the set of exporters from configuration (Factory pattern) and expose them
by name to the export use case and the pipeline's auto-export. Adding a new
exporter means registering it here (or via the same plugin mechanism as
connectors); nothing else changes.
"""

from __future__ import annotations

from threat_hunting.core.application.ports.exporter import ExporterPort
from threat_hunting.infrastructure.config.settings import ExportSettings
from threat_hunting.infrastructure.exporters.csv_exporter import CsvExporter
from threat_hunting.infrastructure.exporters.json_exporter import JsonExporter
from threat_hunting.infrastructure.exporters.misp_exporter import MispExporter
from threat_hunting.infrastructure.exporters.stix_exporter import StixExporter


class ExporterFactory:
    """Creates and indexes exporters from platform settings."""

    def __init__(self, settings: ExportSettings) -> None:
        self._settings = settings

    def build_all(self) -> dict[str, ExporterPort]:
        """Return every available exporter keyed by name."""
        out = self._settings.output_dir
        exporters: list[ExporterPort] = [
            JsonExporter(out),
            CsvExporter(out),
            StixExporter(out),
            MispExporter(
                url=self._settings.misp_url,
                key=self._settings.misp_key,
                event_id=self._settings.misp_event_id,
                output_dir=out,
            ),
        ]
        return {exporter.name: exporter for exporter in exporters}

    def auto_export_targets(self) -> list[ExporterPort]:
        """Return exporters eligible for automatic threshold export."""
        wanted = set(self._settings.auto_export_targets)
        return [
            exporter
            for name, exporter in self.build_all().items()
            if name in wanted and exporter.supports_auto_export()
        ]
