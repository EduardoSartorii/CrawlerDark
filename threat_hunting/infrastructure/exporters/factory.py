"""ExporterFactory.

Responsibility
--------------
Build exporters by name from configuration, so callers select an export target
by data. New exporters are registered here (or via a plugin group) without
touching the CLI or services.
"""

from __future__ import annotations

from typing import Any

from threat_hunting.core.application.ports.exporter import Exporter
from threat_hunting.core.domain.exceptions import ExportError
from threat_hunting.infrastructure.exporters.csv_exporter import CsvExporter
from threat_hunting.infrastructure.exporters.json_exporter import JsonExporter
from threat_hunting.infrastructure.exporters.misp_exporter import MispExporter
from threat_hunting.infrastructure.exporters.stix_exporter import StixExporter
from threat_hunting.infrastructure.exporters.webhook_exporter import WebhookExporter


class ExporterFactory:
    """Creates exporters from a name + options mapping."""

    @staticmethod
    def build(name: str, **options: Any) -> Exporter:
        """Return the exporter registered under ``name``."""
        name = name.lower()
        if name == "json":
            return JsonExporter(**{k: v for k, v in options.items() if k in {"path"}})
        if name == "csv":
            return CsvExporter(**{k: v for k, v in options.items() if k in {"path"}})
        if name == "stix":
            return StixExporter(**{k: v for k, v in options.items() if k in {"path"}})
        if name == "webhook":
            return WebhookExporter(
                url=options.get("url", ""), transport=options.get("transport")
            )
        if name == "misp":
            return MispExporter(
                url=options.get("url"),
                key=options.get("key"),
                verify_tls=options.get("verify_tls", True),
            )
        raise ExportError(f"Unknown exporter '{name}'.")

    @staticmethod
    def available() -> list[str]:
        """Return the names of the built-in exporters."""
        return ["json", "csv", "stix", "webhook", "misp"]
