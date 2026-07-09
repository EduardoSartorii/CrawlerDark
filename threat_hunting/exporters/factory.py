"""Exporter factory."""

from __future__ import annotations

from threat_hunting.exporters.integrations import MispExporter, PlaceholderExternalExporter, WebhookExporter
from threat_hunting.exporters.local import CsvExporter, JsonExporter, Stix21Exporter
from threat_hunting.infrastructure.config.settings import ExporterSettings


class ExporterFactory:
    """Build exporter adapters from typed configuration."""

    def build(self, settings: ExporterSettings) -> object:
        """Return an exporter matching the configured type."""

        config = settings.config
        exporter_type = settings.type.lower()
        if exporter_type == "json":
            return JsonExporter(path=config.get("path", "exports/findings.ndjson"))
        if exporter_type == "csv":
            return CsvExporter(path=config.get("path", "exports/findings.csv"))
        if exporter_type in {"stix", "stix21", "stix2.1"}:
            return Stix21Exporter(path=config.get("path", "exports/findings.stix.ndjson"))
        if exporter_type in {"webhook", "rest"}:
            return WebhookExporter(url=config["url"], headers=config.get("headers"))
        if exporter_type == "misp":
            return MispExporter(
                url=config["url"],
                api_key=config["api_key"],
                event_id=config["event_id"],
                verify_tls=bool(config.get("verify_tls", True)),
            )
        return PlaceholderExternalExporter(name=settings.name, config=config)
