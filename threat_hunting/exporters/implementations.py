"""Concrete exporter adapters."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

import httpx

from threat_hunting.core.domain.entities import Finding
from threat_hunting.exporters.base import BaseExporter
from threat_hunting.infrastructure.config import PlatformSettings


class JsonExporter(BaseExporter):
    """Export findings as JSON."""

    name = "json"

    def __init__(self, path: Path) -> None:
        self.path = path

    def export(self, findings: list[Finding]) -> None:
        """Write findings to JSON."""

        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps([finding.model_dump(mode="json") for finding in findings], indent=2, sort_keys=True),
            encoding="utf-8",
        )


class CsvExporter(BaseExporter):
    """Export findings as CSV."""

    name = "csv"

    def __init__(self, path: Path) -> None:
        self.path = path

    def export(self, findings: list[Finding]) -> None:
        """Write selected finding fields to CSV."""

        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=["id", "title", "source", "connector", "severity", "score"])
            writer.writeheader()
            for finding in findings:
                writer.writerow(
                    {
                        "id": str(finding.id),
                        "title": finding.title,
                        "source": finding.source,
                        "connector": finding.connector,
                        "severity": finding.severity.value,
                        "score": finding.score,
                    }
                )


class WebhookExporter(BaseExporter):
    """Export findings to a generic webhook or REST API."""

    name = "webhook"

    def __init__(self, url: str, headers: dict[str, str] | None = None) -> None:
        self.url = url
        self.headers = headers or {}

    def export(self, findings: list[Finding]) -> None:
        """POST findings to a webhook."""

        httpx.post(self.url, json=[finding.model_dump(mode="json") for finding in findings], headers=self.headers).raise_for_status()


class StubExporter(BaseExporter):
    """Operational placeholder for integrations configured outside tests."""

    def __init__(self, name: str, config: dict[str, Any]) -> None:
        self.name = name
        self.config = config
        self.last_exported: list[Finding] = []

    def export(self, findings: list[Finding]) -> None:
        """Record export intent for adapters that require external services."""

        self.last_exported = list(findings)


def build_exporters(settings: PlatformSettings) -> dict[str, BaseExporter]:
    """Build exporter adapters from configuration."""

    exporters: dict[str, BaseExporter] = {}
    for name, config in settings.exporters.items():
        if not config.get("enabled", True):
            continue
        if name == "json":
            exporters[name] = JsonExporter(Path(config.get("path", "data/export/findings.json")))
        elif name == "csv":
            exporters[name] = CsvExporter(Path(config.get("path", "data/export/findings.csv")))
        elif name in {"webhook", "rest_api"}:
            exporters[name] = WebhookExporter(config["url"], headers=config.get("headers", {}))
        else:
            exporters[name] = StubExporter(name, config)
    for integration in ["misp", "opencti", "splunk", "opensearch", "stix21", "taxii21", "elastic"]:
        exporters.setdefault(integration, StubExporter(integration, settings.exporters.get(integration, {})))
    return exporters
