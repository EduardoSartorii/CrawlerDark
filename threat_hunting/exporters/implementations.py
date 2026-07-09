"""Exporter adapters for MISP/OpenCTI/Splunk/OpenSearch/Webhook/REST/JSON/CSV/STIX/TAXII."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from threat_hunting.core.contracts import ExporterPort, StageContext
from threat_hunting.domain.entities import Finding
from threat_hunting.integrations.misp_adapter import MISPAdapter
from threat_hunting.integrations.opencti_adapter import OpenCTIAdapter


class JsonExporter(ExporterPort):
    """Export findings to local JSON file."""

    name = "json"

    def __init__(self, output_file: str = "artifacts/findings.json") -> None:
        self._output_file = Path(output_file)
        self._output_file.parent.mkdir(parents=True, exist_ok=True)

    def export(self, findings: list[Finding], context: StageContext) -> None:
        payload = [finding.model_dump(mode="json") for finding in findings]
        with self._output_file.open("w", encoding="utf-8") as handler:
            json.dump(payload, handler, ensure_ascii=False, indent=2)


class CsvExporter(ExporterPort):
    """Export findings to CSV."""

    name = "csv"

    def __init__(self, output_file: str = "artifacts/findings.csv") -> None:
        self._output_file = Path(output_file)
        self._output_file.parent.mkdir(parents=True, exist_ok=True)

    def export(self, findings: list[Finding], context: StageContext) -> None:
        with self._output_file.open("w", encoding="utf-8", newline="") as handler:
            writer = csv.DictWriter(
                handler,
                fieldnames=[
                    "id",
                    "title",
                    "source",
                    "connector",
                    "category",
                    "severity",
                    "score",
                    "confidence",
                ],
            )
            writer.writeheader()
            for finding in findings:
                writer.writerow(
                    {
                        "id": finding.id,
                        "title": finding.title,
                        "source": finding.source,
                        "connector": finding.connector,
                        "category": finding.category,
                        "severity": finding.severity.value,
                        "score": finding.score,
                        "confidence": finding.confidence,
                    }
                )


class MISPExporter(ExporterPort):
    """Export findings to MISP via adapter."""

    name = "misp"

    def __init__(self, adapter: MISPAdapter, event_id: str | None = None) -> None:
        self._adapter = adapter
        self._event_id = event_id
        self._adapter.connect()

    def export(self, findings: list[Finding], context: StageContext) -> None:
        self._adapter.export_findings(findings, event_id=self._event_id)


class OpenCTIExporter(ExporterPort):
    """Export findings to OpenCTI."""

    name = "opencti"

    def __init__(self, adapter: OpenCTIAdapter) -> None:
        self._adapter = adapter

    def export(self, findings: list[Finding], context: StageContext) -> None:
        self._adapter.export_findings(findings)


class SplunkExporter(ExporterPort):
    """Splunk exporter placeholder."""

    name = "splunk"

    def export(self, findings: list[Finding], context: StageContext) -> None:
        return


class OpenSearchExporter(ExporterPort):
    """OpenSearch exporter placeholder."""

    name = "opensearch"

    def export(self, findings: list[Finding], context: StageContext) -> None:
        return


class WebhookExporter(ExporterPort):
    """Webhook exporter placeholder."""

    name = "webhook"

    def export(self, findings: list[Finding], context: StageContext) -> None:
        return


class RestAPIExporter(ExporterPort):
    """REST API exporter placeholder."""

    name = "rest_api"

    def export(self, findings: list[Finding], context: StageContext) -> None:
        return


class STIX21Exporter(ExporterPort):
    """STIX 2.1 exporter placeholder."""

    name = "stix21"

    def export(self, findings: list[Finding], context: StageContext) -> None:
        return


class TAXII21Exporter(ExporterPort):
    """TAXII 2.1 exporter placeholder."""

    name = "taxii21"

    def export(self, findings: list[Finding], context: StageContext) -> None:
        return
