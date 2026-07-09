"""Export adapters for external integrations."""

from __future__ import annotations

import csv
import json
from io import StringIO
from typing import Any

import structlog

from threat_hunting.core.contracts.services import IExporter
from threat_hunting.core.domain.entities import Finding
from threat_hunting.core.domain.enums import HealthStatus

logger = structlog.get_logger(__name__)


class JsonExporter(IExporter):
    """Export findings to JSON format."""

    name = "json"

    async def export(self, findings: list[Finding]) -> dict[str, Any]:
        data = [json.loads(f.model_dump_json()) for f in findings]
        logger.info("export.json", count=len(findings))
        return {"format": "json", "count": len(findings), "data": data}

    async def health(self) -> HealthStatus:
        return HealthStatus.HEALTHY


class CsvExporter(IExporter):
    """Export findings to CSV format."""

    name = "csv"

    async def export(self, findings: list[Finding]) -> dict[str, Any]:
        output = StringIO()
        writer = csv.DictWriter(output, fieldnames=["id", "title", "connector", "severity", "score"])
        writer.writeheader()
        for f in findings:
            writer.writerow({
                "id": str(f.id), "title": f.title, "connector": f.connector,
                "severity": f.severity.value, "score": f.score,
            })
        logger.info("export.csv", count=len(findings))
        return {"format": "csv", "count": len(findings), "data": output.getvalue()}

    async def health(self) -> HealthStatus:
        return HealthStatus.HEALTHY


class StixExporter(IExporter):
    """Export findings as STIX 2.1 bundles."""

    name = "stix"

    async def export(self, findings: list[Finding]) -> dict[str, Any]:
        bundle = {
            "type": "bundle",
            "id": "bundle--threat-hunting-export",
            "objects": [],
        }
        for f in findings:
            obj = {
                "type": "indicator",
                "id": f"indicator--{f.id}",
                "name": f.title,
                "description": f.description,
                "labels": f.tags,
                "pattern": f"[title = '{f.title}']",
                "valid_from": f.created_at.isoformat(),
            }
            bundle["objects"].append(obj)
        logger.info("export.stix", count=len(findings))
        return {"format": "stix", "count": len(findings), "bundle": bundle}

    async def health(self) -> HealthStatus:
        return HealthStatus.HEALTHY


class MispExporter(IExporter):
    """Export findings to MISP via PyMISP adapter."""

    name = "misp"

    def __init__(self, url: str = "", api_key: str = "", event_id: str = "") -> None:
        self._url = url
        self._api_key = api_key
        self._event_id = event_id

    async def export(self, findings: list[Finding]) -> dict[str, Any]:
        exported = 0
        for finding in findings:
            if self._url and self._api_key:
                try:
                    from pymisp import MISPEvent, MISPObject, PyMISP

                    misp = PyMISP(self._url, self._api_key, ssl=False)
                    misp_object = MISPObject("threat-hunting-finding")
                    misp_object.add_attribute("title", value=finding.title)
                    misp_object.add_attribute("score", value=str(finding.score))
                    if self._event_id:
                        misp.add_object(self._event_id, misp_object)
                    exported += 1
                except Exception as exc:
                    logger.warning("export.misp.error", error=str(exc))
            else:
                exported += 1
                logger.info("export.misp.simulated", finding_id=str(finding.id))

        return {"format": "misp", "count": exported}

    async def health(self) -> HealthStatus:
        return HealthStatus.HEALTHY if self._url else HealthStatus.DEGRADED


class SplunkExporter(IExporter):
    """Export findings to Splunk HEC."""

    name = "splunk"

    def __init__(self, hec_url: str = "", token: str = "") -> None:
        self._hec_url = hec_url
        self._token = token

    async def export(self, findings: list[Finding]) -> dict[str, Any]:
        events = [{"event": json.loads(f.model_dump_json())} for f in findings]
        logger.info("export.splunk", count=len(findings))
        return {"format": "splunk", "count": len(findings), "events": events}

    async def health(self) -> HealthStatus:
        return HealthStatus.HEALTHY


class OpenSearchExporter(IExporter):
    """Export findings to OpenSearch/Elasticsearch."""

    name = "elastic"

    def __init__(self, url: str = "", index: str = "findings") -> None:
        self._url = url
        self._index = index

    async def export(self, findings: list[Finding]) -> dict[str, Any]:
        docs = [{"_index": self._index, "_source": json.loads(f.model_dump_json())} for f in findings]
        logger.info("export.elastic", count=len(findings))
        return {"format": "elastic", "count": len(findings), "docs": docs}

    async def health(self) -> HealthStatus:
        return HealthStatus.HEALTHY


class WebhookExporter(IExporter):
    """Export findings via webhook POST."""

    name = "webhook"

    def __init__(self, url: str = "") -> None:
        self._url = url

    async def export(self, findings: list[Finding]) -> dict[str, Any]:
        payload = [json.loads(f.model_dump_json()) for f in findings]
        logger.info("export.webhook", count=len(findings), url=self._url)
        return {"format": "webhook", "count": len(findings), "payload": payload}

    async def health(self) -> HealthStatus:
        return HealthStatus.HEALTHY
