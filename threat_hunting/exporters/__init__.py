"""Exporters — independent adapters (Strategy + Factory).

Responsibility
--------------
Export Findings to MISP, OpenCTI, Splunk, OpenSearch, Webhook, REST,
JSON, CSV, STIX 2.1 and TAXII 2.1 without coupling to Core business rules.
Auto-MISP export is triggered by ScoreThresholdExceeded event handler.
"""

from __future__ import annotations

import csv
import io
import json
from abc import ABC
from pathlib import Path
from typing import Any, Sequence

import structlog

from threat_hunting.core.application.ports import ExporterFactoryPort, ExporterPort
from threat_hunting.core.domain.entities import Finding
from threat_hunting.core.domain.enums import ExportFormat, HealthState
from threat_hunting.core.domain.events import DomainEvent, ExportCompleted, ScoreThresholdExceeded
from threat_hunting.core.domain.value_objects import HealthStatus, utc_now

logger = structlog.get_logger(__name__)


class BaseExporter(ExporterPort, ABC):
    format: ExportFormat

    async def health(self) -> HealthStatus:
        return HealthStatus(
            component=f"exporter:{self.format.value}",
            state=HealthState.HEALTHY.value,
            message="ready",
            checked_at=utc_now(),
        )


class JsonExporter(BaseExporter):
    format = ExportFormat.JSON

    async def export(self, findings: Sequence[Finding], **options: Any) -> dict[str, Any]:
        path = Path(options.get("path", "exports/findings.json"))
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = [f.to_export_dict() for f in findings]
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        logger.info("export.json", path=str(path), count=len(payload))
        return {"format": "json", "path": str(path), "count": len(payload)}


class CsvExporter(BaseExporter):
    format = ExportFormat.CSV

    async def export(self, findings: Sequence[Finding], **options: Any) -> dict[str, Any]:
        path = Path(options.get("path", "exports/findings.csv"))
        path.parent.mkdir(parents=True, exist_ok=True)
        fields = [
            "id", "title", "source", "connector", "category", "severity",
            "score", "confidence", "created_at", "tags", "indicators",
        ]
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=fields)
        writer.writeheader()
        for f in findings:
            d = f.to_export_dict()
            writer.writerow(
                {
                    "id": d["id"],
                    "title": d["title"],
                    "source": d["source"],
                    "connector": d["connector"],
                    "category": d["category"],
                    "severity": d["severity"],
                    "score": d["score"],
                    "confidence": d["confidence"],
                    "created_at": d["created_at"],
                    "tags": "|".join(d["tags"]),
                    "indicators": "|".join(
                        f"{i['type']}:{i['value']}" for i in d["indicators"]
                    ),
                }
            )
        path.write_text(buf.getvalue(), encoding="utf-8")
        return {"format": "csv", "path": str(path), "count": len(findings)}


class Stix21Exporter(BaseExporter):
    format = ExportFormat.STIX21

    async def export(self, findings: Sequence[Finding], **options: Any) -> dict[str, Any]:
        path = Path(options.get("path", "exports/findings.stix.json"))
        path.parent.mkdir(parents=True, exist_ok=True)
        objects: list[dict[str, Any]] = []
        for f in findings:
            indicator_objs = []
            for ind in f.indicators:
                indicator_objs.append(
                    {
                        "type": "indicator",
                        "spec_version": "2.1",
                        "id": f"indicator--{f.id.value[:8]}-{abs(hash(ind.value)) % 10**8}",
                        "created": f.created_at.isoformat(),
                        "modified": f.updated_at.isoformat(),
                        "name": f"{ind.type.value}:{ind.value}",
                        "pattern": f"[{ind.type.value}:value = '{ind.value}']",
                        "pattern_type": "stix",
                        "valid_from": f.created_at.isoformat(),
                    }
                )
            objects.append(
                {
                    "type": "bundle",
                    "id": f"bundle--{f.id.value}",
                    "objects": [
                        {
                            "type": "report",
                            "spec_version": "2.1",
                            "id": f"report--{f.id.value}",
                            "created": f.created_at.isoformat(),
                            "modified": f.updated_at.isoformat(),
                            "name": f.title,
                            "description": f.description,
                            "published": f.created_at.isoformat(),
                            "object_refs": [o["id"] for o in indicator_objs],
                            "labels": [t.name for t in f.tags],
                            "confidence": int(float(f.confidence) * 100),
                        },
                        *indicator_objs,
                    ],
                }
            )
        path.write_text(json.dumps(objects, indent=2), encoding="utf-8")
        return {"format": "stix21", "path": str(path), "count": len(findings)}


class MispExporter(BaseExporter):
    """MISP exporter — uses PyMISP when configured; otherwise writes MISP-like JSON."""

    format = ExportFormat.MISP

    def __init__(self, *, url: str | None = None, key: str | None = None) -> None:
        self._url = url
        self._key = key

    async def export(self, findings: Sequence[Finding], **options: Any) -> dict[str, Any]:
        url = options.get("url") or self._url
        key = options.get("key") or self._key
        event_id = options.get("event_id")

        if url and key:
            try:
                return await self._export_live(findings, url=url, key=key, event_id=event_id)
            except Exception as exc:
                logger.warning("export.misp_live_failed", error=str(exc))

        # Offline MISP-compatible JSON
        path = Path(options.get("path", "exports/misp_events.json"))
        path.parent.mkdir(parents=True, exist_ok=True)
        events = []
        for f in findings:
            attrs = [
                {
                    "type": self._misp_type(i.type.value),
                    "value": i.value,
                    "category": "External analysis",
                    "to_ids": True,
                    "comment": i.context or f.title,
                }
                for i in f.indicators
            ]
            events.append(
                {
                    "Event": {
                        "info": f.title,
                        "threat_level_id": self._threat_level(float(f.score)),
                        "analysis": "1",
                        "distribution": "0",
                        "Attribute": attrs,
                        "Tag": [{"name": t.name} for t in f.tags],
                        "date": f.created_at.date().isoformat(),
                    }
                }
            )
        path.write_text(json.dumps(events, indent=2), encoding="utf-8")
        logger.info("export.misp_offline", path=str(path), count=len(events))
        return {"format": "misp", "mode": "offline", "path": str(path), "count": len(events)}

    async def _export_live(
        self,
        findings: Sequence[Finding],
        *,
        url: str,
        key: str,
        event_id: Any,
    ) -> dict[str, Any]:
        from pymisp import PyMISP

        misp = PyMISP(url, key, ssl=False)
        created = 0
        for f in findings:
            if event_id:
                for ind in f.indicators:
                    misp.add_attribute(
                        event_id,
                        {
                            "type": self._misp_type(ind.type.value),
                            "value": ind.value,
                            "category": "External analysis",
                        },
                    )
            else:
                event = misp.new_event(
                    info=f.title,
                    distribution=0,
                    threat_level_id=self._threat_level(float(f.score)),
                    analysis=1,
                )
                eid = event["Event"]["id"] if isinstance(event, dict) else getattr(event, "id", None)
                for ind in f.indicators:
                    misp.add_attribute(
                        eid,
                        {
                            "type": self._misp_type(ind.type.value),
                            "value": ind.value,
                            "category": "External analysis",
                        },
                    )
            created += 1
        return {"format": "misp", "mode": "live", "count": created}

    @staticmethod
    def _misp_type(itype: str) -> str:
        mapping = {
            "ip": "ip-dst",
            "domain": "domain",
            "url": "url",
            "email": "email-src",
            "hash_md5": "md5",
            "hash_sha1": "sha1",
            "hash_sha256": "sha256",
            "cve": "vulnerability",
            "filename": "filename",
        }
        return mapping.get(itype, "text")

    @staticmethod
    def _threat_level(score: float) -> int:
        if score >= 80:
            return 1
        if score >= 50:
            return 2
        if score >= 20:
            return 3
        return 4


class WebhookExporter(BaseExporter):
    format = ExportFormat.WEBHOOK

    async def export(self, findings: Sequence[Finding], **options: Any) -> dict[str, Any]:
        url = options.get("url")
        payload = [f.to_export_dict() for f in findings]
        if not url:
            path = Path(options.get("path", "exports/webhook_payload.json"))
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            return {"format": "webhook", "mode": "offline", "path": str(path), "count": len(payload)}
        import httpx

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
        return {"format": "webhook", "mode": "live", "status": resp.status_code, "count": len(payload)}


class SplunkExporter(BaseExporter):
    format = ExportFormat.SPLUNK

    async def export(self, findings: Sequence[Finding], **options: Any) -> dict[str, Any]:
        path = Path(options.get("path", "exports/splunk_hec.jsonl"))
        path.parent.mkdir(parents=True, exist_ok=True)
        lines = []
        for f in findings:
            lines.append(
                json.dumps(
                    {
                        "event": f.to_export_dict(),
                        "sourcetype": "threat_hunting:finding",
                        "source": f.connector,
                        "time": f.created_at.timestamp(),
                    }
                )
            )
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return {"format": "splunk", "path": str(path), "count": len(findings)}


class OpenSearchExporter(BaseExporter):
    format = ExportFormat.OPENSEARCH

    async def export(self, findings: Sequence[Finding], **options: Any) -> dict[str, Any]:
        path = Path(options.get("path", "exports/opensearch_bulk.ndjson"))
        path.parent.mkdir(parents=True, exist_ok=True)
        index = options.get("index", "threat-hunting-findings")
        lines: list[str] = []
        for f in findings:
            lines.append(json.dumps({"index": {"_index": index, "_id": str(f.id)}}))
            lines.append(json.dumps(f.to_export_dict()))
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return {"format": "opensearch", "path": str(path), "count": len(findings)}


class RestApiExporter(BaseExporter):
    format = ExportFormat.REST_API

    async def export(self, findings: Sequence[Finding], **options: Any) -> dict[str, Any]:
        # Same offline-first pattern as webhook
        return await WebhookExporter().export(findings, **options)


class OpenCtiExporter(BaseExporter):
    format = ExportFormat.OPENCTI

    async def export(self, findings: Sequence[Finding], **options: Any) -> dict[str, Any]:
        path = Path(options.get("path", "exports/opencti_bundle.json"))
        path.parent.mkdir(parents=True, exist_ok=True)
        # Reuse STIX 2.1 as OpenCTI-compatible
        result = await Stix21Exporter().export(findings, path=str(path))
        result["format"] = "opencti"
        return result


class Taxii21Exporter(BaseExporter):
    format = ExportFormat.TAXII21

    async def export(self, findings: Sequence[Finding], **options: Any) -> dict[str, Any]:
        path = Path(options.get("path", "exports/taxii_collection.json"))
        path.parent.mkdir(parents=True, exist_ok=True)
        stix = await Stix21Exporter().export(findings, path=str(path))
        return {"format": "taxii21", "path": stix["path"], "count": stix["count"], "note": "STIX bundle ready for TAXII push"}


EXPORTER_CLASSES: dict[str, type[BaseExporter]] = {
    ExportFormat.JSON.value: JsonExporter,
    ExportFormat.CSV.value: CsvExporter,
    ExportFormat.STIX21.value: Stix21Exporter,
    ExportFormat.MISP.value: MispExporter,
    ExportFormat.WEBHOOK.value: WebhookExporter,
    ExportFormat.SPLUNK.value: SplunkExporter,
    ExportFormat.OPENSEARCH.value: OpenSearchExporter,
    ExportFormat.REST_API.value: RestApiExporter,
    ExportFormat.OPENCTI.value: OpenCtiExporter,
    ExportFormat.TAXII21.value: Taxii21Exporter,
}


class ExporterFactory(ExporterFactoryPort):
    def __init__(self, *, misp_url: str | None = None, misp_key: str | None = None) -> None:
        self._misp_url = misp_url
        self._misp_key = misp_key

    def create(self, format_name: str) -> ExporterPort:
        key = format_name.lower().replace("-", "").replace("_", "")
        # normalize aliases
        aliases = {
            "stix": "stix21",
            "stix2": "stix21",
            "stix21": "stix21",
            "taxii": "taxii21",
            "taxii21": "taxii21",
            "rest": "rest_api",
            "restapi": "rest_api",
            "elastic": "opensearch",
            "elasticsearch": "opensearch",
        }
        normalized = aliases.get(key, format_name.lower())
        cls = EXPORTER_CLASSES.get(normalized)
        if cls is None:
            raise KeyError(f"Unknown exporter: {format_name}. Available: {self.list_available()}")
        if cls is MispExporter:
            return MispExporter(url=self._misp_url, key=self._misp_key)
        return cls()

    def list_available(self) -> Sequence[str]:
        return sorted(EXPORTER_CLASSES.keys())


class AutoMispExportHandler:
    """Observer — on ScoreThresholdExceeded, auto-export to MISP."""

    def __init__(self, exporter_factory: ExporterFactoryPort, event_bus: Any | None = None) -> None:
        self._factory = exporter_factory
        self._event_bus = event_bus

    async def handle(self, event: DomainEvent) -> None:
        if not isinstance(event, ScoreThresholdExceeded) and event.event_type != "ScoreThresholdExceeded":
            return
        finding_data = event.payload.get("finding")
        if not finding_data:
            return
        # Reconstruct minimal Finding for export
        from threat_hunting.core.domain.services import FindingBuilder
        from threat_hunting.core.domain.enums import FindingCategory, Severity

        finding = (
            FindingBuilder()
            .with_title(finding_data.get("title", "auto-export"))
            .with_description(finding_data.get("description", ""))
            .with_source(finding_data.get("source", "auto"))
            .with_connector(finding_data.get("connector", "auto"))
            .with_category(FindingCategory(finding_data.get("category", "other")))
            .with_severity(Severity(finding_data.get("severity", "informational")))
            .with_score(float(finding_data.get("score", 0)))
            .build()
        )
        exporter = self._factory.create("misp")
        result = await exporter.export([finding])
        logger.info("export.auto_misp", result=result, finding_id=event.aggregate_id)
        if self._event_bus is not None:
            await self._event_bus.publish(
                ExportCompleted(
                    aggregate_id=event.aggregate_id,
                    payload={"format": "misp", "result": result},
                )
            )


__all__ = [
    "ExporterFactory",
    "JsonExporter",
    "CsvExporter",
    "Stix21Exporter",
    "MispExporter",
    "AutoMispExportHandler",
    "EXPORTER_CLASSES",
]
