"""STIX 2.1 exporter.

Responsibility
--------------
Convert findings into a STIX 2.1 bundle of ``indicator`` SDOs (with STIX
patterns) and one ``report`` SDO per finding linking them. Emitting valid STIX
2.1 JSON by hand keeps the exporter dependency-free while remaining ingestable
by any TAXII 2.1 server / OpenCTI.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from threat_hunting.core.application.ports.exporter import ExportResult
from threat_hunting.core.domain.entities.finding import Finding
from threat_hunting.core.domain.enums import IndicatorType
from threat_hunting.core.domain.value_objects.indicator import Indicator

# Mapping from our indicator types to STIX pattern expressions.
_STIX_PATTERNS: dict[IndicatorType, str] = {
    IndicatorType.IPV4: "[ipv4-addr:value = '{v}']",
    IndicatorType.IPV6: "[ipv6-addr:value = '{v}']",
    IndicatorType.DOMAIN: "[domain-name:value = '{v}']",
    IndicatorType.URL: "[url:value = '{v}']",
    IndicatorType.EMAIL: "[email-addr:value = '{v}']",
    IndicatorType.MD5: "[file:hashes.'MD5' = '{v}']",
    IndicatorType.SHA1: "[file:hashes.'SHA-1' = '{v}']",
    IndicatorType.SHA256: "[file:hashes.'SHA-256' = '{v}']",
}


class StixExporter:
    """Exports findings as a STIX 2.1 bundle."""

    name = "stix"

    def __init__(self, path: str = "exports/findings.stix.json") -> None:
        self._path = Path(path)

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    def _indicator_sdo(self, indicator: Indicator, timestamp: str) -> dict | None:
        pattern_tpl = _STIX_PATTERNS.get(indicator.type)
        if pattern_tpl is None:
            return None
        return {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid4()}",
            "created": timestamp,
            "modified": timestamp,
            "name": indicator.key,
            "pattern": pattern_tpl.format(v=indicator.value),
            "pattern_type": "stix",
            "valid_from": timestamp,
        }

    def _bundle(self, findings: Sequence[Finding]) -> dict:
        timestamp = self._now()
        objects: list[dict] = []
        for finding in findings:
            indicator_ids: list[str] = []
            for indicator in finding.indicators:
                sdo = self._indicator_sdo(indicator, timestamp)
                if sdo is None:
                    continue
                objects.append(sdo)
                indicator_ids.append(sdo["id"])
            objects.append(
                {
                    "type": "report",
                    "spec_version": "2.1",
                    "id": f"report--{uuid4()}",
                    "created": timestamp,
                    "modified": timestamp,
                    "name": finding.title,
                    "description": finding.description,
                    "report_types": ["threat-report"],
                    "published": timestamp,
                    "object_refs": indicator_ids or [f"report--{uuid4()}"],
                    "labels": finding.tags or ["finding"],
                }
            )
        return {"type": "bundle", "id": f"bundle--{uuid4()}", "objects": objects}

    def export(self, findings: Sequence[Finding]) -> ExportResult:
        """Write the STIX 2.1 bundle to disk and return the result."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        bundle = self._bundle(findings)
        self._path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
        return ExportResult(
            exporter=self.name,
            exported=len(findings),
            destination=str(self._path),
            detail=f"{len(bundle['objects'])} STIX objects",
        )
