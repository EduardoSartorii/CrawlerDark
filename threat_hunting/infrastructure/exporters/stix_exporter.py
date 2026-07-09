"""STIX 2.1 exporter.

Responsibility
--------------
Serialise findings into a STIX 2.1 bundle so intelligence can be shared with any
TAXII 2.1 server or STIX-aware platform (OpenCTI, MISP, sharing communities).
Each finding becomes an ``indicator`` SDO per IOC plus a ``report`` SDO that
references them, with confidence derived from the finding score. The bundle is
built as plain dictionaries (no heavy ``stix2`` dependency) but follows the
STIX 2.1 object shapes.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path

from threat_hunting.core.application.ports.exporter import ExporterPort
from threat_hunting.core.domain.entities import Finding, Indicator
from threat_hunting.core.domain.enums import IndicatorType

# Maps indicator types to STIX pattern object-paths.
_STIX_PATH = {
    IndicatorType.IPV4: "ipv4-addr:value",
    IndicatorType.IPV6: "ipv6-addr:value",
    IndicatorType.DOMAIN: "domain-name:value",
    IndicatorType.URL: "url:value",
    IndicatorType.EMAIL: "email-addr:value",
    IndicatorType.MD5: "file:hashes.MD5",
    IndicatorType.SHA1: "file:hashes.'SHA-1'",
    IndicatorType.SHA256: "file:hashes.'SHA-256'",
}


def _stix_id(kind: str) -> str:
    """Build a STIX identifier (``<type>--<uuid4>``)."""
    return f"{kind}--{uuid.uuid4()}"


def _now() -> str:
    """STIX timestamp in the required RFC3339/UTC format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class StixExporter(ExporterPort):
    """Exports findings as a STIX 2.1 bundle file."""

    name = "stix"

    def __init__(self, output_dir: str | Path = "exports") -> None:
        self._dir = Path(output_dir)

    def supports_auto_export(self) -> bool:
        return False

    def export(self, findings: Sequence[Finding]) -> int:
        objects: list[dict] = []
        for finding in findings:
            objects.extend(self._finding_to_stix(finding))
        bundle = {
            "type": "bundle",
            "id": _stix_id("bundle"),
            "objects": objects,
        }
        self._dir.mkdir(parents=True, exist_ok=True)
        (self._dir / "findings.stix.json").write_text(
            json.dumps(bundle, indent=2), encoding="utf-8"
        )
        return len(findings)

    def _finding_to_stix(self, finding: Finding) -> list[dict]:
        """Convert one finding into indicator SDOs + a report SDO."""
        objects: list[dict] = []
        indicator_refs: list[str] = []
        now = _now()
        for indicator in finding.indicators:
            sdo = self._indicator_to_stix(indicator, finding, now)
            if sdo is not None:
                objects.append(sdo)
                indicator_refs.append(sdo["id"])
        objects.append(
            {
                "type": "report",
                "spec_version": "2.1",
                "id": _stix_id("report"),
                "created": now,
                "modified": now,
                "name": finding.title,
                "description": finding.description[:1000],
                "report_types": ["threat-report"],
                "confidence": int(min(100, max(0, finding.score))),
                "labels": finding.tags or ["osint"],
                "object_refs": indicator_refs or [_stix_id("indicator")],
            }
        )
        return objects

    @staticmethod
    def _indicator_to_stix(
        indicator: Indicator, finding: Finding, now: str
    ) -> dict | None:
        """Convert one indicator into a STIX indicator SDO (if patternable)."""
        path = _STIX_PATH.get(indicator.type)
        if path is None:
            return None
        return {
            "type": "indicator",
            "spec_version": "2.1",
            "id": _stix_id("indicator"),
            "created": now,
            "modified": now,
            "name": f"{indicator.type.value}: {indicator.value}",
            "pattern": f"[{path} = '{indicator.value}']",
            "pattern_type": "stix",
            "valid_from": now,
            "confidence": int(min(100, max(0, finding.score))),
            "labels": ["malicious-activity"],
        }
