"""
STIX 2.1 Exporter.

Exports findings as STIX 2.1 bundles — the industry standard format
for threat intelligence sharing (also used for TAXII 2.1).

STIX Mapping:
    Finding         → STIX Indicator + STIX Sighting
    ThreatActor     → STIX Threat Actor
    Indicator (IOC) → STIX Indicator
    Relationship    → STIX Relationship

References:
    - OASIS STIX 2.1 spec: https://docs.oasis-open.org/cti/stix/v2.1/
"""

from __future__ import annotations

import json
import uuid
from datetime import timezone
from pathlib import Path
from typing import Any

import structlog

from ...core.domain.entities.finding import Finding
from .base import BaseExporter, ExportResult

logger = structlog.get_logger(__name__)


class STIX21Exporter(BaseExporter):
    """
    Exports findings as STIX 2.1 JSON bundles.

    Config keys:
        output_path: str — output file path
        identity_name: str — creator identity name (default: "Threat Hunting Platform")
        identity_id: str — STIX identity UUID
    """

    exporter_id = "stix"
    name = "STIX 2.1 Exporter"
    description = "Exports findings as STIX 2.1 bundles"

    _IDENTITY_TYPE = "identity"
    _INDICATOR_TYPE = "indicator"
    _SIGHTING_TYPE = "sighting"
    _BUNDLE_TYPE = "bundle"

    async def export(self, findings: list[Finding]) -> ExportResult:
        result = ExportResult(destination="stix")
        identity_name = self._config.get("identity_name", "Threat Hunting Platform")
        identity_id = self._config.get("identity_id", f"identity--{uuid.uuid4()}")
        output_path = self._config.get("output_path")

        try:
            objects: list[dict[str, Any]] = [
                self._build_identity(identity_id, identity_name)
            ]

            for finding in findings:
                stix_objects = self._finding_to_stix(finding, identity_id)
                objects.extend(stix_objects)

            bundle = {
                "type": self._BUNDLE_TYPE,
                "id": f"bundle--{uuid.uuid4()}",
                "spec_version": "2.1",
                "objects": objects,
            }

            json_str = json.dumps(bundle, indent=2, default=str)

            if output_path:
                path = Path(output_path)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json_str, encoding="utf-8")
                logger.info("stix.exported", path=str(path), count=len(findings))
            else:
                print(json_str)

            result.exported_count = len(findings)
        except Exception as exc:
            result.errors.append(str(exc))
            logger.error("stix.export_failed", error=str(exc))

        return result

    def _build_identity(self, identity_id: str, name: str) -> dict[str, Any]:
        from datetime import datetime
        return {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "name": name,
            "identity_class": "system",
            "created": datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "modified": datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        }

    def _finding_to_stix(
        self,
        finding: Finding,
        identity_id: str,
    ) -> list[dict[str, Any]]:
        """Convert a Finding to STIX 2.1 Indicator + Sighting objects."""
        objects = []
        created = finding.created_at.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        modified = finding.updated_at.strftime("%Y-%m-%dT%H:%M:%S.000Z")

        # STIX Indicator
        indicator_id = f"indicator--{uuid.uuid4()}"
        indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created_by_ref": identity_id,
            "created": created,
            "modified": modified,
            "name": finding.title[:256],
            "description": finding.description[:2048] if finding.description else "",
            "indicator_types": [self._map_category(finding.category.value)],
            "pattern": f"[domain-name:value = '{finding.source}']",
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": created,
            "confidence": int(finding.confidence * 100),
            "labels": finding.tags[:10],
            "external_references": self._build_refs(finding),
            "object_marking_refs": [self._tlp_to_marking(finding.tlp)],
        }
        objects.append(indicator)

        # STIX Sighting (when/where it was observed)
        sighting = {
            "type": "sighting",
            "spec_version": "2.1",
            "id": f"sighting--{uuid.uuid4()}",
            "created": created,
            "modified": modified,
            "created_by_ref": identity_id,
            "sighting_of_ref": indicator_id,
            "count": 1,
            "first_seen": created,
            "last_seen": modified,
        }
        objects.append(sighting)

        return objects

    def _map_category(self, category: str) -> str:
        mapping = {
            "malware": "malicious-activity",
            "phishing": "malicious-activity",
            "c2_infrastructure": "compromised",
            "credential_leak": "compromised",
            "ioc": "malicious-activity",
        }
        return mapping.get(category, "unknown")

    def _build_refs(self, finding: Finding) -> list[dict[str, Any]]:
        refs = []
        if finding.source_url:
            refs.append({"source_name": finding.source, "url": finding.source_url})
        return refs

    def _tlp_to_marking(self, tlp: str) -> str:
        markings = {
            "WHITE": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
            "GREEN": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
            "AMBER": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
            "RED": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
        }
        return markings.get(tlp, markings["WHITE"])

    async def health(self) -> bool:
        return True
