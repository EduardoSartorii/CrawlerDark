"""
MISP Exporter.

Exports high-confidence findings to MISP (Malware Information Sharing Platform).
MISP is the de-facto standard for structured threat intelligence sharing.

Auto-export Rule:
    Findings with score ≥ threshold AND confidence ≥ min_confidence
    are automatically exported if auto_export=True.

MISP Mapping:
    Finding     → MISP Event
    Indicators  → MISP Attributes (with type mapping)
    Tags        → MISP Tags
    TLP         → MISP Distribution level
    Category    → MISP Category

References:
    - MISP Project: https://www.misp-project.org/
    - PyMISP: https://github.com/MISP/PyMISP
"""

from __future__ import annotations

from typing import Any

import structlog

from ...core.domain.entities.finding import Finding
from .base import BaseExporter, ExportResult

logger = structlog.get_logger(__name__)


class MISPExporter(BaseExporter):
    """
    Exports findings to MISP as events.

    Config keys:
        url: str — MISP instance URL
        key: str — MISP API key
        verify_ssl: bool — verify SSL certificate (default: True)
        min_score: float — minimum score for export (default: 7.0)
        min_confidence: float — minimum confidence (default: 0.6)
        distribution: int — MISP distribution level 0-4 (default: 0 = org-only)
        threat_level_id: int — MISP threat level 1-4 (default: 2 = medium)
        analysis: int — MISP analysis state 0-2 (default: 0 = initial)
    """

    exporter_id = "misp"
    name = "MISP Exporter"
    description = "Exports findings to MISP as structured threat events"

    _TLP_TO_DISTRIBUTION = {
        "WHITE": 3,   # All communities
        "GREEN": 2,   # Connected communities
        "AMBER": 1,   # This community only
        "RED": 0,     # Your organisation only
    }

    _CATEGORY_TO_MISP = {
        "malware": "Malware",
        "credential_leak": "Compromised",
        "c2_infrastructure": "Network activity",
        "phishing": "External analysis",
        "brand_abuse": "External analysis",
        "ioc": "Indicators",
        "vulnerability": "Vulnerability",
    }

    async def export(self, findings: list[Finding]) -> ExportResult:
        result = ExportResult(destination="misp")

        try:
            from pymisp import MISPEvent, MISPAttribute, PyMISP
        except ImportError:
            result.errors.append("pymisp not installed. Run: pip install pymisp")
            return result

        url = self._config.get("url")
        key = self._config.get("key")
        if not url or not key:
            result.errors.append("MISP exporter requires 'url' and 'key' in config")
            return result

        min_score = self._config.get("min_score", 7.0)
        min_confidence = self._config.get("min_confidence", 0.6)

        try:
            misp = PyMISP(url, key, self._config.get("verify_ssl", True))
        except Exception as exc:
            result.errors.append(f"MISP connection failed: {exc}")
            return result

        for finding in findings:
            if finding.score.value < min_score:
                continue
            if finding.confidence < min_confidence:
                continue

            try:
                event = self._finding_to_misp_event(finding)
                created = misp.add_event(event, pythonify=True)
                if created:
                    finding.misp_event_id = str(getattr(created, 'id', ''))
                    finding.mark_exported("misp")
                    result.exported_count += 1
                    logger.info(
                        "misp.exported",
                        finding_id=finding.id,
                        misp_event_id=finding.misp_event_id,
                    )
            except Exception as exc:
                result.failed_count += 1
                result.errors.append(f"Finding {finding.id}: {exc}")
                logger.error("misp.export_failed", finding_id=finding.id, error=str(exc))

        return result

    def _finding_to_misp_event(self, finding: Finding) -> Any:
        """Convert a Finding to a PyMISP event."""
        from pymisp import MISPEvent, MISPAttribute

        event = MISPEvent()
        event.info = finding.title[:256]
        event.distribution = self._TLP_TO_DISTRIBUTION.get(finding.tlp, 0)
        event.threat_level_id = self._score_to_threat_level(finding.score.value)
        event.analysis = self._config.get("analysis", 0)

        # Add attributes from source URL
        if finding.source_url:
            attr = MISPAttribute()
            attr.type = "url"
            attr.value = finding.source_url
            attr.category = "External analysis"
            event.add_attribute(**attr.to_dict())

        # Add tags
        for tag in finding.tags[:20]:
            event.add_tag(tag)
        event.add_tag(f"cti-platform:connector={finding.connector}")
        event.add_tag(f"cti-platform:category={finding.category.value}")

        # Add description as comment
        if finding.description:
            attr = MISPAttribute()
            attr.type = "comment"
            attr.value = finding.description[:65535]
            attr.category = "Other"
            event.add_attribute(**attr.to_dict())

        return event

    def _score_to_threat_level(self, score: float) -> int:
        """Map CTI score to MISP threat level (1=High, 2=Medium, 3=Low, 4=Undefined)."""
        if score >= 8.0:
            return 1
        if score >= 5.0:
            return 2
        if score >= 2.0:
            return 3
        return 4

    async def health(self) -> bool:
        try:
            from pymisp import PyMISP
            url = self._config.get("url")
            key = self._config.get("key")
            if not url or not key:
                return False
            misp = PyMISP(url, key, self._config.get("verify_ssl", True))
            return True
        except Exception:
            return False
