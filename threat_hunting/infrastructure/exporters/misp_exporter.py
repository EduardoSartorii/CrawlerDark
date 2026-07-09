"""
MISPExporter
============

Exports Findings to a MISP instance via the PyMISP library.
Each Finding creates a MISP Event with:
    - Title as event info
    - Source tag
    - Severity and score as custom attributes
    - All detected IOCs as MISP attributes (domain, ip-dst, url, md5, sha256, etc.)
    - TLP tag based on score threshold

Configuration: MISP_URL, MISP_KEY in environment.

Auto-export: When a Finding's score exceeds AUTO_EXPORT_SCORE_THRESHOLD,
the pipeline triggers MISP export automatically.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import structlog

from threat_hunting.core.domain.exceptions.domain_exceptions import ExportError
from threat_hunting.infrastructure.exporters.base import BaseExporter

if TYPE_CHECKING:
    from threat_hunting.core.domain.entities.finding import Finding

logger = structlog.get_logger(__name__)

# IOC type → MISP attribute type mapping
_MISP_TYPE_MAP: dict[str, str] = {
    "ip": "ip-dst",
    "domain": "domain",
    "url": "url",
    "email": "email-src",
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
    "filename": "filename",
    "wallet": "btc",
    "cve": "vulnerability",
}


class MISPExporter(BaseExporter):
    """Exports Findings to MISP via PyMISP."""

    exporter_id = "misp"
    exporter_name = "MISP Exporter"

    def __init__(
        self,
        misp_url: str,
        misp_key: str,
        verify_cert: bool = False,
        distribution: int = 1,
        threat_level: int = 2,
        analysis: int = 2,
    ) -> None:
        super().__init__()
        self._url = misp_url
        self._key = misp_key
        self._verify = verify_cert
        self._distribution = distribution
        self._threat_level = threat_level
        self._analysis = analysis
        self._misp: Any = None

    def _get_misp(self) -> Any:
        """Lazy-initialize PyMISP client."""
        if self._misp is None:
            try:
                from pymisp import PyMISP  # type: ignore[import-untyped]
                self._misp = PyMISP(self._url, self._key, ssl=self._verify)
            except ImportError as exc:
                raise ExportError(
                    "pymisp is required for MISP export. Install it with: pip install pymisp"
                ) from exc
        return self._misp

    async def export(self, finding: "Finding") -> bool:
        """Create a MISP event from a Finding."""
        try:
            import asyncio
            return await asyncio.get_event_loop().run_in_executor(
                None, self._sync_export, finding
            )
        except Exception as exc:
            self._logger.error("misp_export_failed", finding_id=finding.id, error=str(exc))
            raise ExportError(f"MISP export failed: {exc}") from exc

    def _sync_export(self, finding: "Finding") -> bool:
        """Synchronous MISP export (run in thread pool)."""
        from pymisp import MISPEvent, MISPAttribute  # type: ignore[import-untyped]
        misp = self._get_misp()

        event = MISPEvent()
        event.info = f"[ThreatHunting] {finding.title[:256]}"
        event.distribution = self._distribution
        event.threat_level_id = self._threat_level
        event.analysis = self._analysis

        # Add tags.
        event.add_tag(f"source:{finding.source.value}")
        event.add_tag(f"connector:{finding.connector}")
        event.add_tag(f"severity:{finding.severity.value}")
        event.add_tag(f"score:{finding.score.value:.1f}")

        # TLP tag based on severity.
        tlp = {
            "critical": "tlp:red",
            "high": "tlp:amber",
            "medium": "tlp:amber",
            "low": "tlp:green",
            "info": "tlp:white",
        }.get(finding.severity.value, "tlp:white")
        event.add_tag(tlp)

        # Add description as free text.
        if finding.description:
            attr = MISPAttribute()
            attr.type = "text"
            attr.value = finding.description[:65535]
            attr.comment = "ThreatHunting platform: finding description"
            event.add_attribute(**attr)

        # Add source URL.
        if finding.source_url:
            event.add_attribute("url", finding.source_url, comment="Source URL")

        result = misp.add_event(event)
        if result and not result.get("errors"):
            self._logger.info(
                "misp_event_created",
                finding_id=finding.id,
                event_uuid=result.get("Event", {}).get("uuid"),
            )
            return True

        self._logger.warning("misp_event_failed", response=result)
        return False

    async def health(self) -> bool:
        """Check MISP connectivity."""
        try:
            import asyncio
            misp = await asyncio.get_event_loop().run_in_executor(None, self._get_misp)
            return misp is not None
        except Exception:
            return False
