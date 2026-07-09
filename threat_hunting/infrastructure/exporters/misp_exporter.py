"""MISP exporter.

Responsibility
--------------
Push findings to a MISP instance as events with attributes derived from the
finding's indicators. ``PyMISP`` is an optional dependency: when it is missing
(or no URL/key is configured), the exporter operates in a *dry-run* mode that
builds the event payload and reports what it *would* send, so the pipeline and
the "auto-export on threshold" path remain fully testable offline.

This exporter is the target of :class:`AutoExportSubscriber`, wiring the
"score > threshold ⇒ enviar para o MISP" requirement.
"""

from __future__ import annotations

from collections.abc import Sequence

from threat_hunting.core.application.ports.exporter import ExportResult
from threat_hunting.core.domain.entities.finding import Finding
from threat_hunting.core.domain.enums import IndicatorType

# Map our indicator types to MISP attribute types.
_MISP_TYPES: dict[IndicatorType, str] = {
    IndicatorType.IPV4: "ip-dst",
    IndicatorType.DOMAIN: "domain",
    IndicatorType.URL: "url",
    IndicatorType.EMAIL: "email-src",
    IndicatorType.MD5: "md5",
    IndicatorType.SHA1: "sha1",
    IndicatorType.SHA256: "sha256",
    IndicatorType.BTC_WALLET: "btc",
    IndicatorType.CVE: "vulnerability",
}


class MispExporter:
    """Exports findings to MISP (real when PyMISP+config present, else dry-run)."""

    name = "misp"

    def __init__(self, url: str | None = None, key: str | None = None, *, verify_tls: bool = True) -> None:
        self._url = url
        self._key = key
        self._verify_tls = verify_tls
        self._client = self._build_client()
        self.dry_run_events: list[dict] = []

    def _build_client(self) -> object | None:
        """Create a PyMISP client if the library and credentials are available."""
        if not (self._url and self._key):
            return None
        try:
            from pymisp import PyMISP  # optional dependency
        except ImportError:
            return None
        try:
            return PyMISP(self._url, self._key, self._verify_tls)
        except Exception:
            return None

    def _event_payload(self, finding: Finding) -> dict:
        """Build a MISP-event-shaped payload from a finding."""
        attributes = []
        for indicator in finding.indicators:
            misp_type = _MISP_TYPES.get(indicator.type)
            if misp_type is None:
                continue
            attributes.append({"type": misp_type, "value": indicator.value})
        return {
            "info": finding.title,
            "analysis": 0,
            "threat_level_id": max(1, 4 - finding.severity.weight),
            "tags": finding.tags,
            "attributes": attributes,
        }

    def export(self, findings: Sequence[Finding]) -> ExportResult:
        """Send findings to MISP, or record dry-run payloads when offline."""
        sent = 0
        for finding in findings:
            payload = self._event_payload(finding)
            if self._client is None:
                self.dry_run_events.append(payload)
                continue
            try:
                from pymisp import MISPEvent

                event = MISPEvent()
                event.info = payload["info"]
                for attr in payload["attributes"]:
                    event.add_attribute(attr["type"], attr["value"])
                self._client.add_event(event)  # type: ignore[attr-defined]
                sent += 1
            except Exception:
                self.dry_run_events.append(payload)
        mode = "live" if self._client is not None else "dry-run"
        return ExportResult(
            exporter=self.name,
            exported=sent if self._client is not None else len(findings),
            destination=self._url or "dry-run",
            detail=f"mode={mode}",
        )
