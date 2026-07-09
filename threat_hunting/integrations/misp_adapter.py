"""MISP adapter (Adapter Pattern)."""

from __future__ import annotations

from typing import Any

try:
    from pymisp import ExpandedPyMISP
except ImportError:  # pragma: no cover - optional dependency in local runtime
    ExpandedPyMISP = None  # type: ignore[assignment]

from threat_hunting.domain.entities import Finding


class MISPAdapter:
    """Adapter that translates Finding entities into MISP payload operations."""

    def __init__(self, *, url: str, api_key: str, verify_ssl: bool = True) -> None:
        self._url = url
        self._api_key = api_key
        self._verify_ssl = verify_ssl
        self._client: ExpandedPyMISP | None = None

    def connect(self) -> None:
        if ExpandedPyMISP is None:
            return
        if not self._url or not self._api_key:
            return
        self._client = ExpandedPyMISP(self._url, self._api_key, self._verify_ssl)

    def export_findings(self, findings: list[Finding], event_id: str | None = None) -> None:
        """Export findings to MISP if client is configured."""
        if self._client is None or not event_id:
            return
        for finding in findings:
            attributes = [
                {"type": "comment", "value": finding.title},
                {"type": "text", "value": finding.description},
            ]
            for indicator in finding.indicators:
                value = indicator.get("value")
                if value:
                    attributes.append({"type": "text", "value": str(value)})
            self._client.add_attribute(event_id, attributes)
