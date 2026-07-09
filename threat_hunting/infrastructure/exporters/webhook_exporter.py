"""Webhook / REST exporter.

Responsibility
--------------
POST findings as JSON to an HTTP endpoint (Splunk HEC, OpenSearch ingest, a
custom REST API, or a chat webhook). Reuses the OPSEC transport so egress obeys
the same proxy/rate-limit policy as collection. Degrades safely when no
transport is available.
"""

from __future__ import annotations

import json
from collections.abc import Sequence

from threat_hunting.core.application.ports.exporter import ExportResult
from threat_hunting.core.application.ports.transport import Transport
from threat_hunting.core.domain.entities.finding import Finding


class WebhookExporter:
    """Exports findings by POSTing JSON to an HTTP endpoint."""

    name = "webhook"

    def __init__(self, url: str, transport: Transport | None = None) -> None:
        self._url = url
        self._transport = transport

    def export(self, findings: Sequence[Finding]) -> ExportResult:
        """POST the findings as a JSON array and return the result."""
        if self._transport is None:
            return ExportResult(
                exporter=self.name,
                exported=0,
                destination=self._url,
                detail="no transport configured",
            )
        body = json.dumps({"findings": [f.model_dump(mode="json") for f in findings]})
        response = self._transport.request(
            "POST", self._url, content=body, headers={"Content-Type": "application/json"}
        )
        exported = len(findings) if response.ok else 0
        return ExportResult(
            exporter=self.name,
            exported=exported,
            destination=self._url,
            detail=f"status={response.status_code}",
        )
