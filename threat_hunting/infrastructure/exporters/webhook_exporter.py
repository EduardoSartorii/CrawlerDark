"""
WebhookExporter
===============

Posts Finding data as JSON to a configured HTTP webhook endpoint.
Supports HMAC-SHA256 request signing for security.

Use cases:
    - Slack/Teams notifications
    - Custom SIEM integrations
    - PagerDuty/OpsGenie alerts
    - Custom downstream pipelines
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import TYPE_CHECKING

import httpx
import structlog

from threat_hunting.core.domain.exceptions.domain_exceptions import ExportError
from threat_hunting.infrastructure.exporters.base import BaseExporter

if TYPE_CHECKING:
    from threat_hunting.core.domain.entities.finding import Finding

logger = structlog.get_logger(__name__)


class WebhookExporter(BaseExporter):
    """Posts Finding JSON payloads to a webhook URL."""

    exporter_id = "webhook"
    exporter_name = "Webhook Exporter"

    def __init__(self, url: str, secret: str = "", timeout: int = 10) -> None:
        super().__init__()
        self._url = url
        self._secret = secret
        self._timeout = timeout

    async def export(self, finding: "Finding") -> bool:
        """POST the Finding to the webhook URL."""
        if not self._url:
            return False

        payload = json.dumps(self._finding_to_dict(finding), default=str)
        headers = {
            "Content-Type": "application/json",
            "X-ThreatHunting-Event": "finding",
            "X-ThreatHunting-Severity": finding.severity.value,
            "X-ThreatHunting-Score": str(finding.score.value),
        }

        if self._secret:
            timestamp = str(int(time.time()))
            sig = hmac.new(
                self._secret.encode(),
                f"{timestamp}.{payload}".encode(),
                hashlib.sha256,
            ).hexdigest()
            headers["X-ThreatHunting-Timestamp"] = timestamp
            headers["X-ThreatHunting-Signature"] = f"sha256={sig}"

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.post(self._url, content=payload, headers=headers)
                if response.is_success:
                    self._logger.info("webhook_sent", finding_id=finding.id, status=response.status_code)
                    return True
                self._logger.warning("webhook_non_2xx", status=response.status_code, body=response.text[:256])
                return False
        except Exception as exc:
            self._logger.error("webhook_failed", error=str(exc))
            raise ExportError(f"Webhook export failed: {exc}") from exc

    async def health(self) -> bool:
        """Verify the webhook URL is reachable (HEAD request)."""
        if not self._url:
            return False
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.head(self._url)
                return response.status_code < 500
        except Exception:
            return False
