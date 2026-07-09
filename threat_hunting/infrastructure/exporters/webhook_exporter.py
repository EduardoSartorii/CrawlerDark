"""WebhookExporter — POST JSON com HMAC-SHA256 opcional."""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Sequence

import httpx

from ...core.application.dto import FindingDTO
from ...core.domain.entities import Finding


class WebhookExporter:
    name = "webhook"

    def __init__(self, url: str, *, hmac_secret: str | None = None, timeout: float = 15.0) -> None:
        self._url = url
        self._secret = hmac_secret.encode("utf-8") if hmac_secret else None
        self._timeout = timeout

    async def export(self, findings: Sequence[Finding]) -> int:
        if not findings or not self._url:
            return 0
        payload = [FindingDTO.from_entity(f).model_dump(mode="json") for f in findings]
        body = json.dumps({"findings": payload}, default=str).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self._secret:
            sig = hmac.new(self._secret, body, hashlib.sha256).hexdigest()
            headers["X-Signature-SHA256"] = sig
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            response = await client.post(self._url, content=body, headers=headers)
        response.raise_for_status()
        return len(findings)

    async def health(self) -> bool:
        return bool(self._url)
