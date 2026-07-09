"""SplunkExporter — envia findings via HTTP Event Collector (HEC)."""

from __future__ import annotations

import json
from collections.abc import Sequence

import httpx

from ...core.application.dto import FindingDTO
from ...core.domain.entities import Finding


class SplunkExporter:
    name = "splunk"

    def __init__(
        self,
        hec_url: str,
        hec_token: str,
        *,
        index: str = "threat_hunting",
        verify_tls: bool = True,
    ) -> None:
        self._url = hec_url.rstrip("/") + "/services/collector/event"
        self._headers = {"Authorization": f"Splunk {hec_token}"}
        self._index = index
        self._verify = verify_tls

    async def export(self, findings: Sequence[Finding]) -> int:
        if not findings:
            return 0
        lines = []
        for f in findings:
            dto = FindingDTO.from_entity(f).model_dump(mode="json")
            envelope = {
                "index": self._index,
                "sourcetype": "threat_hunting:finding",
                "source": f.connector,
                "time": f.created_at.timestamp(),
                "event": dto,
            }
            lines.append(json.dumps(envelope, default=str))
        body = "\n".join(lines).encode("utf-8")
        async with httpx.AsyncClient(verify=self._verify, timeout=30.0) as client:
            r = await client.post(self._url, headers=self._headers, content=body)
        r.raise_for_status()
        return len(findings)

    async def health(self) -> bool:
        try:
            async with httpx.AsyncClient(verify=self._verify, timeout=5.0) as client:
                r = await client.get(
                    self._url.replace("/services/collector/event", "/services/collector/health"),
                    headers=self._headers,
                )
            return r.status_code == 200
        except Exception:  # noqa: BLE001
            return False
