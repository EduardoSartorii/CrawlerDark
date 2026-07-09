"""OpenSearchExporter — bulk index via API HTTP."""

from __future__ import annotations

import json
from collections.abc import Sequence

import httpx

from ...core.application.dto import FindingDTO
from ...core.domain.entities import Finding


class OpenSearchExporter:
    name = "opensearch"

    def __init__(
        self,
        url: str,
        *,
        index: str,
        user: str | None = None,
        password: str | None = None,
        verify_tls: bool = True,
    ) -> None:
        self._url = url.rstrip("/") + "/_bulk"
        self._index = index
        self._auth = (user, password) if user and password else None
        self._verify = verify_tls

    async def export(self, findings: Sequence[Finding]) -> int:
        if not findings:
            return 0
        lines: list[str] = []
        for f in findings:
            meta = {"index": {"_index": self._index, "_id": str(f.id)}}
            lines.append(json.dumps(meta))
            lines.append(FindingDTO.from_entity(f).model_dump_json())
        body = ("\n".join(lines) + "\n").encode("utf-8")
        async with httpx.AsyncClient(
            verify=self._verify, timeout=30.0, auth=self._auth
        ) as client:
            r = await client.post(
                self._url, content=body, headers={"Content-Type": "application/x-ndjson"}
            )
        r.raise_for_status()
        data = r.json()
        errors = int(data.get("errors", False))
        return len(findings) - errors

    async def health(self) -> bool:
        try:
            async with httpx.AsyncClient(verify=self._verify, timeout=5.0, auth=self._auth) as client:
                r = await client.get(self._url.replace("/_bulk", ""))
            return r.status_code == 200
        except Exception:  # noqa: BLE001
            return False
