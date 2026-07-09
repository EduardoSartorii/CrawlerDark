"""OpenCTIExporter — envia findings ao OpenCTI via GraphQL.

Implementação minimalista via HTTPX; se ``pycti`` estiver instalado, use-o
como upgrade natural (mantendo a mesma interface pública).
"""

from __future__ import annotations

from collections.abc import Sequence

import httpx

from ...core.application.dto import FindingDTO
from ...core.domain.entities import Finding


_CREATE_REPORT_MUTATION = """
mutation ThreatHuntingReport($input: ReportAddInput!) {
    reportAdd(input: $input) { id name }
}
"""


class OpenCTIExporter:
    name = "opencti"

    def __init__(self, url: str, token: str, *, verify_tls: bool = True) -> None:
        self._url = url.rstrip("/") + "/graphql"
        self._headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        self._verify = verify_tls

    async def export(self, findings: Sequence[Finding]) -> int:
        if not findings:
            return 0
        exported = 0
        async with httpx.AsyncClient(verify=self._verify, timeout=30.0) as client:
            for f in findings:
                dto = FindingDTO.from_entity(f)
                variables = {
                    "input": {
                        "name": dto.title[:250],
                        "description": dto.description or dto.title,
                        "published": dto.created_at.isoformat(),
                        "confidence": dto.confidence,
                        "objectLabel": dto.tags,
                    }
                }
                try:
                    r = await client.post(
                        self._url,
                        headers=self._headers,
                        json={"query": _CREATE_REPORT_MUTATION, "variables": variables},
                    )
                    r.raise_for_status()
                    if "errors" not in (r.json() or {}):
                        exported += 1
                except httpx.HTTPError:
                    continue
        return exported

    async def health(self) -> bool:
        try:
            async with httpx.AsyncClient(verify=self._verify, timeout=5.0) as client:
                r = await client.post(
                    self._url,
                    headers=self._headers,
                    json={"query": "{ about { version } }"},
                )
            return r.status_code == 200
        except Exception:  # noqa: BLE001
            return False
