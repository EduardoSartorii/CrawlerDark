"""MISPExporter — envia findings ao MISP quando ``pymisp`` está disponível.

Sem ``pymisp``, permanece ``enabled=False`` e ``health()`` retorna False. O
adapter não deve derrubar a plataforma quando o cliente não estiver instalado.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from ...core.domain.entities import Finding
from ...core.domain.value_objects import IndicatorType

try:  # pymisp é opcional
    from pymisp import ExpandedPyMISP, MISPEvent  # type: ignore[import-untyped]
except Exception:  # pragma: no cover — opcional
    ExpandedPyMISP = None  # type: ignore[assignment]
    MISPEvent = None  # type: ignore[assignment]


_MISP_TYPES: dict[IndicatorType, str] = {
    IndicatorType.IP: "ip-dst",
    IndicatorType.DOMAIN: "domain",
    IndicatorType.URL: "url",
    IndicatorType.EMAIL: "email-dst",
    IndicatorType.HASH_MD5: "md5",
    IndicatorType.HASH_SHA1: "sha1",
    IndicatorType.HASH_SHA256: "sha256",
    IndicatorType.CVE: "vulnerability",
    IndicatorType.CARD_PAN: "cc-number",
    IndicatorType.WALLET_BTC: "btc",
    IndicatorType.WALLET_ETH: "cryptocurrency-address",
    IndicatorType.CREDENTIAL: "text",
}


class MISPExporter:
    name = "misp"

    def __init__(
        self,
        *,
        url: str | None = None,
        key: str | None = None,
        verify_tls: bool = True,
        distribution: int = 0,
        default_event_id: str | None = None,
    ) -> None:
        self._url = url
        self._key = key
        self._verify = verify_tls
        self._distribution = distribution
        self._default_event_id = default_event_id
        self._client: Any = None
        if ExpandedPyMISP and url and key:
            try:
                self._client = ExpandedPyMISP(url, key, verify_tls)
            except Exception:  # noqa: BLE001
                self._client = None

    async def health(self) -> bool:
        return self._client is not None

    async def export(self, findings: Sequence[Finding]) -> int:
        if self._client is None or not findings:
            return 0
        exported = 0
        for f in findings:
            event = MISPEvent()  # type: ignore[operator]
            event.info = f.title[:255]
            event.distribution = self._distribution
            event.threat_level_id = self._map_threat_level(f.severity.name)
            event.analysis = 2
            event.add_tag(f"tlp:{f.tlp.value.lower()}")
            for tag in sorted(f.tags):
                event.add_tag(tag)
            for ind in f.indicators:
                misp_type = _MISP_TYPES.get(ind.type)
                if not misp_type:
                    continue
                event.add_attribute(
                    misp_type,
                    ind.value,
                    comment=f"confidence={ind.confidence.value}",
                    to_ids=True if misp_type not in {"text", "vulnerability"} else False,
                )
            try:
                if self._default_event_id:
                    for attr in event.attributes:
                        self._client.add_attribute(self._default_event_id, attr)
                else:
                    self._client.add_event(event)
                exported += 1
            except Exception:  # noqa: BLE001
                continue
        return exported

    @staticmethod
    def _map_threat_level(severity_name: str) -> int:
        mapping = {"INFO": 4, "LOW": 3, "MEDIUM": 2, "HIGH": 1, "CRITICAL": 1}
        return mapping.get(severity_name, 3)
