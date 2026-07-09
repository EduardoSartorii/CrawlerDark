"""MISPConnector — consome eventos publicados de uma instância MISP.

Só funciona se ``pymisp`` estiver instalado. Caso contrário permanece
silenciosamente vazio (health = False).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from ....core.domain.builders import FindingBuilder
from ....core.domain.entities import Finding, Indicator
from ....core.domain.value_objects import Category, Confidence, IndicatorType, Severity, SourceRef
from ..base import BaseConnector
from ..registry import register_connector

try:
    from pymisp import ExpandedPyMISP  # type: ignore[import-untyped]
except Exception:  # pragma: no cover — opcional
    ExpandedPyMISP = None  # type: ignore[assignment]


_ATTR_MAP: dict[str, IndicatorType] = {
    "ip-dst": IndicatorType.IP,
    "ip-src": IndicatorType.IP,
    "domain": IndicatorType.DOMAIN,
    "hostname": IndicatorType.DOMAIN,
    "url": IndicatorType.URL,
    "email-dst": IndicatorType.EMAIL,
    "email-src": IndicatorType.EMAIL,
    "md5": IndicatorType.HASH_MD5,
    "sha1": IndicatorType.HASH_SHA1,
    "sha256": IndicatorType.HASH_SHA256,
    "vulnerability": IndicatorType.CVE,
    "cc-number": IndicatorType.CARD_PAN,
    "btc": IndicatorType.WALLET_BTC,
}


@register_connector("misp")
class MISPConnector(BaseConnector):
    async def collect(self) -> AsyncIterator[dict[str, Any]]:  # type: ignore[override]
        url = self.options.get("url")
        key = self.options.get("key")
        if not (ExpandedPyMISP and url and key):
            return
        client = ExpandedPyMISP(str(url), str(key), False)
        published = self.options.get("published_only", True)
        try:
            events = client.search(published=bool(published), pythonify=False, limit=50)
        except Exception:  # noqa: BLE001
            return
        for ev in events or []:
            data = ev.get("Event") if isinstance(ev, dict) else None
            if data:
                yield data

    async def parse(self, payload: Any) -> dict[str, Any]:
        return payload if isinstance(payload, dict) else {}

    async def normalize(self, parsed: dict[str, Any]) -> Finding:
        info = parsed.get("info", "(misp event)")
        source = SourceRef(source="misp", connector=self.name, url=f"misp-event://{parsed.get('id')}")
        f = (
            FindingBuilder()
            .title(f"MISP: {info}"[:400])
            .description(parsed.get("description", "") or "")
            .source(source)
            .category(Category.THREAT_ACTOR)
            .severity(Severity.MEDIUM)
            .raw(parsed)
            .tag("misp", f"event:{parsed.get('id')}")
            .build()
        )
        for attr in (parsed.get("Attribute") or []):
            itype = _ATTR_MAP.get(attr.get("type", ""))
            value = attr.get("value")
            if not (itype and value):
                continue
            f.add_indicator(
                Indicator(type=itype, value=str(value), confidence=Confidence(75), tags={"misp"})
            )
        return f

    async def health(self) -> bool:
        return bool(ExpandedPyMISP and self.options.get("url") and self.options.get("key"))
