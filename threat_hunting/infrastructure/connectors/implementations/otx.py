"""OTXConnector — AlienVault OTX pulses."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from ....core.domain.builders import FindingBuilder
from ....core.domain.entities import Finding, Indicator
from ....core.domain.value_objects import Category, Confidence, IndicatorType, Severity, SourceRef
from ..base import BaseConnector
from ..registry import register_connector


_TYPE_MAP: dict[str, IndicatorType] = {
    "IPv4": IndicatorType.IP,
    "IPv6": IndicatorType.IP,
    "domain": IndicatorType.DOMAIN,
    "hostname": IndicatorType.DOMAIN,
    "URL": IndicatorType.URL,
    "URI": IndicatorType.URL,
    "email": IndicatorType.EMAIL,
    "FileHash-MD5": IndicatorType.HASH_MD5,
    "FileHash-SHA1": IndicatorType.HASH_SHA1,
    "FileHash-SHA256": IndicatorType.HASH_SHA256,
    "CVE": IndicatorType.CVE,
}


@register_connector("otx")
class OTXConnector(BaseConnector):
    ENDPOINT = "https://otx.alienvault.com/api/v1/pulses/subscribed"

    async def collect(self) -> AsyncIterator[dict[str, Any]]:  # type: ignore[override]
        if self.http is None:
            raise RuntimeError("OTXConnector requires HTTP client")
        key = self.options.get("api_key")
        if not key:
            return
        limit = int(self.options.get("pulses_limit", 20))
        headers = {"X-OTX-API-KEY": str(key)}
        response = await self.http.get(self.ENDPOINT, headers=headers, params={"limit": limit})
        data = response.json() or {}
        for pulse in (data.get("results") or []):
            yield pulse

    async def parse(self, payload: Any) -> dict[str, Any]:
        return payload if isinstance(payload, dict) else {}

    async def normalize(self, parsed: dict[str, Any]) -> Finding:
        name = parsed.get("name", "(otx pulse)")
        desc = parsed.get("description", "") or ""
        source = SourceRef(source="otx", connector=self.name, url=f"https://otx.alienvault.com/pulse/{parsed.get('id', '')}")
        f = (
            FindingBuilder()
            .title(f"OTX Pulse: {name}"[:400])
            .description(desc[:2000])
            .source(source)
            .category(Category.CAMPAIGN)
            .severity(Severity.MEDIUM)
            .raw(parsed)
            .tag("otx", "pulse", *(parsed.get("tags") or []))
            .build()
        )
        for ioc in (parsed.get("indicators") or [])[:200]:
            itype = _TYPE_MAP.get(ioc.get("type", ""))
            value = ioc.get("indicator")
            if not (itype and value):
                continue
            f.add_indicator(
                Indicator(
                    type=itype,
                    value=value,
                    confidence=Confidence(70),
                    tags={"otx"},
                )
            )
        return f

    async def health(self) -> bool:
        return bool(self.options.get("api_key"))
