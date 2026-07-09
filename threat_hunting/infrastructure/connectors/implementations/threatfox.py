"""ThreatFoxConnector — abuse.ch ThreatFox API.

Endpoint público: https://threatfox-api.abuse.ch/api/v1/
Query: {"query": "get_iocs", "days": 1}
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from ....core.domain.builders import FindingBuilder
from ....core.domain.entities import Finding, Indicator
from ....core.domain.value_objects import Category, Confidence, IndicatorType, Severity, SourceRef
from ..base import BaseConnector
from ..registry import register_connector


_TYPE_MAP: dict[str, IndicatorType] = {
    "ip:port": IndicatorType.IP,
    "ip": IndicatorType.IP,
    "domain": IndicatorType.DOMAIN,
    "url": IndicatorType.URL,
    "md5_hash": IndicatorType.HASH_MD5,
    "sha1_hash": IndicatorType.HASH_SHA1,
    "sha256_hash": IndicatorType.HASH_SHA256,
    "email": IndicatorType.EMAIL,
}


@register_connector("threatfox")
class ThreatFoxConnector(BaseConnector):
    ENDPOINT = "https://threatfox-api.abuse.ch/api/v1/"

    async def collect(self) -> AsyncIterator[dict[str, Any]]:  # type: ignore[override]
        if self.http is None:
            raise RuntimeError("ThreatFoxConnector requires HTTP client")
        payload = {"query": "get_iocs", "days": int(self.options.get("days", 1))}
        api_key = self.options.get("api_key")
        headers = {"API-KEY": str(api_key)} if api_key else {}
        response = await self.http.post(self.ENDPOINT, json=payload, headers=headers)
        data = response.json() or {}
        for item in (data.get("data") or []):
            yield item

    async def parse(self, payload: Any) -> dict[str, Any]:
        return payload if isinstance(payload, dict) else {}

    async def normalize(self, parsed: dict[str, Any]) -> Finding:
        ioc_type = str(parsed.get("ioc_type") or "").lower()
        ioc_value = str(parsed.get("ioc") or "").strip()
        malware = str(parsed.get("malware") or "").strip()
        source = SourceRef(
            source="threatfox",
            connector=self.name,
            url=parsed.get("reference") or f"{self.ENDPOINT}#ioc",
        )
        raw_ip = ioc_value.split(":")[0] if ioc_type == "ip:port" and ioc_value else ioc_value
        builder = (
            FindingBuilder()
            .title(f"ThreatFox {ioc_type}: {malware or 'unknown malware'}")
            .description(f"IOC {raw_ip} associated with {malware or 'unknown malware'}")
            .source(source)
            .category(Category.IOC)
            .severity(Severity.HIGH)
            .confidence(int(parsed.get("confidence_level") or 60))
            .raw(parsed)
            .tag("threatfox", "malware", malware.lower())
        )
        finding = builder.build()
        indicator_type = _TYPE_MAP.get(ioc_type)
        if indicator_type and raw_ip:
            finding.add_indicator(
                Indicator(
                    type=indicator_type,
                    value=raw_ip,
                    confidence=Confidence(int(parsed.get("confidence_level") or 60)),
                    tags={malware.lower(), "threatfox"} if malware else {"threatfox"},
                    context={
                        "malware": malware,
                        "threat_type": parsed.get("threat_type"),
                        "first_seen": parsed.get("first_seen"),
                        "reporter": parsed.get("reporter"),
                    },
                )
            )
        return finding

    async def health(self) -> bool:
        return self.http is not None
