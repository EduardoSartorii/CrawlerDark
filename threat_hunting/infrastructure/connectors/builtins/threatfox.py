"""ThreatFox (abuse.ch) threat-intel feed connector.

Responsibility
--------------
Pull recent IOCs from the ThreatFox API and turn each into a finding. It shows
how a feed/API connector maps a structured JSON payload into the canonical
model. Networked; the API endpoint and lookback window come from configuration.
"""

from __future__ import annotations

import json
from collections.abc import Sequence

from threat_hunting.core.application.dto import RawRecord
from threat_hunting.core.domain.entities import Finding, Indicator
from threat_hunting.core.domain.enums import Category, ConfidenceLevel, IndicatorType
from threat_hunting.infrastructure.connectors.base import BaseConnector

#: Maps ThreatFox ``ioc_type`` values to the platform's indicator types.
_IOC_TYPE_MAP = {
    "ip:port": IndicatorType.IPV4,
    "domain": IndicatorType.DOMAIN,
    "url": IndicatorType.URL,
    "md5_hash": IndicatorType.MD5,
    "sha1_hash": IndicatorType.SHA1,
    "sha256_hash": IndicatorType.SHA256,
}


class ThreatFoxConnector(BaseConnector):
    """Collects recent IOCs from the ThreatFox API."""

    name = "threatfox"
    source = "threatfox"
    default_category = Category.IOC_HUNTING

    _API = "https://threatfox-api.abuse.ch/api/v1/"

    async def collect(self) -> Sequence[RawRecord]:
        """Query ThreatFox for IOCs seen in the configured lookback window."""
        days = int(self.options.get("days", 1))
        endpoint = self.options.get("api", self._API)
        response = await self.transport.post(
            endpoint, json={"query": "get_iocs", "days": days}
        )
        if not response.ok:
            return []
        payload = json.loads(response.text)
        records: list[RawRecord] = []
        for entry in payload.get("data", []):
            records.append(
                self._record(
                    content=str(entry.get("ioc", "")),
                    url=entry.get("reference"),
                    metadata={
                        "title": f"ThreatFox IOC: {entry.get('ioc', '')}",
                        "malware": entry.get("malware_printable"),
                        "threat_type": entry.get("threat_type"),
                    },
                    raw=entry,
                )
            )
        return records

    def normalize(self, record: RawRecord) -> Finding:
        """Map a ThreatFox entry into a finding with a typed indicator."""
        finding = super().normalize(record)
        raw = record.raw
        ioc_type = _IOC_TYPE_MAP.get(raw.get("ioc_type", ""), IndicatorType.OTHER)
        finding.add_indicator(
            Indicator(
                type=ioc_type,
                value=str(raw.get("ioc", "")),
                context={
                    "malware": raw.get("malware_printable"),
                    "confidence": raw.get("confidence_level"),
                },
            )
        )
        if raw.get("malware_printable"):
            finding.add_tag(str(raw["malware_printable"]))
        finding.confidence = ConfidenceLevel.HIGH
        return finding
