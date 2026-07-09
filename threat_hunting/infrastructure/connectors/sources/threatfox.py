"""ThreatFox threat-feed connector.

Responsibility
--------------
Pull recent IOCs from abuse.ch ThreatFox (a threat feed / API source) and turn
each IOC into a raw item. Demonstrates a threat-feed connector whose findings
are pure IOCs feeding the correlation/enrichment stages.
"""

from __future__ import annotations

import json
from collections.abc import Iterable

from threat_hunting.core.application.ports.connector import ConnectorMeta
from threat_hunting.core.domain.entities.raw_item import RawItem
from threat_hunting.core.domain.enums import Category, SourceType
from threat_hunting.infrastructure.connectors.base import BaseConnector

_API = "https://threatfox-api.abuse.ch/api/v1/"


class ThreatFoxConnector(BaseConnector):
    """Collects recent IOCs from abuse.ch ThreatFox."""

    meta = ConnectorMeta(
        name="threatfox",
        source=SourceType.THREAT_FEED,
        category=Category.IOC,
        description="abuse.ch ThreatFox recent-IOC collector.",
        groups=["feed", "ioc"],
    )

    def __init__(self, transport=None, days: int = 1) -> None:
        super().__init__(transport=transport)
        self._days = days

    def collect(self) -> Iterable[RawItem]:
        """Yield one raw item per recent IOC returned by the ThreatFox API."""
        body = json.dumps({"query": "get_iocs", "days": self._days})
        response = self._transport.request("POST", _API, content=body)
        if not response.ok:
            return
        try:
            data = json.loads(response.text)
        except json.JSONDecodeError:
            return
        for ioc in data.get("data", []) or []:
            yield RawItem(
                connector=self.meta.name,
                source="threatfox",
                url=ioc.get("reference", _API),
                title=f"{ioc.get('threat_type', 'ioc')}: {ioc.get('ioc', '')}",
                content=ioc.get("ioc", ""),
                payload={
                    "malware": ioc.get("malware_printable", ""),
                    "ioc_type": ioc.get("ioc_type", ""),
                    "confidence": str(ioc.get("confidence_level", 50)),
                },
            )
