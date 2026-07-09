"""
ThreatFox Connector.

Collects recent IOCs from abuse.ch ThreatFox — a free threat intelligence
sharing platform focused on malware IOCs.

ThreatFox API provides:
    - Recent IOCs (IPs, domains, URLs, hashes) with malware family attribution
    - Confidence levels and threat types
    - Bulk IOC downloads

This is a high-fidelity source — findings from ThreatFox are auto-scored higher.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from ...core.domain.entities.finding import Finding
from ...core.domain.entities.indicator import Indicator, IndicatorType
from ...core.domain.value_objects import ThreatCategory
from ...core.domain.value_objects.source_type import SourceType
from .base import BaseConnector, CollectionContext, ConnectorHealth, ConnectorStatus


class ThreatFoxConnector(BaseConnector):
    """
    ThreatFox IOC feed connector.

    Config keys:
        api_key: str — ThreatFox API key (optional, increases limits)
        days: int — lookback window in days (default: 1)
        malware_filter: list[str] — filter by malware family (optional)
        min_confidence: int — minimum confidence level 0-100 (default: 50)
    """

    connector_id = "threatfox"
    source_type = SourceType.THREATFOX
    group = "feeds"
    description = "ThreatFox IOC feed (abuse.ch)"
    version = "1.0.0"

    _API_URL = "https://threatfox-api.abuse.ch/api/v1/"

    # IOC type mapping: ThreatFox type → IndicatorType
    _IOC_TYPE_MAP: dict[str, IndicatorType] = {
        "ip:port": IndicatorType.IP_V4,
        "domain": IndicatorType.DOMAIN,
        "url": IndicatorType.URL,
        "md5_hash": IndicatorType.FILE_HASH_MD5,
        "sha256_hash": IndicatorType.FILE_HASH_SHA256,
        "sha1_hash": IndicatorType.FILE_HASH_SHA1,
    }

    async def connect(self) -> None:
        api_key = self._config.get("api_key", "")
        self._headers: dict[str, str] = {"API-KEY": api_key} if api_key else {}
        self.log.info("threatfox.connected", authenticated=bool(api_key))

    async def collect(self, ctx: CollectionContext) -> None:
        """Fetch recent IOCs from ThreatFox API."""
        days = self._config.get("days", 1)
        payload: dict[str, Any] = {"query": "get_iocs", "days": days}

        malware_filter = self._config.get("malware_filter")
        if malware_filter:
            payload["malware"] = malware_filter[0] if isinstance(malware_filter, list) else malware_filter

        try:
            resp = await self.http.post(
                self._API_URL,
                json=payload,
                headers=self._headers,
            )
            if resp.status_code != 200:
                ctx.errors.append(f"ThreatFox API returned {resp.status_code}")
                return

            data = resp.json()
            if data.get("query_status") != "ok":
                ctx.errors.append(f"ThreatFox error: {data.get('query_status')}")
                return

            ctx.raw_items = data.get("data", []) or []
            self.log.info("threatfox.fetched", count=len(ctx.raw_items), days=days)

        except Exception as exc:
            ctx.errors.append(f"ThreatFox collection failed: {exc}")
            self.log.error("threatfox.collect_failed", error=str(exc))

    async def parse(self, ctx: CollectionContext) -> None:
        """Filter and extract IOC data."""
        min_confidence = self._config.get("min_confidence", 50)

        for ioc in ctx.raw_items:
            confidence = ioc.get("confidence_level", 0)
            if confidence < min_confidence:
                continue

            ctx.parsed_items.append({
                "id": ioc.get("id", ""),
                "ioc": ioc.get("ioc", ""),
                "ioc_type": ioc.get("ioc_type", "unknown"),
                "threat_type": ioc.get("threat_type", ""),
                "malware": ioc.get("malware", ""),
                "malware_printable": ioc.get("malware_printable", ""),
                "confidence": confidence,
                "first_seen": ioc.get("first_seen", ""),
                "last_seen": ioc.get("last_seen", ""),
                "tags": ioc.get("tags") or [],
                "reporter": ioc.get("reporter", ""),
                "reference": ioc.get("reference", ""),
            })

    async def normalize(self, ctx: CollectionContext) -> None:
        """Convert ThreatFox IOCs into Findings with embedded Indicators."""
        for item in ctx.parsed_items:
            malware_name = item["malware_printable"] or item["malware"] or "Unknown Malware"
            ioc_value = item["ioc"]

            title = f"[ThreatFox] {malware_name} IOC: {ioc_value[:80]}"
            description = (
                f"Malware: {malware_name}\n"
                f"Threat type: {item['threat_type']}\n"
                f"IOC: {ioc_value}\n"
                f"Confidence: {item['confidence']}%\n"
                f"Reporter: {item['reporter']}\n"
                f"First seen: {item['first_seen']}"
            )

            finding = Finding.create(
                title=title,
                source="ThreatFox (abuse.ch)",
                connector=self.connector_id,
                category=self._classify_threat(item),
                source_type=self.source_type,
                description=description,
                raw_data=json.dumps(item),
                tags=["threatfox", "ioc", "abuse.ch"] + item["tags"],
            )
            finding.source_id = str(item["id"])
            finding.malware_family = malware_name
            finding.normalized_data = item

            # Confidence from ThreatFox (0-100) → normalized (0-1)
            finding.confidence = item["confidence"] / 100.0

            ctx.findings.append(finding)

    def _classify_threat(self, item: dict[str, Any]) -> ThreatCategory:
        threat_type = item.get("threat_type", "").lower()
        malware = item.get("malware", "").lower()

        if "ransomware" in malware or "ransomware" in threat_type:
            return ThreatCategory.RANSOMWARE
        if "botnet" in threat_type or "c2" in threat_type:
            return ThreatCategory.C2_INFRASTRUCTURE
        if "payload" in threat_type or "malware" in threat_type:
            return ThreatCategory.MALWARE
        return ThreatCategory.IOC

    async def close(self) -> None:
        pass

    async def health(self) -> ConnectorHealth:
        try:
            resp = await self.http.post(
                self._API_URL,
                json={"query": "get_iocs", "days": 1},
                headers=self._headers,
            )
            healthy = resp.status_code == 200
        except Exception as exc:
            return ConnectorHealth(
                connector_id=self.connector_id,
                healthy=False,
                status=ConnectorStatus.ERROR,
                last_error=str(exc),
            )
        return ConnectorHealth(
            connector_id=self.connector_id,
            healthy=healthy,
            status=self._status,
            last_run=self._last_run,
            findings_total=self._total_findings,
        )
