"""Integration client adapters for external threat intelligence APIs."""

from __future__ import annotations

from typing import Any


class VirusTotalAdapter:
    """Adapter for VirusTotal API enrichment."""

    def __init__(self, api_key: str = "") -> None:
        self._api_key = api_key

    async def lookup_domain(self, domain: str) -> dict[str, Any]:
        return {"domain": domain, "reputation": "unknown", "source": "virustotal"}

    async def lookup_hash(self, hash_value: str) -> dict[str, Any]:
        return {"hash": hash_value, "detections": 0, "source": "virustotal"}


class GreyNoiseAdapter:
    """Adapter for GreyNoise API enrichment."""

    def __init__(self, api_key: str = "") -> None:
        self._api_key = api_key

    async def lookup_ip(self, ip: str) -> dict[str, Any]:
        return {"ip": ip, "classification": "unknown", "source": "greynoise"}
