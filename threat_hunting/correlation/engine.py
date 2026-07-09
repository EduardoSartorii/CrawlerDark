"""Correlation engine implementation."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from threat_hunting.core.contracts import StageContext

CORRELATION_KEYS = (
    "domain",
    "ip",
    "asn",
    "certificate",
    "threat_actor",
    "campaign",
    "email",
    "wallet",
    "nickname",
    "github",
    "telegram",
    "forum_user",
    "ioc",
    "malware",
    "brand",
    "infrastructure",
)


class EntityCorrelationEngine:
    """Correlates findings based on shared key entities."""

    def run(self, items: list[dict[str, Any]], context: StageContext) -> list[dict[str, Any]]:
        """Annotate findings with correlation clusters."""
        clusters: dict[str, list[str]] = defaultdict(list)
        for item in items:
            normalized_data = item.get("normalized_data", {})
            for key in CORRELATION_KEYS:
                value = normalized_data.get(key)
                if value:
                    clusters[f"{key}:{value}"].append(str(item.get("title", "unknown")))
        output: list[dict[str, Any]] = []
        for item in items:
            correlations: list[dict[str, Any]] = list(item.get("relationships", []))
            normalized_data = item.get("normalized_data", {})
            for key in CORRELATION_KEYS:
                value = normalized_data.get(key)
                if not value:
                    continue
                bucket = clusters.get(f"{key}:{value}", [])
                if len(bucket) > 1:
                    correlations.append({"type": key, "value": value, "cluster_size": len(bucket)})
            output.append({**item, "relationships": correlations})
        return output
