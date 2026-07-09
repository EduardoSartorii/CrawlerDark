"""Normalizer stage to enforce canonical finding fields before detection."""

from __future__ import annotations

from datetime import UTC, datetime

from threat_hunting.core.contracts import StageContext


class DefaultNormalizer:
    """Normalize records to canonical fields expected by Finding entity."""

    def run(self, items: list[dict[str, object]], context: StageContext) -> list[dict[str, object]]:
        """Apply canonical defaults and normalization."""
        normalized: list[dict[str, object]] = []
        now = datetime.now(UTC).isoformat()
        for item in items:
            normalized_data = dict(item.get("normalized_data", {}))
            normalized.append(
                {
                    "title": item.get("title") or "untitled finding",
                    "description": item.get("description") or "",
                    "source": item.get("source") or context.connector_name,
                    "connector": item.get("connector") or context.connector_name,
                    "category": item.get("category") or "unknown",
                    "severity": item.get("severity") or "info",
                    "score": float(item.get("score", 0.0)),
                    "confidence": float(item.get("confidence", 0.0)),
                    "created_at": item.get("created_at") or now,
                    "updated_at": item.get("updated_at") or now,
                    "raw_data": item.get("raw_data") or {},
                    "normalized_data": normalized_data,
                    "metadata": item.get("metadata") or {},
                    "tags": list(item.get("tags", [])),
                    "artifacts": list(item.get("artifacts", [])),
                    "indicators": list(item.get("indicators", [])),
                    "relationships": list(item.get("relationships", [])),
                    "timeline": list(item.get("timeline", [])),
                }
            )
        return normalized
