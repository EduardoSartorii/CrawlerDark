"""Base connector SDK contract implementation.

Every new connector must inherit this class and only implement source specifics.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from threat_hunting.core.contracts import ConnectorPort, StageContext, TransportPort


class BaseConnector(ConnectorPort):
    """Reusable base connector with safe defaults and lifecycle hooks."""

    name = "base"
    category = "generic"

    def __init__(self, config: dict[str, Any] | None = None, transport: TransportPort | None = None) -> None:
        self.config = config or {}
        self.transport = transport
        self._connected = False

    def connect(self) -> None:
        """Initialize connector state and validate baseline configuration."""
        self._connected = True

    def collect(self, context: StageContext) -> list[dict[str, Any]]:
        """Collect raw records from source. Must be overridden."""
        return []

    def parse(self, raw_items: list[dict[str, Any]], context: StageContext) -> list[dict[str, Any]]:
        """Default parser pass-through."""
        return raw_items

    def normalize(self, parsed_items: list[dict[str, Any]], context: StageContext) -> list[dict[str, Any]]:
        """Default normalization baseline for connector-origin payloads."""
        normalized: list[dict[str, Any]] = []
        now = datetime.now(UTC).isoformat()
        for item in parsed_items:
            normalized.append(
                {
                    "title": item.get("title", f"{self.name} finding"),
                    "description": item.get("description", ""),
                    "source": item.get("source", self.name),
                    "connector": self.name,
                    "category": item.get("category", self.category),
                    "severity": item.get("severity", "info"),
                    "created_at": item.get("created_at", now),
                    "updated_at": item.get("updated_at", now),
                    "raw_data": item,
                    "normalized_data": item.get("normalized_data", {}),
                    "metadata": item.get("metadata", {}),
                    "tags": item.get("tags", []),
                    "artifacts": item.get("artifacts", []),
                    "indicators": item.get("indicators", []),
                    "relationships": item.get("relationships", []),
                    "timeline": item.get("timeline", []),
                }
            )
        return normalized

    def health(self) -> dict[str, Any]:
        """Return current connector health state."""
        return {"name": self.name, "connected": self._connected, "status": "ok"}

    def close(self) -> None:
        """Release connector resources."""
        self._connected = False
