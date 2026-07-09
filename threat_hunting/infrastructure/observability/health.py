"""Health checks for connectors and platform dependencies."""

from __future__ import annotations

from threat_hunting.connectors.registry import ConnectorRegistry


class HealthService:
    """Collect health details from configured connectors."""

    def __init__(self, registry: ConnectorRegistry) -> None:
        self._registry = registry

    def check(self) -> dict[str, object]:
        """Return platform health summary."""

        connectors = []
        for definition in self._registry.list(enabled_only=True):
            connector = self._registry.get(definition.name)
            connectors.append(connector.health())
            connector.close()
        return {"status": "ok", "connectors": connectors}
