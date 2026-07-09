"""Plugin discovery facade."""

from __future__ import annotations

from threat_hunting.connectors.registry import ConnectorRegistry


class PluginManager:
    """Facade for discovering connector plugins."""

    def __init__(self, registry: ConnectorRegistry) -> None:
        self.registry = registry

    def load(self, modules: list[str] | None = None) -> ConnectorRegistry:
        """Load connector plugins and return the populated registry."""

        return self.registry.discover(modules)
