"""Factory helpers for connector and exporter instantiation."""

from __future__ import annotations

from threat_hunting.core.contracts import ConnectorPort
from threat_hunting.core.plugin import ConnectorRegistry


class ConnectorFactory:
    """Factory pattern wrapper around plugin registry."""

    def __init__(self, registry: ConnectorRegistry) -> None:
        self._registry = registry

    def create(self, connector_name: str) -> ConnectorPort:
        """Create connector instance by canonical name."""
        return self._registry.get(connector_name)
