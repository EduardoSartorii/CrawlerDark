"""Factory pattern helpers to instantiate connectors/exporters."""

from __future__ import annotations

from typing import Any

from threat_hunting.core.contracts import ConnectorPort, ExporterPort
from threat_hunting.core.exceptions import ConnectorNotFoundError


class ConnectorFactory:
    """Factory for connector instances discovered via plugin manager."""

    def __init__(self, registry: dict[str, type[ConnectorPort]], config: dict[str, Any]) -> None:
        self._registry = registry
        self._config = config

    def create(self, connector_name: str) -> ConnectorPort:
        """Instantiate connector by name."""
        connector_type = self._registry.get(connector_name.lower())
        if not connector_type:
            raise ConnectorNotFoundError(f"Connector '{connector_name}' not registered")
        connector_config = self._config.get("connectors", {}).get(connector_name.lower(), {})
        return connector_type(config=connector_config)

    def available(self) -> list[str]:
        """Return sorted list of available connectors."""
        return sorted(self._registry)


class ExporterFactory:
    """Factory for exporter instances."""

    def __init__(self, registry: dict[str, ExporterPort]) -> None:
        self._registry = registry

    def get(self, exporter_name: str) -> ExporterPort:
        """Resolve exporter by name."""
        key = exporter_name.lower()
        exporter = self._registry.get(key)
        if exporter is None:
            msg = f"Exporter '{exporter_name}' not registered"
            raise ValueError(msg)
        return exporter
