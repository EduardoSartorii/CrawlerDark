"""Plugin registry with connector auto-discovery support."""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from typing import Any

from threat_hunting.core.contracts import ConnectorPort, ConnectorRegistryPort


class ConnectorRegistry(ConnectorRegistryPort):
    """In-memory connector plugin registry."""

    def __init__(self, connector_kwargs: dict[str, Any] | None = None) -> None:
        self._types: dict[str, type[ConnectorPort]] = {}
        self._connector_kwargs = connector_kwargs or {}

    def register(self, connector_type: type[ConnectorPort]) -> None:
        """Register connector class keyed by canonical name."""
        connector_name = getattr(connector_type, "name", "").strip().lower()
        if not connector_name:
            msg = f"Connector {connector_type.__name__} is missing a valid name attribute."
            raise ValueError(msg)
        self._types[connector_name] = connector_type

    def get(self, name: str) -> ConnectorPort:
        """Instantiate a connector from a registered type."""
        connector_type = self._types[name.lower()]
        return connector_type(**self._connector_kwargs)

    def names(self) -> list[str]:
        """List all registered connector names."""
        return sorted(self._types.keys())

    def autodiscover(self, package: str = "threat_hunting.connectors") -> None:
        """Import connector modules and register ConnectorPort subclasses."""
        module = importlib.import_module(package)
        for _, module_name, _ in pkgutil.iter_modules(module.__path__, f"{package}."):
            imported = importlib.import_module(module_name)
            for attribute_name in dir(imported):
                attribute = getattr(imported, attribute_name)
                if isinstance(attribute, type) and issubclass(attribute, ConnectorPort):
                    if attribute is ConnectorPort:
                        continue
                    if inspect.isabstract(attribute):
                        continue
                    if attribute.__module__ != imported.__name__:
                        continue
                    self.register(attribute)
