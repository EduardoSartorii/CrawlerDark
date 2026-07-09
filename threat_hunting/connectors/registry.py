"""Connector discovery and factory registry."""

from __future__ import annotations

from importlib import import_module
from importlib.metadata import entry_points
from typing import Any

from threat_hunting.connectors.base import BaseConnector
from threat_hunting.connectors.builtins import BUILTIN_CONNECTORS


class ConnectorRegistry:
    """Discover, register, and instantiate connector plugins."""

    def __init__(
        self,
        connector_configs: dict[str, dict[str, Any]] | None = None,
        transport_factory: Any | None = None,
    ) -> None:
        self.connector_configs = connector_configs or {}
        self.transport_factory = transport_factory
        self._classes: dict[str, type[BaseConnector]] = {}
        self._enabled_overrides: dict[str, bool] = {}

    def discover(self, modules: list[str] | None = None) -> "ConnectorRegistry":
        """Load built-ins, Python modules, and package entry points."""

        for connector_cls in BUILTIN_CONNECTORS:
            self.register(connector_cls)
        for module_name in modules or []:
            module = import_module(module_name)
            for value in vars(module).values():
                if isinstance(value, type) and issubclass(value, BaseConnector) and value is not BaseConnector:
                    self.register(value)
        for entry_point in entry_points(group="threat_hunting.connectors"):
            self.register(entry_point.load())
        return self

    def register(self, connector_cls: type[BaseConnector]) -> None:
        """Register a connector class by its declared name."""

        self._classes[connector_cls.name] = connector_cls

    def names(self) -> list[str]:
        """Return registered connector names."""

        return sorted(self._classes)

    def set_enabled(self, connector_name: str, enabled: bool) -> None:
        """Apply runtime enabled state."""

        if connector_name not in self._classes:
            raise KeyError(f"unknown connector: {connector_name}")
        self._enabled_overrides[connector_name] = enabled

    def create(self, connector_name: str) -> BaseConnector:
        """Instantiate a connector using configured OPSEC transport profile."""

        connector_cls = self._classes[connector_name]
        config = self.connector_configs.get(connector_name, {})
        transport = self.transport_factory(connector_name, config) if self.transport_factory else None
        connector = connector_cls(config=config, transport=transport)
        if connector_name in self._enabled_overrides:
            connector.enabled = self._enabled_overrides[connector_name]
        return connector

    def resolve(self, target: str) -> list[BaseConnector]:
        """Resolve connector by exact name, group name, or ``all``."""

        if target in self._classes:
            connector = self.create(target)
            return [connector] if connector.enabled else []
        connectors: list[BaseConnector] = []
        for name, connector_cls in sorted(self._classes.items()):
            connector = self.create(name)
            if connector.enabled and (target == "all" or target in connector_cls.groups):
                connectors.append(connector)
        if not connectors and target != "all":
            raise KeyError(f"unknown connector or group: {target}")
        return connectors
