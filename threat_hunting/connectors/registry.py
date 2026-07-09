"""Connector Registry & Factory — Plugin + Factory Patterns.

Responsibility
--------------
Auto-discover BaseConnector subclasses under threat_hunting.connectors.*
and instantiate them by name. Core is never modified when adding connectors.
"""

from __future__ import annotations

import importlib
import pkgutil
from typing import Any, Sequence

import structlog

from threat_hunting.connectors.base import BaseConnector
from threat_hunting.core.application.ports import (
    ConnectorFactoryPort,
    ConnectorPort,
    OpsecTransportPort,
)
from threat_hunting.core.domain.value_objects import OpsecProfile

logger = structlog.get_logger(__name__)


class ConnectorRegistry:
    """Plugin registry — discovers and holds connector classes."""

    def __init__(self) -> None:
        self._classes: dict[str, type[BaseConnector]] = {}

    def register(self, cls: type[BaseConnector]) -> None:
        if not getattr(cls, "name", None) or cls.name == "base":
            return
        self._classes[cls.name] = cls
        logger.debug("connector.registered", name=cls.name, group=cls.category_group)

    def get(self, name: str) -> type[BaseConnector] | None:
        return self._classes.get(name)

    def list_names(self) -> list[str]:
        return sorted(self._classes.keys())

    def list_by_group(self, group: str) -> list[str]:
        return sorted(n for n, c in self._classes.items() if c.category_group == group)

    def discover(self, package_name: str = "threat_hunting.connectors") -> int:
        """Import all submodules to trigger registration via decorators / subclass scan."""
        package = importlib.import_module(package_name)
        count_before = len(self._classes)
        for module_info in pkgutil.walk_packages(package.__path__, package.__name__ + "."):
            if module_info.name.endswith(".base") or module_info.name.endswith(".registry"):
                continue
            try:
                mod = importlib.import_module(module_info.name)
                for attr_name in dir(mod):
                    attr = getattr(mod, attr_name)
                    if (
                        isinstance(attr, type)
                        and issubclass(attr, BaseConnector)
                        and attr is not BaseConnector
                        and getattr(attr, "name", "base") != "base"
                    ):
                        self.register(attr)
            except Exception as exc:
                logger.warning("connector.discover_error", module=module_info.name, error=str(exc))
        discovered = len(self._classes) - count_before
        logger.info("connector.discovery_complete", total=len(self._classes), new=discovered)
        return len(self._classes)


# Global registry singleton (populated at DI bootstrap)
_REGISTRY = ConnectorRegistry()


def get_registry() -> ConnectorRegistry:
    return _REGISTRY


def register_connector(cls: type[BaseConnector]) -> type[BaseConnector]:
    """Decorator to explicitly register a connector class."""
    _REGISTRY.register(cls)
    return cls


class ConnectorFactory(ConnectorFactoryPort):
    """Factory Pattern — create connector instances with OPSEC binding."""

    def __init__(
        self,
        *,
        registry: ConnectorRegistry | None = None,
        transport: OpsecTransportPort | None = None,
        opsec_profiles: dict[str, OpsecProfile] | None = None,
        enabled: set[str] | None = None,
    ) -> None:
        self._registry = registry or get_registry()
        self._transport = transport
        self._opsec_profiles = opsec_profiles or {}
        self._enabled = enabled  # None = all enabled

    def create(self, name: str, **options: Any) -> ConnectorPort:
        cls = self._registry.get(name)
        if cls is None:
            # Attempt discovery then retry
            self._registry.discover()
            cls = self._registry.get(name)
        if cls is None:
            raise KeyError(f"Unknown connector: {name}. Available: {self.list_available()}")
        if self._enabled is not None and name not in self._enabled:
            raise PermissionError(f"Connector '{name}' is disabled")

        profile_name = options.pop("opsec_profile", None) or cls.opsec_profile_name
        profile = self._opsec_profiles.get(profile_name) or OpsecProfile(name=profile_name)
        return cls(transport=self._transport, opsec_profile=profile, options=options)

    def list_available(self) -> Sequence[str]:
        names = self._registry.list_names()
        if not names:
            self._registry.discover()
            names = self._registry.list_names()
        if self._enabled is not None:
            return [n for n in names if n in self._enabled]
        return names

    def list_by_group(self, group: str) -> Sequence[str]:
        if not self._registry.list_names():
            self._registry.discover()
        names = self._registry.list_by_group(group)
        if self._enabled is not None:
            return [n for n in names if n in self._enabled]
        return names


__all__ = [
    "ConnectorRegistry",
    "ConnectorFactory",
    "get_registry",
    "register_connector",
]
