"""Connector registry with automatic discovery (Plugin pattern).

Responsibility
--------------
Discover every available connector without the core knowing about any specific
source. Discovery happens from three places, in order:

1. The built-in connectors package (``connectors.builtins``).
2. External plugin packages dropped into ``threat_hunting.plugins``.
3. setuptools *entry points* in the ``threat_hunting.connectors`` group, so
   third parties can ship connectors as separate pip packages.

The registry then acts as a **Factory**, instantiating connectors on demand with
their configuration and the OPSEC transport factory injected.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from collections.abc import Iterable
from types import ModuleType

from threat_hunting.core.application.ports.transport import TransportFactoryPort
from threat_hunting.infrastructure.config.settings import PlatformSettings
from threat_hunting.infrastructure.connectors.base import BaseConnector


class ConnectorRegistry:
    """Discovers and instantiates connectors (Plugin + Factory)."""

    def __init__(
        self,
        *,
        settings: PlatformSettings,
        transport_factory: TransportFactoryPort | None = None,
    ) -> None:
        self._settings = settings
        self._transport_factory = transport_factory
        self._classes: dict[str, type[BaseConnector]] = {}
        self._disabled_overrides: set[str] = set()

    # -- discovery ---------------------------------------------------------

    def discover(self) -> "ConnectorRegistry":
        """Populate the registry from all discovery sources. Idempotent."""
        self._classes.clear()
        from threat_hunting.infrastructure.connectors import builtins as builtins_pkg
        from threat_hunting import plugins as plugins_pkg

        for module in self._iter_submodules(builtins_pkg):
            self._register_from_module(module)
        for module in self._iter_submodules(plugins_pkg):
            self._register_from_module(module)
        self._register_from_entry_points()
        return self

    @staticmethod
    def _iter_submodules(package: ModuleType) -> Iterable[ModuleType]:
        """Yield every importable submodule of a package."""
        if not hasattr(package, "__path__"):
            return
        for info in pkgutil.iter_modules(package.__path__):
            if info.name.startswith("_"):
                continue
            try:
                yield importlib.import_module(f"{package.__name__}.{info.name}")
            except Exception:  # noqa: BLE001 - a broken plugin must not break all
                continue

    def _register_from_module(self, module: ModuleType) -> None:
        """Register every concrete ``BaseConnector`` subclass in a module."""
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if (
                issubclass(obj, BaseConnector)
                and obj is not BaseConnector
                and not inspect.isabstract(obj)
                and obj.__module__ == module.__name__
            ):
                self.register(obj)

    def _register_from_entry_points(self) -> None:
        """Register connectors advertised via setuptools entry points."""
        try:
            from importlib.metadata import entry_points

            eps = entry_points(group="threat_hunting.connectors")
        except Exception:  # noqa: BLE001 - metadata may be unavailable
            return
        for ep in eps:
            try:
                obj = ep.load()
            except Exception:  # noqa: BLE001
                continue
            if inspect.isclass(obj) and issubclass(obj, BaseConnector):
                self.register(obj)

    # -- registration & querying -------------------------------------------

    def register(self, connector_cls: type[BaseConnector]) -> None:
        """Register a connector class by its ``name``."""
        self._classes[connector_cls.name] = connector_cls

    def names(self, *, include_disabled: bool = False) -> list[str]:
        """Return connector names, filtering disabled ones by default."""
        return sorted(
            name
            for name in self._classes
            if include_disabled or self.is_enabled(name)
        )

    def is_enabled(self, name: str) -> bool:
        """Whether a connector is enabled (config + runtime overrides)."""
        if name in self._disabled_overrides:
            return False
        return self._settings.connector_settings(name).enabled

    def enable(self, name: str) -> None:
        """Runtime-enable a connector (clears a runtime disable override)."""
        self._require(name)
        self._disabled_overrides.discard(name)

    def disable(self, name: str) -> None:
        """Runtime-disable a connector for this process."""
        self._require(name)
        self._disabled_overrides.add(name)

    def create(self, name: str) -> BaseConnector:
        """Instantiate a connector with its settings + transport injected."""
        connector_cls = self._require(name)
        return connector_cls(
            transport_factory=self._transport_factory,
            settings=self._settings.connector_settings(name),
        )

    def enabled_connectors(self) -> list[str]:
        """Return the names of all enabled connectors."""
        return self.names(include_disabled=False)

    def _require(self, name: str) -> type[BaseConnector]:
        if name not in self._classes:
            raise KeyError(name)
        return self._classes[name]
