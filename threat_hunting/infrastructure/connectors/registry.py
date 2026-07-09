"""ConnectorRegistry: automatic connector discovery (Plugin Pattern).

Responsibility
--------------
Discover every :class:`BaseConnector` subclass without a hand-maintained list.
Two discovery mechanisms are supported:

1. **Package scan** — import every module under
   :mod:`threat_hunting.infrastructure.connectors.sources` and collect the
   concrete ``BaseConnector`` subclasses found.
2. **Entry points** — third-party packages can register connectors under the
   ``threat_hunting.connectors`` entry-point group, so connectors can ship as
   separate installable plugins that never touch the core.

The registry also applies runtime enable/disable overrides and builds
connectors with their OPSEC transport (Factory collaboration).
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from collections.abc import Sequence

from threat_hunting.core.application.ports.connector import ConnectorMeta, ConnectorPort
from threat_hunting.core.domain.exceptions import (
    ConnectorDisabledError,
    ConnectorNotFoundError,
)
from threat_hunting.infrastructure.connectors.base import BaseConnector
from threat_hunting.infrastructure.opsec.manager import OpsecManager

_ENTRY_POINT_GROUP = "threat_hunting.connectors"


class ConnectorRegistry:
    """Discovers, enables/disables and instantiates connectors."""

    def __init__(
        self,
        opsec: OpsecManager | None = None,
        *,
        enabled_overrides: dict[str, bool] | None = None,
        sources_package: str = "threat_hunting.infrastructure.connectors.sources",
    ) -> None:
        self._opsec = opsec or OpsecManager(offline=True)
        self._overrides = dict(enabled_overrides or {})
        self._sources_package = sources_package
        self._classes: dict[str, type[BaseConnector]] = {}
        self._discovered = False

    # -- discovery --------------------------------------------------------
    def discover(self) -> None:
        """Populate the class map from the package scan + entry points (idempotent)."""
        if self._discovered:
            return
        self._discover_package()
        self._discover_entry_points()
        self._discovered = True

    def _register_class(self, cls: type[BaseConnector]) -> None:
        meta = getattr(cls, "meta", None)
        if not isinstance(meta, ConnectorMeta):
            return
        if inspect.isabstract(cls):
            return
        self._classes[meta.name] = cls

    def _discover_package(self) -> None:
        try:
            package = importlib.import_module(self._sources_package)
        except ModuleNotFoundError:
            return
        for module_info in pkgutil.iter_modules(package.__path__):
            module = importlib.import_module(f"{self._sources_package}.{module_info.name}")
            for _, obj in inspect.getmembers(module, inspect.isclass):
                if issubclass(obj, BaseConnector) and obj is not BaseConnector:
                    self._register_class(obj)

    def _discover_entry_points(self) -> None:
        try:
            from importlib.metadata import entry_points
        except ImportError:  # pragma: no cover - Python < 3.10 only
            return
        try:
            eps = entry_points(group=_ENTRY_POINT_GROUP)
        except TypeError:  # pragma: no cover - very old importlib.metadata
            eps = entry_points().get(_ENTRY_POINT_GROUP, [])  # type: ignore[attr-defined]
        for ep in eps:
            try:
                obj = ep.load()
            except Exception:  # a broken plugin must not break discovery
                continue
            if inspect.isclass(obj) and issubclass(obj, BaseConnector):
                self._register_class(obj)

    # -- queries ----------------------------------------------------------
    def _effective_meta(self, cls: type[BaseConnector]) -> ConnectorMeta:
        """Return the connector meta with runtime enable/disable overrides applied."""
        meta = cls.meta
        assert meta is not None  # guaranteed by _register_class
        if meta.name in self._overrides:
            return meta.model_copy(update={"enabled": self._overrides[meta.name]})
        return meta

    def all(self) -> Sequence[ConnectorMeta]:
        """Return metadata for every discovered connector."""
        self.discover()
        return [self._effective_meta(cls) for cls in self._classes.values()]

    def get(self, name: str) -> ConnectorPort:
        """Instantiate the connector ``name`` with its OPSEC transport."""
        self.discover()
        cls = self._classes.get(name)
        if cls is None:
            raise ConnectorNotFoundError(f"No connector registered under '{name}'.")
        meta = self._effective_meta(cls)
        if not meta.enabled:
            raise ConnectorDisabledError(f"Connector '{name}' is disabled.")
        transport = self._opsec.transport_for(name)
        return cls(transport=transport)

    def by_group(self, group: str) -> Sequence[ConnectorPort]:
        """Instantiate every enabled connector belonging to ``group``."""
        self.discover()
        result: list[ConnectorPort] = []
        for name, cls in self._classes.items():
            meta = self._effective_meta(cls)
            if group in meta.groups and meta.enabled:
                transport = self._opsec.transport_for(name)
                result.append(cls(transport=transport))
        return result

    def set_enabled(self, name: str, enabled: bool) -> None:
        """Override the enabled flag for a connector at runtime."""
        self._overrides[name] = enabled
