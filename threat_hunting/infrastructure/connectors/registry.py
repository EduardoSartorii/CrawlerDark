"""
ConnectorRegistry — Plugin Auto-Discovery
==========================================

Implements the Plugin Pattern for connector management.
The registry:
    1. Scans the connectors/ directory for BaseConnector subclasses.
    2. Registers each connector by its connector_id.
    3. Provides factory methods for instantiating connectors.
    4. Supports enable/disable without touching connector code.

Auto-discovery rules:
    - Any Python module in any subdirectory of connectors/ that defines a
      class inheriting from BaseConnector with a non-empty connector_id is
      automatically registered on import.
    - Connectors do not need to register themselves explicitly.
    - External plugins (installed as packages) can also register via
      the 'threat_hunting.connectors' entry_point group.

Architecture:
    - The registry is a singleton managed by the DI container.
    - connector_id must be unique across all registered connectors.
    - Registration is idempotent — re-registering the same class is a no-op.
"""

from __future__ import annotations

import importlib
import importlib.metadata
import importlib.util
import inspect
import pkgutil
import sys
from pathlib import Path
from typing import Any, Type

import structlog

from threat_hunting.core.domain.exceptions.domain_exceptions import (
    ConnectorNotFoundError,
    DuplicateEntityError,
)
from threat_hunting.infrastructure.connectors.base import BaseConnector

logger = structlog.get_logger(__name__)


class ConnectorRegistry:
    """
    Singleton connector registry with auto-discovery.

    Usage:
        registry = ConnectorRegistry()
        registry.discover()          # auto-discover from filesystem
        connector_cls = registry.get("reddit")
        instance = registry.create("reddit", opsec_layer, config)
    """

    def __init__(self) -> None:
        self._registry: dict[str, Type[BaseConnector]] = {}
        self._disabled: set[str] = set()

    def register(self, connector_cls: Type[BaseConnector]) -> None:
        """Register a connector class.

        Args:
            connector_cls: A BaseConnector subclass with a non-empty connector_id.

        Raises:
            DuplicateEntityError: If a different class is already registered under the same id.
        """
        cid = connector_cls.connector_id
        if not cid:
            return
        if cid in self._registry and self._registry[cid] is not connector_cls:
            raise DuplicateEntityError("Connector", cid)
        if cid not in self._registry:
            self._registry[cid] = connector_cls
            logger.debug("connector_registered", connector_id=cid, cls=connector_cls.__name__)

    def discover(self, package_path: str | Path | None = None) -> int:
        """
        Auto-discover connectors by scanning the connectors package.

        Args:
            package_path: Override path for scanning. Defaults to this package's directory.

        Returns:
            Number of newly registered connectors.
        """
        if package_path is None:
            package_path = Path(__file__).parent

        before_count = len(self._registry)
        self._scan_directory(Path(package_path))

        # Also scan Python entry points (external plugins).
        self._discover_entry_points()

        registered = len(self._registry) - before_count
        logger.info("connector_discovery_complete", total_registered=len(self._registry))
        return registered

    def _scan_directory(self, directory: Path) -> None:
        """Recursively scan a directory for BaseConnector subclasses."""
        for path in directory.rglob("*.py"):
            if path.stem.startswith("_") or path.stem in ("base", "registry"):
                continue
            module_name = self._path_to_module(path)
            if module_name:
                self._load_module(module_name)

    def _path_to_module(self, path: Path) -> str | None:
        """Convert a filesystem path to a Python module name."""
        try:
            # Find the package root (threat_hunting/)
            parts = path.parts
            if "threat_hunting" in parts:
                idx = list(parts).index("threat_hunting")
                module_parts = list(parts[idx:])
                module_name = ".".join(module_parts).removesuffix(".py")
                return module_name
        except Exception:
            pass
        return None

    def _load_module(self, module_name: str) -> None:
        """Import a module and register any BaseConnector subclasses found."""
        try:
            if module_name in sys.modules:
                module = sys.modules[module_name]
            else:
                module = importlib.import_module(module_name)
            for _name, obj in inspect.getmembers(module, inspect.isclass):
                if (
                    issubclass(obj, BaseConnector)
                    and obj is not BaseConnector
                    and obj.connector_id
                ):
                    try:
                        self.register(obj)
                    except Exception as exc:
                        logger.warning(
                            "connector_registration_failed",
                            cls=obj.__name__,
                            error=str(exc),
                        )
        except ImportError as exc:
            logger.debug("module_import_skipped", module=module_name, reason=str(exc))
        except Exception as exc:
            logger.warning("module_scan_error", module=module_name, error=str(exc))

    def _discover_entry_points(self) -> None:
        """Discover connectors registered as entry points (external plugins)."""
        try:
            eps = importlib.metadata.entry_points(group="threat_hunting.connectors")
            for ep in eps:
                try:
                    cls = ep.load()
                    if inspect.isclass(cls) and issubclass(cls, BaseConnector):
                        self.register(cls)
                except Exception as exc:
                    logger.warning(
                        "entry_point_load_failed",
                        entry_point=ep.name,
                        error=str(exc),
                    )
        except Exception:
            pass

    def get(self, connector_id: str) -> Type[BaseConnector]:
        """Return the connector class for the given ID.

        Raises:
            ConnectorNotFoundError: If not registered.
        """
        if connector_id not in self._registry:
            raise ConnectorNotFoundError(
                f"Connector {connector_id!r} is not registered",
                context={"available": list(self._registry)},
            )
        return self._registry[connector_id]

    def create(
        self,
        connector_id: str,
        opsec_layer: Any,
        config: dict[str, Any] | None = None,
        opsec_profile: str = "standard",
    ) -> BaseConnector:
        """Instantiate and return a connector.

        Args:
            connector_id: The connector's ID.
            opsec_layer: Injected OPSEC layer instance.
            config: Connector-specific configuration dict.
            opsec_profile: OPSEC profile name to use.

        Returns:
            An initialized connector instance.
        """
        cls = self.get(connector_id)
        return cls(opsec_layer=opsec_layer, config=config, opsec_profile=opsec_profile)

    def enable(self, connector_id: str) -> None:
        """Enable a connector."""
        self._disabled.discard(connector_id)
        logger.info("connector_enabled", connector_id=connector_id)

    def disable(self, connector_id: str) -> None:
        """Disable a connector (still registered but not run by scheduler)."""
        self._disabled.add(connector_id)
        logger.info("connector_disabled", connector_id=connector_id)

    def is_enabled(self, connector_id: str) -> bool:
        return connector_id not in self._disabled

    def list_all(self) -> list[dict[str, str]]:
        """Return a summary list of all registered connectors."""
        return [
            {
                "connector_id": cid,
                "name": cls.connector_name,
                "source_type": cls.source_type,
                "enabled": str(cid not in self._disabled),
            }
            for cid, cls in self._registry.items()
        ]

    @property
    def registered_ids(self) -> list[str]:
        return list(self._registry)

    def __len__(self) -> int:
        return len(self._registry)

    def __repr__(self) -> str:
        return f"ConnectorRegistry(registered={len(self._registry)}, disabled={len(self._disabled)})"
