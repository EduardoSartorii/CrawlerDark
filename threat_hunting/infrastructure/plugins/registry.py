"""
Connector Plugin Registry.

Auto-discovers and manages all BaseConnector subclasses.
Implements the Plugin Pattern — new connectors are registered automatically
by virtue of being imported/installed, without modifying any existing code.

Discovery Mechanism:
    1. Scans the connectors package for all subclasses of BaseConnector
    2. Validates required class attributes (connector_id, source_type)
    3. Registers them by connector_id
    4. Provides factory methods for instantiation

Design Patterns:
    - Plugin Pattern: self-registering components
    - Factory Pattern: connector instantiation
    - Registry Pattern: centralized lookup

Architecture Note:
    The registry lives in infrastructure, not core.
    Core uses the CollectorRegistryPort (protocol) defined in application layer.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from pathlib import Path
from typing import Any, Type

import structlog

from ..connectors.base import BaseConnector
from ...core.domain.value_objects.source_type import SourceType
from ..opsec.profiles import OpsecProfile

logger = structlog.get_logger(__name__)


class ConnectorRegistryError(Exception):
    """Raised on registry configuration errors."""


class ConnectorRegistry:
    """
    Central registry for all connector classes.

    Usage:
        registry = ConnectorRegistry.create()
        connector = registry.get_connector("reddit", config={...})
        findings = await connector.run(run_id="...")
    """

    def __init__(self) -> None:
        self._registry: dict[str, type[BaseConnector]] = {}
        self._enabled: set[str] = set()
        self._configs: dict[str, dict[str, Any]] = {}
        self._profiles: dict[str, OpsecProfile] = {}

    @classmethod
    def create(cls) -> "ConnectorRegistry":
        """
        Create a registry and auto-discover all connectors.
        This is the primary factory method.
        """
        registry = cls()
        registry.autodiscover()
        return registry

    def autodiscover(self) -> None:
        """
        Auto-discover all BaseConnector subclasses in the connectors package.

        Scans the connectors directory and imports all modules.
        Any class that:
            - Inherits from BaseConnector
            - Is not abstract
            - Has a non-empty connector_id
        is registered automatically.
        """
        connectors_path = Path(__file__).parent.parent / "connectors"
        package_name = "threat_hunting.infrastructure.connectors"

        logger.debug("registry.autodiscover", path=str(connectors_path))

        for module_info in pkgutil.iter_modules([str(connectors_path)]):
            if module_info.name.startswith("_"):
                continue
            try:
                module = importlib.import_module(f"{package_name}.{module_info.name}")
                self._scan_module(module)
            except Exception as exc:
                logger.warning(
                    "registry.import_failed",
                    module=module_info.name,
                    error=str(exc),
                )

        logger.info(
            "registry.discovered",
            count=len(self._registry),
            connectors=list(self._registry.keys()),
        )

    def _scan_module(self, module: Any) -> None:
        """Scan a module for BaseConnector subclasses."""
        for name, obj in inspect.getmembers(module, inspect.isclass):
            if (
                obj is not BaseConnector
                and issubclass(obj, BaseConnector)
                and not inspect.isabstract(obj)
                and obj.connector_id
            ):
                self.register(obj)

    def register(self, connector_class: type[BaseConnector]) -> None:
        """Manually register a connector class."""
        connector_id = connector_class.connector_id
        if not connector_id:
            raise ConnectorRegistryError(
                f"{connector_class.__name__} has no connector_id"
            )
        if connector_id in self._registry:
            logger.debug("registry.overwrite", connector_id=connector_id)

        self._registry[connector_id] = connector_class
        if connector_class.is_enabled:
            self._enabled.add(connector_id)

        logger.debug(
            "registry.registered",
            connector_id=connector_id,
            class_name=connector_class.__name__,
            group=connector_class.group,
        )

    def get_class(self, connector_id: str) -> type[BaseConnector]:
        """Get the connector class by ID."""
        if connector_id not in self._registry:
            raise ConnectorRegistryError(f"Connector '{connector_id}' not found")
        return self._registry[connector_id]

    def create_connector(
        self,
        connector_id: str,
        config: dict[str, Any] | None = None,
        profile: OpsecProfile | None = None,
    ) -> BaseConnector:
        """
        Factory: instantiate a connector by ID with optional config and OPSEC profile.
        """
        cls = self.get_class(connector_id)
        merged_config = {**self._configs.get(connector_id, {}), **(config or {})}
        resolved_profile = profile or self._profiles.get(connector_id) or OpsecProfile.default()
        return cls(profile=resolved_profile, config=merged_config)

    def enable(self, connector_id: str) -> None:
        if connector_id not in self._registry:
            raise ConnectorRegistryError(f"Connector '{connector_id}' not found")
        self._enabled.add(connector_id)
        logger.info("connector.enabled", connector_id=connector_id)

    def disable(self, connector_id: str) -> None:
        self._enabled.discard(connector_id)
        logger.info("connector.disabled", connector_id=connector_id)

    def is_enabled(self, connector_id: str) -> bool:
        return connector_id in self._enabled

    def get_enabled_connector_ids(self, group: str | None = None) -> list[str]:
        """Return IDs of enabled connectors, optionally filtered by group."""
        enabled = list(self._enabled)
        if group:
            enabled = [
                cid for cid in enabled
                if self._registry[cid].group == group
            ]
        return sorted(enabled)

    def get_all_connector_ids(self) -> list[str]:
        return sorted(self._registry.keys())

    def configure(
        self,
        connector_id: str,
        config: dict[str, Any],
        profile: OpsecProfile | None = None,
    ) -> None:
        """Set persistent config and optional OPSEC profile for a connector."""
        self._configs[connector_id] = config
        if profile:
            self._profiles[connector_id] = profile

    def list_connectors(self) -> list[dict[str, Any]]:
        """Return summary of all registered connectors."""
        return [
            {
                "connector_id": cid,
                "class": cls.__name__,
                "group": cls.group,
                "source_type": cls.source_type,
                "description": cls.description,
                "enabled": cid in self._enabled,
                "version": cls.version,
            }
            for cid, cls in sorted(self._registry.items())
        ]

    def __len__(self) -> int:
        return len(self._registry)

    def __contains__(self, connector_id: str) -> bool:
        return connector_id in self._registry
