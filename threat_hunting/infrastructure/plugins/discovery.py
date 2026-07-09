"""Connector plugin discovery and registry.

Auto-discovers connectors via entry points and manual registration.
"""

from __future__ import annotations

import importlib
import pkgutil
from typing import Any

import structlog

from threat_hunting.core.domain.exceptions import ConnectorNotFoundError
from threat_hunting.infrastructure.connectors.base import BaseConnector

logger = structlog.get_logger(__name__)


class ConnectorRegistry:
    """Plugin registry for connector auto-discovery.

    Uses the Plugin pattern: new connectors are discovered automatically
    without modifying core or pipeline code.
    """

    def __init__(self) -> None:
        self._connectors: dict[str, type[BaseConnector]] = {}
        self._instances: dict[str, BaseConnector] = {}

    def register(self, connector_cls: type[BaseConnector]) -> None:
        """Register a connector class."""
        self._connectors[connector_cls.name] = connector_cls
        logger.debug("connector.registered", name=connector_cls.name)

    def get(self, name: str) -> BaseConnector:
        """Get or instantiate a connector by name."""
        if name not in self._connectors:
            raise ConnectorNotFoundError(f"Connector not found: {name}")
        if name not in self._instances:
            self._instances[name] = self._connectors[name]()
        return self._instances[name]

    def list_names(self) -> list[str]:
        """List all registered connector names."""
        return sorted(self._connectors.keys())

    def discover(self, package_name: str = "threat_hunting.infrastructure.connectors") -> int:
        """Auto-discover connectors in package submodules."""
        discovered = 0
        try:
            package = importlib.import_module(package_name)
            for _, module_name, _ in pkgutil.iter_modules(package.__path__, package.__name__ + "."):
                if module_name.endswith(".base"):
                    continue
                try:
                    module = importlib.import_module(module_name)
                    for attr_name in dir(module):
                        attr = getattr(module, attr_name)
                        if (
                            isinstance(attr, type)
                            and issubclass(attr, BaseConnector)
                            and attr is not BaseConnector
                            and hasattr(attr, "name")
                        ):
                            self.register(attr)
                            discovered += 1
                except ImportError as exc:
                    logger.warning("connector.discovery.failed", module=module_name, error=str(exc))
        except ImportError as exc:
            logger.warning("connector.package.not_found", package=package_name, error=str(exc))
        return discovered

    def create_with_config(self, name: str, transport: Any = None, config: dict[str, Any] | None = None) -> BaseConnector:
        """Factory method for connector instantiation with DI."""
        if name not in self._connectors:
            raise ConnectorNotFoundError(f"Connector not found: {name}")
        return self._connectors[name](transport=transport, config=config)
