"""Plugin manager for auto-discovery of connectors.

Implements plugin pattern by scanning connector package for BaseConnector subclasses.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from typing import TypeVar

from threat_hunting.connectors.base import BaseConnector

T = TypeVar("T", bound=BaseConnector)


class ConnectorPluginManager:
    """Discovers connectors automatically without core changes."""

    def __init__(self, package_name: str = "threat_hunting.connectors") -> None:
        self._package_name = package_name

    def discover(self) -> dict[str, type[BaseConnector]]:
        """Discover all concrete connector classes."""
        package = importlib.import_module(self._package_name)
        registry: dict[str, type[BaseConnector]] = {}
        for module_info in pkgutil.iter_modules(package.__path__, prefix=f"{self._package_name}."):
            module = importlib.import_module(module_info.name)
            for _, obj in inspect.getmembers(module, inspect.isclass):
                if not issubclass(obj, BaseConnector) or obj is BaseConnector:
                    continue
                if obj.__module__ != module.__name__:
                    continue
                registry[obj.name.lower()] = obj
        return registry
