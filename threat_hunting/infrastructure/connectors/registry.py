"""Registry global de conectores + auto-discovery.

Padrões aplicados:
* **Registry**: coleção nomeada de classes.
* **Plugin**: importar o módulo já registra a classe via decorator.

Uso::

    @register_connector("threatfox")
    class ThreatFoxConnector(BaseConnector):
        ...

    ConnectorRegistry.discover()
    cls = ConnectorRegistry.get("threatfox")
"""

from __future__ import annotations

import importlib
import pkgutil
from collections.abc import Callable
from typing import ClassVar

from ...core.domain.exceptions import ConnectorNotFoundError
from .base import BaseConnector

ConnectorClass = type[BaseConnector]


class ConnectorRegistry:
    """Registry singleton (via classe stateless com ``ClassVar``)."""

    _registry: ClassVar[dict[str, ConnectorClass]] = {}

    @classmethod
    def register(cls, name: str, connector_cls: ConnectorClass) -> None:
        key = name.strip().lower()
        if not key:
            raise ValueError("Connector name cannot be empty")
        if key in cls._registry and cls._registry[key] is not connector_cls:
            # Idempotência: mesmo nome → mesma classe é OK; conflito é erro.
            raise ValueError(f"Connector name already registered: {name}")
        cls._registry[key] = connector_cls

    @classmethod
    def get(cls, name: str) -> ConnectorClass:
        key = name.strip().lower()
        if key not in cls._registry:
            raise ConnectorNotFoundError(f"Connector not found: {name}")
        return cls._registry[key]

    @classmethod
    def names(cls) -> list[str]:
        return sorted(cls._registry.keys())

    @classmethod
    def all(cls) -> dict[str, ConnectorClass]:
        return dict(cls._registry)

    @classmethod
    def clear(cls) -> None:
        cls._registry.clear()

    @classmethod
    def discover(cls, package: str = "threat_hunting.infrastructure.connectors.implementations") -> None:
        """Importa todos os módulos do pacote para acionar decorators de registro."""
        try:
            module = importlib.import_module(package)
        except ModuleNotFoundError:
            return
        if not hasattr(module, "__path__"):
            return
        for _, modname, _ in pkgutil.iter_modules(module.__path__):
            importlib.import_module(f"{package}.{modname}")


def register_connector(name: str) -> Callable[[ConnectorClass], ConnectorClass]:
    """Decorator que registra a classe no ``ConnectorRegistry``."""

    def wrapper(cls: ConnectorClass) -> ConnectorClass:
        cls.name = name
        ConnectorRegistry.register(name, cls)
        return cls

    return wrapper
