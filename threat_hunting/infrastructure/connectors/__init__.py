"""Conectores plugáveis.

Novos conectores basta herdarem ``BaseConnector`` e serem registrados via
``@register_connector("nome")``. Auto-discovery ocorre em
``ConnectorRegistry.discover()``.
"""

from .base import BaseConnector
from .factory import ConnectorFactory
from .registry import ConnectorRegistry, register_connector

__all__ = ["BaseConnector", "ConnectorFactory", "ConnectorRegistry", "register_connector"]
