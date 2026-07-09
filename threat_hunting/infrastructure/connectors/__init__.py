"""Connector SDK and auto-discovery registry.

New data sources are added by subclassing :class:`BaseConnector` and dropping
the module in this package (or shipping it as an entry-point plugin). The
:class:`ConnectorRegistry` discovers them automatically — no central list to
edit — honouring the Open/Closed Principle and the Plugin Pattern.
"""

from threat_hunting.infrastructure.connectors.base import BaseConnector
from threat_hunting.infrastructure.connectors.registry import ConnectorRegistry
from threat_hunting.infrastructure.connectors.factory import ConnectorFactory

__all__ = ["BaseConnector", "ConnectorRegistry", "ConnectorFactory"]
