"""
Connectors Package
==================

Auto-discovers and registers all available connectors.
Import this package to trigger auto-discovery.
"""

from threat_hunting.infrastructure.connectors.base import BaseConnector
from threat_hunting.infrastructure.connectors.registry import ConnectorRegistry

__all__ = ["BaseConnector", "ConnectorRegistry"]
