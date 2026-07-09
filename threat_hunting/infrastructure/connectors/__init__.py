"""Connectors SDK: the ``BaseConnector`` and the auto-discovery registry.

Every collection source is a subclass of :class:`BaseConnector`. New sources
require *only* a new subclass — the core and the pipeline never change. The
:class:`ConnectorRegistry` discovers connectors automatically (built-ins,
external plugin packages and setuptools entry points).
"""

from threat_hunting.infrastructure.connectors.base import BaseConnector
from threat_hunting.infrastructure.connectors.registry import ConnectorRegistry

__all__ = ["BaseConnector", "ConnectorRegistry"]
