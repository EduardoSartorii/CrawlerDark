"""Plugin system for auto-discovery of connectors and engines."""

from .registry import ConnectorRegistry, ConnectorRegistryError

__all__ = ["ConnectorRegistry", "ConnectorRegistryError"]
