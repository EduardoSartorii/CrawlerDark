"""Plugin discovery services for connectors and future extensibility points."""

from __future__ import annotations

from threat_hunting.core.plugin import ConnectorRegistry
from threat_hunting.infrastructure.config import AppSettings


def build_registry(settings: AppSettings, registry: ConnectorRegistry) -> ConnectorRegistry:
    """Discover connectors and filter by enabled configuration."""
    registry.autodiscover("threat_hunting.connectors")
    if not settings.enabled_connectors:
        return registry

    disabled = {
        connector_name
        for connector_name, enabled in settings.enabled_connectors.items()
        if not enabled
    }
    for connector_name in list(registry.names()):
        if connector_name in disabled:
            registry._types.pop(connector_name, None)  # noqa: SLF001
    return registry
