"""ConnectorFactory.

Responsibility
--------------
Thin Factory that builds a fully-wired :class:`ConnectorRegistry` from platform
settings (OPSEC profiles + enable/disable overrides). Keeping construction here
means callers (DI container, CLI) never assemble the registry by hand.
"""

from __future__ import annotations

from threat_hunting.infrastructure.connectors.registry import ConnectorRegistry
from threat_hunting.infrastructure.opsec.manager import OpsecManager


class ConnectorFactory:
    """Builds a ready-to-use connector registry."""

    @staticmethod
    def build(
        opsec: OpsecManager | None = None,
        enabled_overrides: dict[str, bool] | None = None,
    ) -> ConnectorRegistry:
        """Return a discovered registry wired with the given OPSEC manager."""
        registry = ConnectorRegistry(opsec=opsec, enabled_overrides=enabled_overrides)
        registry.discover()
        return registry
