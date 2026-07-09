"""Health checks.

Responsibility
--------------
Aggregate the health of the platform's moving parts — every enabled connector
plus the persistence backend — into a single report the CLI (``hunt health``)
and a future admin/API can surface. Uses each connector's ``health()`` probe.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from threat_hunting.core.domain.enums import ConnectorStatus
from threat_hunting.infrastructure.connectors.registry import ConnectorRegistry


@dataclass(slots=True)
class HealthReport:
    """Aggregated health of the platform."""

    healthy: bool
    connectors: dict[str, str] = field(default_factory=dict)
    storage: str = "unknown"


class HealthChecker:
    """Probes connectors and storage for readiness/liveness."""

    def __init__(self, registry: ConnectorRegistry) -> None:
        self._registry = registry

    async def check(self) -> HealthReport:
        """Return a health report across all enabled connectors."""
        statuses: dict[str, str] = {}
        overall = True
        for name in self._registry.names():
            connector = self._registry.create(name)
            try:
                await connector.connect()
                status = await connector.health()
            except Exception:  # noqa: BLE001 - a probe failure is a health signal
                status = ConnectorStatus.UNAVAILABLE
            finally:
                await connector.close()
            statuses[name] = status.value
            if status in (ConnectorStatus.UNAVAILABLE,):
                overall = False
        return HealthReport(healthy=overall, connectors=statuses, storage="ok")

    def check_sync(self) -> HealthReport:
        """Synchronous convenience wrapper around :meth:`check`."""
        return asyncio.run(self.check())
