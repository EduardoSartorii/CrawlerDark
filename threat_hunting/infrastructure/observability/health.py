"""
HealthChecker
=============

Checks the health of all platform components:
    - Database connectivity
    - Redis connectivity
    - Connector health (delegated to connector.health())
    - Exporter health (delegated to exporter.health())

Used by the CLI 'hunt health' command and (future) Django health endpoint.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from threat_hunting.infrastructure.connectors.base import BaseConnector
    from threat_hunting.infrastructure.exporters.base import BaseExporter
    from threat_hunting.infrastructure.database.session import DatabaseSession

logger = structlog.get_logger(__name__)


@dataclass
class ComponentHealth:
    """Health status of a single component."""

    name: str
    healthy: bool
    message: str = ""
    latency_ms: float = 0.0
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class PlatformHealth:
    """Aggregated health status of the full platform."""

    components: list[ComponentHealth] = field(default_factory=list)

    @property
    def is_healthy(self) -> bool:
        return all(c.healthy for c in self.components)

    @property
    def summary(self) -> str:
        healthy = sum(1 for c in self.components if c.healthy)
        return f"{healthy}/{len(self.components)} components healthy"


class HealthChecker:
    """Platform-wide health checker."""

    def __init__(self, db: "DatabaseSession | None" = None) -> None:
        self._db = db
        self._connectors: list["BaseConnector"] = []
        self._exporters: list["BaseExporter"] = []

    def register_connector(self, connector: "BaseConnector") -> None:
        self._connectors.append(connector)

    def register_exporter(self, exporter: "BaseExporter") -> None:
        self._exporters.append(exporter)

    async def check_all(self) -> PlatformHealth:
        """Run all health checks and return aggregated results."""
        health = PlatformHealth()

        # Database
        if self._db:
            health.components.append(await self._check_database())

        # Connectors
        for connector in self._connectors:
            health.components.append(await self._check_connector(connector))

        # Exporters
        for exporter in self._exporters:
            health.components.append(await self._check_exporter(exporter))

        return health

    async def _check_database(self) -> ComponentHealth:
        """Verify database is reachable."""
        import time
        start = time.perf_counter()
        try:
            assert self._db is not None
            async with self._db.session():
                pass
            latency = (time.perf_counter() - start) * 1000
            return ComponentHealth(name="database", healthy=True, latency_ms=latency)
        except Exception as exc:
            return ComponentHealth(name="database", healthy=False, message=str(exc))

    async def _check_connector(self, connector: "BaseConnector") -> ComponentHealth:
        """Delegate to connector.health()."""
        try:
            await connector.connect()
            status = await connector.health()
            await connector.close()
            return ComponentHealth(
                name=f"connector:{connector.connector_id}",
                healthy=status.healthy,
                message=status.message,
                latency_ms=status.latency_ms,
            )
        except Exception as exc:
            return ComponentHealth(
                name=f"connector:{connector.connector_id}",
                healthy=False,
                message=str(exc),
            )

    async def _check_exporter(self, exporter: "BaseExporter") -> ComponentHealth:
        """Delegate to exporter.health()."""
        try:
            healthy = await exporter.health()
            return ComponentHealth(
                name=f"exporter:{exporter.exporter_id}",
                healthy=healthy,
            )
        except Exception as exc:
            return ComponentHealth(
                name=f"exporter:{exporter.exporter_id}",
                healthy=False,
                message=str(exc),
            )
