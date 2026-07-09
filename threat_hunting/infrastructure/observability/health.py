"""Health checks.

Responsibility
--------------
Aggregate the health of the platform's components (connectors, storage) into a
single report for readiness/liveness probes and the ``hunt`` CLI. Each check is
a callable returning a boolean/detail; failures are captured, never raised.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence

from pydantic import BaseModel, Field

from threat_hunting.core.application.ports.connector import ConnectorRegistryPort

# A named health probe returning (healthy, detail).
HealthProbe = Callable[[], tuple[bool, str]]


class ComponentHealth(BaseModel):
    """Health of a single component."""

    component: str
    healthy: bool
    detail: str = ""


class HealthReport(BaseModel):
    """Aggregate health of the platform."""

    healthy: bool
    components: list[ComponentHealth] = Field(default_factory=list)


class HealthCheck:
    """Runs registered probes and connector health into a single report."""

    def __init__(
        self,
        registry: ConnectorRegistryPort | None = None,
        probes: dict[str, HealthProbe] | None = None,
    ) -> None:
        self._registry = registry
        self._probes = dict(probes or {})

    def add_probe(self, name: str, probe: HealthProbe) -> None:
        """Register an additional named probe."""
        self._probes[name] = probe

    def run(self, connectors: Sequence[str] | None = None) -> HealthReport:
        """Execute all probes (and optional connector probes) and aggregate."""
        components: list[ComponentHealth] = []

        for name, probe in self._probes.items():
            try:
                healthy, detail = probe()
            except Exception as exc:
                healthy, detail = False, str(exc)
            components.append(ComponentHealth(component=name, healthy=healthy, detail=detail))

        if self._registry is not None and connectors:
            for connector_name in connectors:
                try:
                    connector = self._registry.get(connector_name)
                    status = connector.health()
                    components.append(
                        ComponentHealth(
                            component=f"connector:{connector_name}",
                            healthy=status.healthy,
                            detail=status.detail,
                        )
                    )
                except Exception as exc:
                    components.append(
                        ComponentHealth(
                            component=f"connector:{connector_name}",
                            healthy=False,
                            detail=str(exc),
                        )
                    )

        overall = all(c.healthy for c in components) if components else True
        return HealthReport(healthy=overall, components=components)
