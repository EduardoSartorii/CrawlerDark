"""Caso de uso: health check consolidado (conectores + exporters)."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from ...domain.ports import ConnectorPort, ExporterPort


@dataclass(slots=True, kw_only=True)
class HealthReport:
    connectors: dict[str, bool]
    exporters: dict[str, bool]

    @property
    def healthy(self) -> bool:
        return all(self.connectors.values()) and all(self.exporters.values())


class HealthCheckUseCase:
    async def execute(
        self,
        connectors: Sequence[ConnectorPort],
        exporters: Sequence[ExporterPort],
    ) -> HealthReport:
        connector_status: dict[str, bool] = {}
        for c in connectors:
            try:
                connector_status[c.name] = await c.health()
            except Exception:  # noqa: BLE001
                connector_status[c.name] = False
        exporter_status: dict[str, bool] = {}
        for e in exporters:
            try:
                exporter_status[e.name] = await e.health()
            except Exception:  # noqa: BLE001
                exporter_status[e.name] = False
        return HealthReport(connectors=connector_status, exporters=exporter_status)
