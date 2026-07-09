"""ExportStage — auto-export ao ultrapassar threshold."""

from __future__ import annotations

from collections.abc import Sequence

from ....domain.events import FindingExported
from ....domain.ports import EventBusPort, ExporterPort
from ..context import PipelineContext
from ..stage import PipelineStage


class ExportStage(PipelineStage):
    name = "export"

    def __init__(
        self,
        exporters: Sequence[ExporterPort],
        event_bus: EventBusPort,
        *,
        threshold: float = 80.0,
    ) -> None:
        self._exporters = list(exporters)
        self._bus = event_bus
        self._threshold = threshold

    async def run(self, context: PipelineContext) -> PipelineContext:
        finding = context.finding
        if finding is None or context.discard:
            return context
        if finding.score.value < self._threshold:
            context.stage_meta(self.name)["skipped"] = True
            return context
        exported: list[str] = []
        for exporter in self._exporters:
            try:
                count = await exporter.export([finding])
            except Exception as exc:  # noqa: BLE001
                finding.record_event("export.error", str(exc), {"target": exporter.name})
                continue
            if count:
                finding.mark_exported(exporter.name)
                exported.append(exporter.name)
                await self._bus.publish(
                    FindingExported(finding_id=finding.id, target=exporter.name)
                )
        context.stage_meta(self.name)["exported"] = exported
        return context
