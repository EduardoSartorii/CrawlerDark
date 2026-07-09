"""EnrichStage — adiciona contexto externo (whois, geoip, threatfox, ...)."""

from __future__ import annotations

from ....domain.events import FindingEnriched
from ....domain.ports import EnrichmentEnginePort, EventBusPort
from ..context import PipelineContext
from ..stage import PipelineStage


class EnrichStage(PipelineStage):
    name = "enrich"

    def __init__(self, engine: EnrichmentEnginePort, event_bus: EventBusPort) -> None:
        self._engine = engine
        self._bus = event_bus

    async def run(self, context: PipelineContext) -> PipelineContext:
        if context.finding is None:
            return context
        context.finding = await self._engine.enrich(context.finding)
        providers = tuple(
            e.payload.get("provider", "?")
            for e in context.finding.timeline
            if e.kind == "enrich"
        )
        await self._bus.publish(FindingEnriched(finding_id=context.finding.id, providers=providers))
        return context
