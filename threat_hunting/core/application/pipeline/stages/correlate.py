"""CorrelateStage — correlaciona finding com o corpus recente."""

from __future__ import annotations

from ....domain.ports import CorrelationEnginePort, UnitOfWorkPort
from ..context import PipelineContext
from ..stage import PipelineStage


class CorrelateStage(PipelineStage):
    name = "correlate"

    def __init__(
        self,
        engine: CorrelationEnginePort,
        uow_factory: type[UnitOfWorkPort] | object,
    ) -> None:
        self._engine = engine
        self._uow_factory = uow_factory

    async def run(self, context: PipelineContext) -> PipelineContext:
        if context.finding is None:
            return context
        async with self._uow_factory() as uow:  # type: ignore[operator]
            corpus = await uow.findings.find_recent(limit=500)
        context.finding = await self._engine.correlate(context.finding, corpus)
        context.stage_meta(self.name)["relationships"] = len(context.finding.relationships)
        return context
