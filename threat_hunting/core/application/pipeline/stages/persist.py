"""PersistStage — salva finding via UnitOfWork."""

from __future__ import annotations

from ....domain.events import FindingPersisted
from ....domain.ports import EventBusPort, UnitOfWorkPort
from ..context import PipelineContext
from ..stage import PipelineStage


class PersistStage(PipelineStage):
    name = "persist"

    def __init__(
        self,
        uow_factory: type[UnitOfWorkPort] | object,
        event_bus: EventBusPort,
    ) -> None:
        self._uow_factory = uow_factory
        self._bus = event_bus

    async def run(self, context: PipelineContext) -> PipelineContext:
        if context.finding is None or context.discard:
            return context
        async with self._uow_factory() as uow:  # type: ignore[operator]
            if context.finding.dedup_hash:
                existing = await uow.findings.find_by_dedup_hash(context.finding.dedup_hash)
                if existing is not None:
                    context.discard = True
                    return context
            await uow.findings.add(context.finding)
            await uow.commit()
        await self._bus.publish(FindingPersisted(finding_id=context.finding.id))
        context.stage_meta(self.name)["persisted"] = True
        return context
