"""DeduplicateStage — checa duplicidade contra findings recentes."""

from __future__ import annotations

from ....domain.events import FindingDeduplicated
from ....domain.ports import DeduplicationEnginePort, EventBusPort, UnitOfWorkPort
from ..context import PipelineContext
from ..stage import PipelineStage


class DeduplicateStage(PipelineStage):
    name = "deduplicate"

    def __init__(
        self,
        engine: DeduplicationEnginePort,
        uow_factory: type[UnitOfWorkPort] | object,
        event_bus: EventBusPort,
    ) -> None:
        self._engine = engine
        self._uow_factory = uow_factory
        self._bus = event_bus

    async def run(self, context: PipelineContext) -> PipelineContext:
        if context.finding is None:
            return context
        async with self._uow_factory() as uow:  # type: ignore[operator]
            corpus = await uow.findings.find_recent(limit=1000)
            existing = None
            if context.finding.dedup_hash:
                existing = await uow.findings.find_by_dedup_hash(context.finding.dedup_hash)
        _, is_dup = await self._engine.deduplicate(context.finding, corpus)
        if is_dup or existing is not None:
            context.duplicate_of = existing
            context.stage_meta(self.name)["duplicate"] = True
            action = "merged" if existing is not None else "flagged"
            await self._bus.publish(
                FindingDeduplicated(
                    finding_id=context.finding.id,
                    duplicate_of=existing.id if existing else None,
                    action=action,
                )
            )
            if existing is not None:
                context.discard = True
        return context
