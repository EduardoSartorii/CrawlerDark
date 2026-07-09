"""ScoreStage — atribui score via ``ScoringEnginePort``."""

from __future__ import annotations

from ....domain.events import ScoreComputed
from ....domain.ports import EventBusPort, ScoringEnginePort
from ..context import PipelineContext
from ..stage import PipelineStage


class ScoreStage(PipelineStage):
    name = "score"

    def __init__(self, engine: ScoringEnginePort, event_bus: EventBusPort) -> None:
        self._engine = engine
        self._bus = event_bus

    async def run(self, context: PipelineContext) -> PipelineContext:
        if context.finding is None:
            return context
        score = await self._engine.score(context.finding)
        context.finding.set_score(score, reason="scoring-engine")
        await self._bus.publish(ScoreComputed(finding_id=context.finding.id, score=score.value))
        context.stage_meta(self.name)["score"] = score.value
        return context
