"""DetectStage — aplica regras Regex/YARA/Sigma/Keyword/IOC."""

from __future__ import annotations

from ....domain.ports import DetectionEnginePort
from ..context import PipelineContext
from ..stage import PipelineStage


class DetectStage(PipelineStage):
    name = "detect"

    def __init__(self, engine: DetectionEnginePort) -> None:
        self._engine = engine

    async def run(self, context: PipelineContext) -> PipelineContext:
        if context.finding is None:
            return context
        context.finding = await self._engine.detect(context.finding)
        matched = [
            e.payload.get("rule_id") for e in context.finding.timeline if e.kind == "rule.matched"
        ]
        context.stage_meta(self.name)["matched_rules"] = matched
        return context
