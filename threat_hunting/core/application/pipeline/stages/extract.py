"""ExtractStage — extrai IOCs / credenciais / cartões etc. do finding."""

from __future__ import annotations

from ....domain.ports import ExtractorPort
from ..context import PipelineContext
from ..stage import PipelineStage


class ExtractStage(PipelineStage):
    name = "extract"

    def __init__(self, extractor: ExtractorPort) -> None:
        self._extractor = extractor

    async def run(self, context: PipelineContext) -> PipelineContext:
        if context.finding is None:
            return context
        context.finding = await self._extractor.extract(context.finding)
        context.stage_meta(self.name)["indicators"] = len(context.finding.indicators)
        return context
