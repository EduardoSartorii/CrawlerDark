"""NormalizeStage — transforma o dict parseado em ``Finding`` canônico."""

from __future__ import annotations

from ..context import PipelineContext
from ..stage import PipelineStage


class NormalizeStage(PipelineStage):
    name = "normalize"

    async def run(self, context: PipelineContext) -> PipelineContext:
        if context.connector_instance is None:
            raise RuntimeError("NormalizeStage requires connector_instance in context")
        if not isinstance(context.payload, dict):
            raise RuntimeError("NormalizeStage expects dict payload (run ParseStage first)")
        finding = await context.connector_instance.normalize(context.payload)
        context.finding = finding
        return context
