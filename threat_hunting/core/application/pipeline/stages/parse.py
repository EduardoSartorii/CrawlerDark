"""ParseStage — invoca ``connector.parse`` no payload bruto."""

from __future__ import annotations

from ..context import PipelineContext
from ..stage import PipelineStage


class ParseStage(PipelineStage):
    name = "parse"

    async def run(self, context: PipelineContext) -> PipelineContext:
        if context.connector_instance is None:
            raise RuntimeError("ParseStage requires connector_instance in context")
        parsed = await context.connector_instance.parse(context.payload)
        context.stage_meta(self.name)["fields"] = list(parsed.keys()) if isinstance(parsed, dict) else []
        context.payload = parsed
        return context
