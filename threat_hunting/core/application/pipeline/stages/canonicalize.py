"""CanonicalizeStage — normalização canônica pós-Extract.

Aplica normalização de valores dos IOCs, do URL canônico, e calcula o
``dedup_hash`` do finding. É separada da ``NormalizeStage`` (que só constrói o
finding a partir do payload parseado do conector) para respeitar SRP.
"""

from __future__ import annotations

from ....domain.ports import NormalizerPort
from ..context import PipelineContext
from ..stage import PipelineStage


class CanonicalizeStage(PipelineStage):
    name = "canonicalize"

    def __init__(self, normalizer: NormalizerPort) -> None:
        self._normalizer = normalizer

    async def run(self, context: PipelineContext) -> PipelineContext:
        if context.finding is None:
            return context
        context.finding = await self._normalizer.normalize(context.finding)
        context.stage_meta(self.name)["dedup_hash"] = context.finding.dedup_hash
        return context
