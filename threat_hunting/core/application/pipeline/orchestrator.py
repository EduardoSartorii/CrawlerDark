"""PipelineOrchestrator — compõe e executa os estágios."""

from __future__ import annotations

import time
from collections.abc import Sequence

from ...domain.events import FindingCreated
from ...domain.exceptions import PipelineError
from ...domain.ports import EventBusPort
from .context import PipelineContext
from .stage import PipelineStage


class PipelineOrchestrator:
    """Executa os estágios em ordem, coletando métricas por estágio.

    * Publica ``FindingCreated`` assim que o finding surge (após ``NormalizeStage``).
    * Registra a duração de cada estágio em ``context.metadata[stage_name]['duration_ms']``.
    * Interrompe execução se ``context.discard`` for setado.
    """

    def __init__(self, stages: Sequence[PipelineStage], event_bus: EventBusPort) -> None:
        self._stages = list(stages)
        self._bus = event_bus

    async def process(self, context: PipelineContext) -> PipelineContext:
        for stage in self._stages:
            if context.discard:
                context.stage_meta(stage.name)["skipped"] = True
                continue
            started = time.perf_counter()
            try:
                context = await stage.run(context)
            except Exception as exc:  # noqa: BLE001
                raise PipelineError(stage.name, str(exc)) from exc
            finally:
                context.stage_meta(stage.name)["duration_ms"] = round(
                    (time.perf_counter() - started) * 1000, 3
                )
            if stage.name == "normalize" and context.finding is not None:
                await self._bus.publish(
                    FindingCreated(finding_id=context.finding.id, connector=context.connector)
                )
        return context
