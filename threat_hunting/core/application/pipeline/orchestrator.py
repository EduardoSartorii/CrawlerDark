"""Pipeline orchestrator.

Responsibility
--------------
Execute an ordered list of decoupled pipeline stages against a
:class:`PipelineContext`. The orchestrator is the *only* component that knows
the mandatory order; stages themselves remain ignorant of one another
(satisfying the "each stage fully decoupled" requirement).

Behaviour
---------
* Publishes ``PipelineStarted`` / ``PipelineCompleted`` events.
* Wraps each stage so a failure is isolated: it is logged, metered, published as
  ``PipelineStageFailed`` and — depending on ``fail_fast`` — either aborts the
  run or skips to the next stage. This keeps a single bad stage from silently
  corrupting the whole collection.
* Times every stage into ``context.stats`` for observability.
"""

from __future__ import annotations

import time
from collections.abc import Sequence

from threat_hunting.core.application.ports.event_bus import EventBus
from threat_hunting.core.application.ports.pipeline import PipelineContext, PipelineStage
from threat_hunting.core.domain.events.finding_events import (
    PipelineCompleted,
    PipelineStageFailed,
    PipelineStarted,
)
from threat_hunting.core.domain.exceptions import PipelineError


class _NullEventBus:
    """No-op event bus used when the caller does not supply one."""

    def subscribe(self, event_name: object, handler: object) -> None:  # noqa: D401
        return None

    def publish(self, event: object) -> None:  # noqa: D401
        return None


class PipelineOrchestrator:
    """Runs the ordered collection pipeline for a single connector run."""

    def __init__(
        self,
        stages: Sequence[PipelineStage],
        event_bus: EventBus | None = None,
        *,
        fail_fast: bool = False,
    ) -> None:
        """Store the ordered ``stages`` and the (optional) event bus.

        :param fail_fast: when ``True`` a stage error aborts the whole run;
            otherwise the stage is skipped and processing continues.
        """
        self._stages = list(stages)
        self._bus: EventBus = event_bus or _NullEventBus()  # type: ignore[assignment]
        self._fail_fast = fail_fast

    @property
    def stage_names(self) -> list[str]:
        """Ordered names of the configured stages (for introspection/tests)."""
        return [stage.name for stage in self._stages]

    def run(self, context: PipelineContext) -> PipelineContext:
        """Execute every stage in order and return the resulting context."""
        self._bus.publish(
            PipelineStarted(connector=context.connector_name, run_id=context.run_id)
        )
        for stage in self._stages:
            start = time.perf_counter()
            try:
                context = stage.process(context)
            except Exception as exc:  # isolate stage failures
                elapsed = time.perf_counter() - start
                context.stats[f"stage.{stage.name}.seconds"] = elapsed
                context.bump("stage.failures")
                self._bus.publish(
                    PipelineStageFailed(
                        connector=context.connector_name,
                        stage=stage.name,
                        error=str(exc),
                        run_id=context.run_id,
                    )
                )
                if self._fail_fast:
                    raise PipelineError(stage.name, str(exc)) from exc
                continue
            else:
                elapsed = time.perf_counter() - start
                context.stats[f"stage.{stage.name}.seconds"] = elapsed

        self._bus.publish(
            PipelineCompleted(
                connector=context.connector_name,
                findings_count=len(context.findings),
                stats=dict(context.stats),
                run_id=context.run_id,
            )
        )
        return context
