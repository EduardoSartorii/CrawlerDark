"""APScheduler-based hunting scheduler.

Responsibility
--------------
Run collection on a schedule (interval/cron) so the platform operates
autonomously, not just on demand. Each enabled connector is scheduled to run the
pipeline at its configured cadence. APScheduler is optional: if it is not
installed the scheduler falls back to a simple asyncio interval loop so
``hunt scheduler run`` still works.
"""

from __future__ import annotations

import asyncio

from threat_hunting.core.application.use_cases.run_hunt import RunHuntUseCase
from threat_hunting.infrastructure.observability.logging import get_logger

try:
    from apscheduler.schedulers.asyncio import AsyncIOScheduler  # type: ignore

    _APS = True
except Exception:  # noqa: BLE001 - optional
    _APS = False


class HuntScheduler:
    """Schedules recurring hunting runs across enabled connectors."""

    def __init__(
        self,
        *,
        use_case: RunHuntUseCase,
        interval_seconds: int = 3600,
    ) -> None:
        self._use_case = use_case
        self._interval = interval_seconds
        self._log = get_logger("threat_hunting.scheduler")

    async def _tick(self) -> None:
        """Execute one full collection round over all enabled connectors."""
        result = await self._use_case.run_all()
        self._log.info(
            "scheduler_tick",
            collected=result.collected,
            persisted=result.persisted,
            duplicates=result.duplicates,
            exported=result.exported,
            errors=len(result.errors),
        )

    async def run(self, *, iterations: int | None = None) -> None:
        """Run the scheduler loop.

        Parameters
        ----------
        iterations:
            When set, run exactly that many rounds then stop (used by tests and
            one-shot invocations). When ``None``, run indefinitely.
        """
        if _APS and iterations is None:
            scheduler = AsyncIOScheduler()
            scheduler.add_job(self._tick, "interval", seconds=self._interval)
            scheduler.start()
            self._log.info("scheduler_started", interval=self._interval)
            while True:  # pragma: no cover - long-running loop
                await asyncio.sleep(self._interval)
        else:
            count = 0
            while iterations is None or count < iterations:
                await self._tick()
                count += 1
                if iterations is None:  # pragma: no cover - long-running loop
                    await asyncio.sleep(self._interval)
