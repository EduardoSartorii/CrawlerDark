"""APScheduler-based hunt scheduler.

Responsibility
--------------
Schedule connector runs from ConnectorConfig.schedule (cron) or defaults.
Decoupled from CLI — both use RunHuntHandler.
"""

from __future__ import annotations

from typing import Any, Callable, Awaitable

import structlog
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

from threat_hunting.core.application.commands import RunHuntCommand
from threat_hunting.core.application.use_cases import RunHuntHandler

logger = structlog.get_logger(__name__)


class HuntScheduler:
    """Schedule hunt jobs using APScheduler."""

    def __init__(
        self,
        *,
        run_handler: RunHuntHandler,
        timezone: str = "UTC",
    ) -> None:
        self._handler = run_handler
        self._scheduler = AsyncIOScheduler(timezone=timezone)
        self._jobs: dict[str, str] = {}

    def add_connector_cron(self, connector: str, cron: str) -> None:
        """Add a cron schedule for a connector (5-field cron)."""
        trigger = CronTrigger.from_crontab(cron)
        job = self._scheduler.add_job(
            self._run_connector,
            trigger=trigger,
            id=f"hunt:{connector}",
            replace_existing=True,
            kwargs={"connector": connector},
        )
        self._jobs[connector] = job.id
        logger.info("scheduler.job_added", connector=connector, cron=cron)

    async def _run_connector(self, connector: str) -> None:
        logger.info("scheduler.triggered", connector=connector)
        await self._handler.handle(RunHuntCommand(connector=connector))

    async def run_once(self, connector: str = "all") -> list[Any]:
        """Run immediately without starting the scheduler loop."""
        return await self._handler.handle(RunHuntCommand(connector=connector))

    def start(self) -> None:
        if not self._scheduler.running:
            self._scheduler.start()
            logger.info("scheduler.started", jobs=len(self._jobs))

    def shutdown(self) -> None:
        if self._scheduler.running:
            self._scheduler.shutdown(wait=False)
            logger.info("scheduler.stopped")

    @property
    def job_count(self) -> int:
        return len(self._jobs)


__all__ = ["HuntScheduler"]
