"""APScheduler integration for automated collection jobs."""

from __future__ import annotations

from typing import Any, Callable

import structlog
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

logger = structlog.get_logger(__name__)


class HuntScheduler:
    """Scheduler for automated connector execution.

    Jobs are loaded from connector configurations with cron expressions.
    """

    def __init__(self) -> None:
        self._scheduler = AsyncIOScheduler()
        self._jobs: dict[str, str] = {}

    def add_connector_job(
        self,
        connector_name: str,
        cron_expression: str,
        handler: Callable,
    ) -> None:
        """Schedule a connector for periodic execution."""
        parts = cron_expression.split()
        if len(parts) == 5:
            trigger = CronTrigger(
                minute=parts[0], hour=parts[1], day=parts[2],
                month=parts[3], day_of_week=parts[4],
            )
        else:
            trigger = CronTrigger(hour="*/6")

        job = self._scheduler.add_job(
            handler,
            trigger=trigger,
            args=[connector_name],
            id=f"connector_{connector_name}",
            replace_existing=True,
        )
        self._jobs[connector_name] = job.id
        logger.info("scheduler.job.added", connector=connector_name, cron=cron_expression)

    def start(self) -> None:
        """Start the scheduler daemon."""
        if not self._scheduler.running:
            self._scheduler.start()
            logger.info("scheduler.started")

    def stop(self) -> None:
        """Stop the scheduler."""
        if self._scheduler.running:
            self._scheduler.shutdown()
            logger.info("scheduler.stopped")

    @property
    def is_running(self) -> bool:
        return self._scheduler.running
