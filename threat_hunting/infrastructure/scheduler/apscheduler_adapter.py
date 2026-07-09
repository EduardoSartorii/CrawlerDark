"""Adapter para o APScheduler (async).

Implementa ``SchedulerPort``. Aceita triggers ``interval``, ``cron`` e ``date``.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.date import DateTrigger
from apscheduler.triggers.interval import IntervalTrigger


class APSchedulerAdapter:
    def __init__(self, *, timezone: str = "UTC") -> None:
        self._scheduler = AsyncIOScheduler(timezone=timezone)

    def add_job(
        self,
        job_id: str,
        func: Callable[..., Awaitable[Any]],
        *,
        trigger: str,
        **trigger_options: Any,
    ) -> None:
        trigger_obj: Any
        if trigger == "interval":
            trigger_obj = IntervalTrigger(**trigger_options)
        elif trigger == "cron":
            trigger_obj = CronTrigger(**trigger_options)
        elif trigger == "date":
            trigger_obj = DateTrigger(**trigger_options)
        else:
            raise ValueError(f"Unsupported trigger: {trigger}")
        self._scheduler.add_job(
            func,
            trigger=trigger_obj,
            id=job_id,
            replace_existing=True,
            misfire_grace_time=60,
        )

    async def start(self) -> None:
        self._scheduler.start()

    async def shutdown(self) -> None:
        if self._scheduler.running:
            self._scheduler.shutdown(wait=False)

    def list_jobs(self) -> list[str]:
        return [j.id for j in self._scheduler.get_jobs()]
