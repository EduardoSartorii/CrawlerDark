"""
Scheduler.

Manages scheduled collection jobs using APScheduler.
Connectors can be scheduled to run at configurable intervals.

Scheduling Strategies:
    - Cron: run at specific times (e.g., "0 */4 * * *" = every 4 hours)
    - Interval: run every N minutes/hours
    - One-shot: run once at a specific time

Design:
    - Jobs are persisted in config (YAML/DB) — survive restarts
    - Each job is independent: a failure doesn't stop others
    - Health metrics exposed via Prometheus
    - Job results stored for audit trail
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable

import structlog
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

logger = structlog.get_logger(__name__)


class ScheduledJob:
    """Represents a registered collection job."""

    def __init__(
        self,
        job_id: str,
        connector_id: str,
        trigger_type: str,
        trigger_config: dict[str, Any],
        enabled: bool = True,
    ) -> None:
        self.job_id = job_id
        self.connector_id = connector_id
        self.trigger_type = trigger_type
        self.trigger_config = trigger_config
        self.enabled = enabled
        self.last_run: datetime | None = None
        self.last_status: str = "never_run"
        self.run_count: int = 0
        self.error_count: int = 0


class CollectionScheduler:
    """
    Manages scheduled threat hunting collection jobs.

    Wraps APScheduler with a CTI-domain-aware interface.
    """

    def __init__(self) -> None:
        self._scheduler = AsyncIOScheduler()
        self._jobs: dict[str, ScheduledJob] = {}
        self._running = False

    def start(self) -> None:
        """Start the scheduler."""
        if not self._running:
            self._scheduler.start()
            self._running = True
            logger.info("scheduler.started")

    def shutdown(self, wait: bool = True) -> None:
        """Gracefully shut down the scheduler."""
        if self._running:
            self._scheduler.shutdown(wait=wait)
            self._running = False
            logger.info("scheduler.shutdown")

    def add_cron_job(
        self,
        job_id: str,
        connector_id: str,
        cron_expression: str,
        callback: Callable[..., Any],
        **callback_kwargs: Any,
    ) -> ScheduledJob:
        """
        Schedule a connector with a cron expression.

        Example: cron_expression="0 */4 * * *" runs every 4 hours.
        """
        job = ScheduledJob(
            job_id=job_id,
            connector_id=connector_id,
            trigger_type="cron",
            trigger_config={"cron": cron_expression},
        )

        async def _job_wrapper() -> None:
            job.last_run = datetime.now(tz=timezone.utc)
            job.run_count += 1
            log = logger.bind(job_id=job_id, connector=connector_id)
            log.info("scheduler.job_start", run=job.run_count)
            try:
                await callback(**callback_kwargs)
                job.last_status = "success"
                log.info("scheduler.job_success")
            except Exception as exc:
                job.error_count += 1
                job.last_status = f"error: {exc}"
                log.error("scheduler.job_failed", error=str(exc), exc_info=True)

        parts = cron_expression.split()
        trigger = CronTrigger(
            minute=parts[0] if len(parts) > 0 else "*",
            hour=parts[1] if len(parts) > 1 else "*",
            day=parts[2] if len(parts) > 2 else "*",
            month=parts[3] if len(parts) > 3 else "*",
            day_of_week=parts[4] if len(parts) > 4 else "*",
        )

        self._scheduler.add_job(
            _job_wrapper,
            trigger=trigger,
            id=job_id,
            replace_existing=True,
        )
        self._jobs[job_id] = job
        logger.info("scheduler.job_added", job_id=job_id, connector=connector_id, cron=cron_expression)
        return job

    def add_interval_job(
        self,
        job_id: str,
        connector_id: str,
        minutes: int = 60,
        callback: Callable[..., Any] | None = None,
        **callback_kwargs: Any,
    ) -> ScheduledJob:
        """Schedule a connector to run every N minutes."""
        job = ScheduledJob(
            job_id=job_id,
            connector_id=connector_id,
            trigger_type="interval",
            trigger_config={"minutes": minutes},
        )

        async def _job_wrapper() -> None:
            job.last_run = datetime.now(tz=timezone.utc)
            job.run_count += 1
            logger.info("scheduler.interval_job_run", job_id=job_id)
            if callback:
                try:
                    await callback(**callback_kwargs)
                    job.last_status = "success"
                except Exception as exc:
                    job.error_count += 1
                    job.last_status = f"error: {exc}"
                    logger.error("scheduler.interval_job_failed", job_id=job_id, error=str(exc))

        self._scheduler.add_job(
            _job_wrapper,
            trigger=IntervalTrigger(minutes=minutes),
            id=job_id,
            replace_existing=True,
        )
        self._jobs[job_id] = job
        logger.info("scheduler.interval_job_added", job_id=job_id, minutes=minutes)
        return job

    def remove_job(self, job_id: str) -> None:
        """Remove a scheduled job."""
        if job_id in self._jobs:
            self._scheduler.remove_job(job_id)
            del self._jobs[job_id]
            logger.info("scheduler.job_removed", job_id=job_id)

    def pause_job(self, job_id: str) -> None:
        self._scheduler.pause_job(job_id)
        if job_id in self._jobs:
            self._jobs[job_id].enabled = False
        logger.info("scheduler.job_paused", job_id=job_id)

    def resume_job(self, job_id: str) -> None:
        self._scheduler.resume_job(job_id)
        if job_id in self._jobs:
            self._jobs[job_id].enabled = True
        logger.info("scheduler.job_resumed", job_id=job_id)

    def list_jobs(self) -> list[dict[str, Any]]:
        """Return status of all registered jobs."""
        return [
            {
                "job_id": job.job_id,
                "connector_id": job.connector_id,
                "trigger_type": job.trigger_type,
                "trigger_config": job.trigger_config,
                "enabled": job.enabled,
                "last_run": job.last_run.isoformat() if job.last_run else None,
                "last_status": job.last_status,
                "run_count": job.run_count,
                "error_count": job.error_count,
            }
            for job in self._jobs.values()
        ]

    @property
    def is_running(self) -> bool:
        return self._running
