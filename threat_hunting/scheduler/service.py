"""APScheduler integration for recurring collection jobs."""

from __future__ import annotations

import time

from apscheduler.schedulers.background import BackgroundScheduler

from threat_hunting.core.application.commands import RunHuntCommand
from threat_hunting.infrastructure.container import ApplicationContainer


class SchedulerService:
    """Run configured hunting jobs with APScheduler."""

    def __init__(self, container: ApplicationContainer) -> None:
        self.container = container
        self.scheduler = BackgroundScheduler()

    def configure_jobs(self) -> None:
        """Register jobs from platform settings."""

        settings = self.container.settings()
        for job in settings.scheduler.get("jobs", []):
            target = job.get("target", "all")
            interval_seconds = int(job.get("interval_seconds", 3600))
            self.scheduler.add_job(
                self._run_target,
                "interval",
                seconds=interval_seconds,
                args=[target],
                id=f"hunt:{target}",
                replace_existing=True,
            )

    def _run_target(self, target: str) -> None:
        """Run one scheduled target."""

        self.container.run_hunt_use_case().execute(RunHuntCommand(target=target))

    def run_forever(self) -> None:
        """Start scheduler and keep the process alive."""

        self.configure_jobs()
        self.scheduler.start()
        try:
            while True:
                time.sleep(1)
        finally:
            self.scheduler.shutdown()
