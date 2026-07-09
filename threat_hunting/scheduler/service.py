"""APScheduler orchestration for periodic hunts."""

from __future__ import annotations

from collections.abc import Callable

from apscheduler.schedulers.background import BackgroundScheduler


class SchedulerService:
    """Wrapper service around APScheduler for decoupled scheduling."""

    def __init__(self, run_target: Callable[[str], object] | None = None, default_target: str = "all") -> None:
        self._run_target = run_target or (lambda _: None)
        self._default_target = default_target
        self._scheduler = BackgroundScheduler()

    def set_run_target(self, run_target: Callable[[str], object]) -> None:
        """Attach runtime callback after container wiring."""
        self._run_target = run_target

    def start(self, cron_expr: str = "*/30 * * * *") -> None:
        """Start scheduler with cron expression in minute granularity."""
        minute, hour, day, month, day_of_week = cron_expr.split()
        self._scheduler.add_job(
            lambda: self._run_target(self._default_target),
            trigger="cron",
            minute=minute,
            hour=hour,
            day=day,
            month=month,
            day_of_week=day_of_week,
            id="hunt-runner",
            replace_existing=True,
        )
        self._scheduler.start()

    def run_once(self) -> None:
        """Trigger one scheduler cycle immediately."""
        self._run_target(self._default_target)
