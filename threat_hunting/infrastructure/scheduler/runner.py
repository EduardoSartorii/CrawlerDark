"""SchedulerRunner.

Responsibility
--------------
Drive periodic collection. It delegates the actual work to
:class:`RunCollectionService`, so scheduling stays independent of collection
logic. ``APScheduler`` powers real interval scheduling when available; a plain
sleep loop is the dependency-free fallback.
"""

from __future__ import annotations

import time
from collections.abc import Sequence

from threat_hunting.core.application.dto.run_summary import RunSummary
from threat_hunting.core.application.services.run_collection import RunCollectionService


class SchedulerRunner:
    """Runs one or more collection targets on demand or on an interval."""

    def __init__(self, service: RunCollectionService) -> None:
        self._service = service

    def run_cycle(self, targets: Sequence[str]) -> list[RunSummary]:
        """Run every target once and return their summaries."""
        summaries: list[RunSummary] = []
        for target in targets:
            summaries.append(self._service.run(target))
        return summaries

    def loop(
        self,
        targets: Sequence[str],
        interval_seconds: int = 3600,
        *,
        max_cycles: int | None = None,
    ) -> None:  # pragma: no cover - long-running loop
        """Run cycles on an interval (APScheduler when available, else sleep)."""
        try:
            from apscheduler.schedulers.blocking import BlockingScheduler

            scheduler = BlockingScheduler()
            scheduler.add_job(
                self.run_cycle, "interval", seconds=interval_seconds, args=[list(targets)]
            )
            scheduler.start()
        except ImportError:
            cycles = 0
            while max_cycles is None or cycles < max_cycles:
                self.run_cycle(targets)
                cycles += 1
                time.sleep(interval_seconds)
