"""APScheduler runner for periodic hunting jobs."""

from __future__ import annotations

from apscheduler.schedulers.background import BackgroundScheduler

from threat_hunting.connectors.registry import ConnectorRegistry
from threat_hunting.pipelines.collection import CollectionPipeline


class SchedulerRunner:
    """Schedule enabled connectors at a fixed interval."""

    def __init__(self, registry: ConnectorRegistry, pipeline: CollectionPipeline, interval_minutes: int) -> None:
        self._registry = registry
        self._pipeline = pipeline
        self._interval_minutes = interval_minutes
        self._scheduler = BackgroundScheduler()

    def start(self) -> BackgroundScheduler:
        """Start scheduled jobs and return the scheduler instance."""

        for definition in self._registry.list(enabled_only=True):
            self._scheduler.add_job(
                lambda name=definition.name: self._pipeline.run(self._registry.get(name)),
                "interval",
                minutes=self._interval_minutes,
                id=f"hunt-{definition.name}",
                replace_existing=True,
            )
        self._scheduler.start()
        return self._scheduler
