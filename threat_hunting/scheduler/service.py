"""Scheduler services for periodic hunting execution."""

from __future__ import annotations

from apscheduler.schedulers.background import BackgroundScheduler

from threat_hunting.application.use_cases import RunConnectorCommand
from threat_hunting.core.contracts import ConnectorRegistryPort
from threat_hunting.application.pipeline import HuntingPipeline


class SchedulerService:
    """APScheduler wrapper for connector jobs."""

    def __init__(self, pipeline: HuntingPipeline, registry: ConnectorRegistryPort) -> None:
        self._pipeline = pipeline
        self._registry = registry
        self._scheduler = BackgroundScheduler()

    def register_connector_job(self, connector_name: str, minutes: int = 30) -> None:
        """Register periodic hunt execution for a connector."""
        command = RunConnectorCommand(
            connector_name=connector_name,
            pipeline=self._pipeline,
            registry=self._registry,
            command_name="hunt scheduler run",
        )
        self._scheduler.add_job(command.execute, "interval", minutes=minutes, id=connector_name)

    def start(self) -> None:
        """Start scheduler process."""
        if not self._scheduler.running:
            self._scheduler.start()

    def run_all_once(self) -> None:
        """Trigger all connector jobs once in foreground."""
        for connector_name in self._registry.names():
            command = RunConnectorCommand(
                connector_name=connector_name,
                pipeline=self._pipeline,
                registry=self._registry,
                command_name="hunt scheduler run",
            )
            command.execute()
