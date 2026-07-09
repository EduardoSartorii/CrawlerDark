"""
ThreatHuntingScheduler
======================

Wraps APScheduler to automate connector collection runs on configurable
cron schedules.

Design:
    - Each connector has a corresponding Job defined in config/settings.yaml.
    - Jobs are added to the scheduler at startup.
    - The scheduler runs in the same async event loop as the application.
    - Job execution calls RunCollectionUseCase.execute().
    - Failed jobs are retried according to the connector's OPSEC profile.
    - Job state (last_run, last_success, error_count) is persisted via UoW.

Job configuration (from settings.yaml):
    scheduler:
      jobs:
        - id: reddit_collection
          connector: reddit
          cron: "0 */4 * * *"
          enabled: true
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import structlog
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

if TYPE_CHECKING:
    from threat_hunting.core.application.use_cases.run_collection import RunCollectionUseCase
    from threat_hunting.infrastructure.connectors.registry import ConnectorRegistry
    from threat_hunting.infrastructure.opsec.layer import OpsecLayer
    from threat_hunting.core.domain.ports.storage import IUnitOfWork

logger = structlog.get_logger(__name__)


class ThreatHuntingScheduler:
    """
    APScheduler-backed connector job scheduler.

    Reads job definitions from configuration and schedules connector
    collection runs accordingly.
    """

    def __init__(
        self,
        use_case: "RunCollectionUseCase",
        connector_registry: "ConnectorRegistry",
        opsec_layer: "OpsecLayer",
        uow: "IUnitOfWork",
    ) -> None:
        self._use_case = use_case
        self._registry = connector_registry
        self._opsec = opsec_layer
        self._uow = uow
        self._scheduler = AsyncIOScheduler(timezone="UTC")

    def configure(self, job_configs: list[dict[str, Any]]) -> None:
        """Load job definitions from configuration and register them."""
        for job_cfg in job_configs:
            if not job_cfg.get("enabled", True):
                continue
            connector_id: str = job_cfg.get("connector", "")
            cron: str = job_cfg.get("cron", "0 * * * *")
            job_id: str = job_cfg.get("id", connector_id)

            if not self._registry.is_enabled(connector_id):
                logger.info("scheduler_job_skipped_disabled", connector=connector_id)
                continue

            try:
                trigger = CronTrigger.from_crontab(cron, timezone="UTC")
                self._scheduler.add_job(
                    self._run_connector,
                    trigger=trigger,
                    id=job_id,
                    args=[connector_id, job_cfg],
                    replace_existing=True,
                    max_instances=1,
                    coalesce=True,
                )
                logger.info("job_scheduled", job_id=job_id, connector=connector_id, cron=cron)
            except Exception as exc:
                logger.error("job_schedule_failed", job_id=job_id, error=str(exc))

    async def _run_connector(self, connector_id: str, config: dict[str, Any]) -> None:
        """Execute a scheduled connector run."""
        log = logger.bind(connector=connector_id, trigger="scheduler")
        log.info("scheduled_run_start")
        try:
            opsec_profile = config.get("opsec_profile", "standard")
            connector = self._registry.create(
                connector_id,
                opsec_layer=self._opsec,
                config=config.get("params", {}),
                opsec_profile=opsec_profile,
            )

            async with self._uow as uow:
                conn_config = await uow.connector_configs.get_by_connector_id(connector_id)

            if conn_config is None:
                from threat_hunting.core.domain.entities.connector_config import ConnectorConfig
                from threat_hunting.core.domain.value_objects.source import SourceType
                conn_config = ConnectorConfig(
                    connector_id=connector_id,
                    name=connector_id,
                    source_type=SourceType(connector.source_type),
                )

            result = await self._use_case.execute(connector, conn_config)
            log.info(
                "scheduled_run_complete",
                findings=result.findings_processed,
                duration=result.duration_seconds,
            )
        except Exception as exc:
            log.error("scheduled_run_failed", error=str(exc), exc_info=True)

    def start(self) -> None:
        """Start the scheduler."""
        if not self._scheduler.running:
            self._scheduler.start()
            logger.info("scheduler_started", jobs=len(self._scheduler.get_jobs()))

    def shutdown(self, wait: bool = True) -> None:
        """Stop the scheduler."""
        if self._scheduler.running:
            self._scheduler.shutdown(wait=wait)
            logger.info("scheduler_stopped")

    def list_jobs(self) -> list[dict[str, Any]]:
        """Return a summary of all scheduled jobs."""
        return [
            {
                "id": job.id,
                "next_run": str(job.next_run_time),
                "trigger": str(job.trigger),
            }
            for job in self._scheduler.get_jobs()
        ]
