"""
RunCollectionUseCase
====================

Orchestrates the full collection cycle for one or more connectors.
For each connector:
    1. Calls connector.connect().
    2. Iterates connector.collect() → parse() → normalize().
    3. Passes each normalized Finding to the Pipeline.
    4. Calls connector.close().
    5. Updates ConnectorConfig statistics.
    6. Publishes CollectionCompleted / CollectionFailed events.

This use case is the primary entry point for the CLI 'hunt run' command
and the scheduler jobs.

Architecture:
    - Depends only on domain ports — no infrastructure imports.
    - Connector is passed in via dependency injection.
    - Pipeline is passed in via dependency injection.
    - Error handling separates transient from fatal failures.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import structlog

from threat_hunting.core.domain.events.collection_events import (
    CollectionCompleted,
    CollectionFailed,
    CollectionStarted,
)
from threat_hunting.core.domain.exceptions.domain_exceptions import CollectionError

if TYPE_CHECKING:
    from threat_hunting.core.application.pipeline.pipeline import Pipeline, PipelineResult
    from threat_hunting.core.domain.entities.connector_config import ConnectorConfig
    from threat_hunting.core.domain.ports.connectors import IConnector
    from threat_hunting.core.domain.ports.event_bus import IEventBus
    from threat_hunting.core.domain.ports.storage import IUnitOfWork

logger = structlog.get_logger(__name__)


@dataclass
class CollectionRunResult:
    """Aggregated result of one connector collection run."""

    connector_id: str
    success: bool
    findings_collected: int = 0
    findings_processed: int = 0
    pipeline_results: list["PipelineResult"] = field(default_factory=list)
    duration_seconds: float = 0.0
    error: str | None = None


class RunCollectionUseCase:
    """
    Execute a full collection cycle for a given connector.

    This is the primary application-layer use case for threat hunting.
    It coordinates the connector, pipeline, and event bus.
    """

    def __init__(
        self,
        pipeline: "Pipeline",
        event_bus: "IEventBus",
        uow: "IUnitOfWork",
    ) -> None:
        self._pipeline = pipeline
        self._event_bus = event_bus
        self._uow = uow

    async def execute(
        self, connector: "IConnector", config: "ConnectorConfig"
    ) -> CollectionRunResult:
        """Run the collection cycle for one connector.

        Args:
            connector: The connector to run.
            config: Runtime configuration for the connector.

        Returns:
            CollectionRunResult with run statistics.
        """
        log = logger.bind(connector=connector.connector_id)
        start_time = time.perf_counter()
        result = CollectionRunResult(connector_id=connector.connector_id, success=True)

        await self._event_bus.publish(
            CollectionStarted(
                aggregate_id=config.id,
                connector=connector.connector_id,
                source=connector.source_type,
            )
        )
        log.info("collection_started")

        try:
            await connector.connect()
        except Exception as exc:
            log.error("connect_failed", error=str(exc))
            result.success = False
            result.error = str(exc)
            await self._publish_failed(config, connector, exc)
            return result

        try:
            async for raw_item in connector.collect():
                try:
                    result.findings_collected += 1
                    parsed = await connector.parse(raw_item)
                    finding = await connector.normalize(parsed)
                    pipeline_result = await self._pipeline.process(finding)
                    result.pipeline_results.append(pipeline_result)
                    if pipeline_result.success:
                        result.findings_processed += 1
                except Exception as exc:
                    log.warning(
                        "item_processing_error",
                        error=str(exc),
                        exc_info=True,
                    )
                    # Continue collecting — one bad item should not abort the run.

        except CollectionError as exc:
            log.error("collection_error", error=str(exc))
            result.success = False
            result.error = str(exc)
            await self._publish_failed(config, connector, exc)

        except Exception as exc:
            log.error("unexpected_collection_error", error=str(exc), exc_info=True)
            result.success = False
            result.error = str(exc)
            await self._publish_failed(config, connector, exc)

        finally:
            try:
                await connector.close()
            except Exception as exc:
                log.warning("connector_close_error", error=str(exc))

        result.duration_seconds = time.perf_counter() - start_time

        # Update statistics in storage.
        async with self._uow as uow:
            config.record_run(
                findings_count=result.findings_processed,
                error=result.error,
            )
            await uow.connector_configs.save(config)
            await uow.commit()

        await self._event_bus.publish(
            CollectionCompleted(
                aggregate_id=config.id,
                connector=connector.connector_id,
                source=connector.source_type,
                findings_count=result.findings_processed,
                duration_seconds=result.duration_seconds,
            )
        )

        log.info(
            "collection_completed",
            findings_collected=result.findings_collected,
            findings_processed=result.findings_processed,
            duration_seconds=f"{result.duration_seconds:.2f}",
        )
        return result

    async def _publish_failed(
        self, config: "ConnectorConfig", connector: "IConnector", exc: Exception
    ) -> None:
        await self._event_bus.publish(
            CollectionFailed(
                aggregate_id=config.id,
                connector=connector.connector_id,
                source=connector.source_type,
                error=str(exc),
            )
        )
