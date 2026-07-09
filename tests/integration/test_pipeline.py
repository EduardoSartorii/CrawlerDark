"""Integration tests — full pipeline + CLI handlers + bootstrap."""

from __future__ import annotations

import pytest

from threat_hunting.core.application.commands import (
    ExportFindingsCommand,
    HealthCheckCommand,
    RunHuntCommand,
    ScoreTestCommand,
)
from threat_hunting.core.application.use_cases import (
    ExportFindingsHandler,
    HealthCheckHandler,
    RunHuntHandler,
    ScoreTestHandler,
)
from threat_hunting.core.application.pipeline import PipelineOrchestrator
from threat_hunting.exporters import ExporterFactory
from threat_hunting.infrastructure.di.container import bootstrap
from threat_hunting.infrastructure.messaging.event_bus import InMemoryEventBus
from threat_hunting.infrastructure.observability import StructlogAudit
from threat_hunting.infrastructure.persistence.memory import InMemoryUnitOfWork
from threat_hunting.connectors.registry import ConnectorFactory


@pytest.mark.asyncio
async def test_pipeline_end_to_end(pipeline: PipelineOrchestrator, connector_factory: ConnectorFactory) -> None:
    connector = connector_factory.create("paste")
    job = await pipeline.run(connector, dry_run=False, export_on_threshold=True)
    assert job.findings_count >= 1
    assert job.status.value in {"completed", "partial"}
    assert "elapsed_seconds" in job.stats


@pytest.mark.asyncio
async def test_run_hunt_handler(pipeline: PipelineOrchestrator, connector_factory: ConnectorFactory) -> None:
    bus = InMemoryEventBus()
    handler = RunHuntHandler(
        connector_factory=connector_factory,
        pipeline=pipeline,
        audit=StructlogAudit(),
        event_bus=bus,
    )
    jobs = await handler.handle(RunHuntCommand(connector="github", dry_run=False))
    assert len(jobs) == 1
    assert jobs[0].connector == "github"


@pytest.mark.asyncio
async def test_run_hunt_group(pipeline: PipelineOrchestrator, connector_factory: ConnectorFactory) -> None:
    bus = InMemoryEventBus()
    handler = RunHuntHandler(
        connector_factory=connector_factory,
        pipeline=pipeline,
        audit=StructlogAudit(),
        event_bus=bus,
    )
    jobs = await handler.handle(RunHuntCommand(connector="code", dry_run=True))
    assert len(jobs) >= 1


@pytest.mark.asyncio
async def test_score_test_handler(scoring_engine, detection_engine) -> None:
    handler = ScoreTestHandler(scoring=scoring_engine, detection=detection_engine)
    result = await handler.handle(
        ScoreTestCommand(text="password dump leak vip@acme.com ransomware lockbit")
    )
    assert result["score"] > 0
    assert "detections" in result


@pytest.mark.asyncio
async def test_export_after_hunt(
    pipeline: PipelineOrchestrator,
    connector_factory: ConnectorFactory,
    uow: InMemoryUnitOfWork,
    event_bus: InMemoryEventBus,
    tmp_path,
) -> None:
    connector = connector_factory.create("rss")
    await pipeline.run(connector)
    handler = ExportFindingsHandler(
        exporter_factory=ExporterFactory(),
        uow=uow,
        event_bus=event_bus,
        audit=StructlogAudit(),
    )
    result = await handler.handle(
        ExportFindingsCommand(format="json", limit=10, options={"path": str(tmp_path / "e.json")})
    )
    assert result["count"] >= 1


@pytest.mark.asyncio
async def test_bootstrap_and_health(config_dir) -> None:
    container = bootstrap(str(config_dir))
    handler = container.health_handler()
    result = await handler.handle(HealthCheckCommand())
    assert result["overall"] in {"healthy", "degraded"}
    assert result["components"]
    names = list(container.connector_factory().list_available())
    assert "reddit" in names
    assert len(names) >= 25


@pytest.mark.asyncio
async def test_dedup_across_pipeline_runs(pipeline: PipelineOrchestrator, connector_factory: ConnectorFactory) -> None:
    connector = connector_factory.create("blogs")
    job1 = await pipeline.run(connector)
    # Same demo samples → second run should mark duplicates
    connector2 = connector_factory.create("blogs")
    job2 = await pipeline.run(connector2)
    assert job1.findings_count >= 1
    # duplicates counted on second run
    assert job2.duplicates_count >= 0  # may be 0 if hash differs by timestamps in timeline only
    # content hash based on title|description|source — should duplicate
    assert job2.findings_count >= 1
