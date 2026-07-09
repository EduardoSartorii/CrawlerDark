"""
hunt scheduler — Scheduler Commands
=====================================

Examples:
    hunt scheduler run
    hunt scheduler list
    hunt scheduler status
"""

from __future__ import annotations

import asyncio
import signal

import typer
from rich.console import Console
from rich.table import Table

scheduler_app = typer.Typer(help="Manage the collection scheduler")
console = Console()


@scheduler_app.command("run")
def run_scheduler(
    config_path: str = typer.Option("config/settings.yaml", help="Path to settings YAML"),
) -> None:
    """Start the scheduler and run jobs according to their cron schedule."""
    from threat_hunting.config.settings import get_settings
    from threat_hunting.infrastructure.connectors.registry import ConnectorRegistry
    from threat_hunting.infrastructure.database.session import DatabaseSession
    from threat_hunting.infrastructure.event_bus.in_memory_bus import InMemoryEventBus
    from threat_hunting.infrastructure.observability.logging import configure_logging
    from threat_hunting.infrastructure.opsec.layer import OpsecLayer
    from threat_hunting.infrastructure.scheduler.scheduler import ThreatHuntingScheduler
    from threat_hunting.infrastructure.storage.unit_of_work import SQLAlchemyUnitOfWork
    from threat_hunting.core.application.use_cases.run_collection import RunCollectionUseCase
    from threat_hunting.infrastructure.detections.engine import DetectionEngine
    from threat_hunting.infrastructure.scoring.engine import ScoringEngine
    from threat_hunting.infrastructure.correlation.engine import CorrelationEngine
    from threat_hunting.infrastructure.deduplication.engine import DeduplicationEngine
    from threat_hunting.infrastructure.enrichment.engine import EnrichmentEngine
    from threat_hunting.infrastructure.exporters.json_exporter import JSONExporter
    from threat_hunting.core.application.pipeline.pipeline import PipelineBuilder
    from threat_hunting.core.application.pipeline.stages import (
        DetectionStage, ScoringStage, CorrelationStage,
        DeduplicationStage, EnrichmentStage, PersistenceStage,
    )
    from threat_hunting.cli.commands.hunt import (
        _NullRuleRepo, _NullVIPRepo, _NullKeywordRepo,
        _NullActorRepo, _NullFindingRepo, _NullIndicatorRepo,
    )
    import yaml

    settings = get_settings()
    configure_logging(settings.log_level)

    with open(config_path) as f:
        raw_config = yaml.safe_load(f) or {}

    opsec_layer = OpsecLayer.from_config(raw_config.get("opsec", {}))
    db = DatabaseSession(settings.database.url)
    event_bus = InMemoryEventBus()
    uow = SQLAlchemyUnitOfWork(db)

    scoring_engine = ScoringEngine(settings.scoring.model_dump())
    detection_engine = DetectionEngine(
        rule_repo=_NullRuleRepo(), vip_repo=_NullVIPRepo(),
        keyword_repo=_NullKeywordRepo(), actor_repo=_NullActorRepo(),
        event_bus=event_bus,
    )
    correlation_engine = CorrelationEngine(finding_repo=_NullFindingRepo(), event_bus=event_bus)
    dedup_engine = DeduplicationEngine(finding_repo=_NullFindingRepo(), event_bus=event_bus)
    enrichment_engine = EnrichmentEngine(indicator_repo=_NullIndicatorRepo(), event_bus=event_bus)

    pipeline = (
        PipelineBuilder(event_bus, settings.exporters.auto_export_threshold)
        .with_stage(DetectionStage(detection_engine))
        .with_stage(ScoringStage(scoring_engine))
        .with_stage(CorrelationStage(correlation_engine))
        .with_stage(DeduplicationStage(dedup_engine))
        .with_stage(EnrichmentStage(enrichment_engine))
        .with_stage(PersistenceStage(uow))
        .with_exporter(JSONExporter(settings.exporters.json_output_path))
        .build()
    )
    use_case = RunCollectionUseCase(pipeline=pipeline, event_bus=event_bus, uow=uow)
    registry = ConnectorRegistry()
    registry.discover()

    scheduler = ThreatHuntingScheduler(
        use_case=use_case,
        connector_registry=registry,
        opsec_layer=opsec_layer,
        uow=uow,
    )

    job_configs = raw_config.get("scheduler", {}).get("jobs", [])
    scheduler.configure(job_configs)

    async def _run():
        await db.create_all()
        scheduler.start()
        console.print(f"[green]✓[/] Scheduler started with {len(scheduler.list_jobs())} jobs.")
        console.print("[dim]Press Ctrl+C to stop.[/]")

        loop = asyncio.get_event_loop()
        stop = asyncio.Event()

        def _handle_signal():
            stop.set()

        loop.add_signal_handler(signal.SIGINT, _handle_signal)
        loop.add_signal_handler(signal.SIGTERM, _handle_signal)

        await stop.wait()
        scheduler.shutdown()
        await db.close()
        console.print("[yellow]Scheduler stopped.[/]")

    asyncio.run(_run())


@scheduler_app.command("list")
def list_jobs(
    config_path: str = typer.Option("config/settings.yaml", help="Path to settings YAML"),
) -> None:
    """List all configured scheduler jobs."""
    import yaml

    with open(config_path) as f:
        raw = yaml.safe_load(f) or {}

    jobs = raw.get("scheduler", {}).get("jobs", [])
    table = Table(title="Scheduled Jobs", show_header=True)
    table.add_column("ID", style="cyan")
    table.add_column("Connector")
    table.add_column("Cron")
    table.add_column("Enabled")

    for job in jobs:
        enabled = "[green]✓[/]" if job.get("enabled", True) else "[red]✗[/]"
        table.add_row(
            job.get("id", "-"),
            job.get("connector", "-"),
            job.get("cron", "-"),
            enabled,
        )
    console.print(table)
