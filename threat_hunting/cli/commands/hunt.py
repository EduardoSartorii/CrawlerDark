"""
hunt run — Collection Commands
================================

Examples:
    hunt run reddit
    hunt run github
    hunt run threatfox
    hunt run all

Runs one or more connectors immediately (outside the scheduler).
"""

from __future__ import annotations

import asyncio
import time
from typing import Optional

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

hunt_app = typer.Typer(help="Run threat hunting connectors")
console = Console()


def _build_container() -> dict:
    """Build the minimal dependency graph needed for collection."""
    from threat_hunting.config.settings import get_settings
    from threat_hunting.infrastructure.connectors.registry import ConnectorRegistry
    from threat_hunting.infrastructure.database.session import DatabaseSession
    from threat_hunting.infrastructure.deduplication.engine import DeduplicationEngine
    from threat_hunting.infrastructure.detections.engine import DetectionEngine
    from threat_hunting.infrastructure.enrichment.engine import EnrichmentEngine
    from threat_hunting.infrastructure.correlation.engine import CorrelationEngine
    from threat_hunting.infrastructure.event_bus.in_memory_bus import InMemoryEventBus
    from threat_hunting.infrastructure.exporters.json_exporter import JSONExporter
    from threat_hunting.infrastructure.exporters.csv_exporter import CSVExporter
    from threat_hunting.infrastructure.observability.logging import configure_logging
    from threat_hunting.infrastructure.opsec.layer import OpsecLayer
    from threat_hunting.infrastructure.scoring.engine import ScoringEngine
    from threat_hunting.infrastructure.storage.unit_of_work import SQLAlchemyUnitOfWork
    from threat_hunting.core.application.pipeline.pipeline import PipelineBuilder
    from threat_hunting.core.application.pipeline.stages import (
        DetectionStage, ScoringStage, CorrelationStage,
        DeduplicationStage, EnrichmentStage, PersistenceStage,
    )
    from threat_hunting.core.application.use_cases.run_collection import RunCollectionUseCase
    import yaml

    settings = get_settings()
    configure_logging(settings.log_level)

    # Load opsec config
    opsec_config = {}
    cfg_path = settings.config_dir / "settings.yaml"
    if cfg_path.exists():
        with open(cfg_path) as f:
            raw = yaml.safe_load(f) or {}
        opsec_config = raw.get("opsec", {})

    opsec_layer = OpsecLayer.from_config(opsec_config)
    db = DatabaseSession(settings.database.url, echo=settings.database.echo)
    event_bus = InMemoryEventBus()
    uow = SQLAlchemyUnitOfWork(db)

    scoring_engine = ScoringEngine(settings.scoring.model_dump())
    detection_engine = DetectionEngine(
        rule_repo=_NullRuleRepo(),
        vip_repo=_NullVIPRepo(),
        keyword_repo=_NullKeywordRepo(),
        actor_repo=_NullActorRepo(),
        event_bus=event_bus,
    )
    correlation_engine = CorrelationEngine(
        finding_repo=_NullFindingRepo(),
        event_bus=event_bus,
    )
    dedup_engine = DeduplicationEngine(
        finding_repo=_NullFindingRepo(),
        event_bus=event_bus,
    )
    enrichment_engine = EnrichmentEngine(
        indicator_repo=_NullIndicatorRepo(),
        event_bus=event_bus,
        enabled=settings.enrichment_enabled,
    )

    json_exporter = JSONExporter(settings.exporters.json_output_path)
    csv_exporter = CSVExporter(settings.exporters.csv_output_path)

    pipeline = (
        PipelineBuilder(event_bus, settings.exporters.auto_export_threshold)
        .with_stage(DetectionStage(detection_engine))
        .with_stage(ScoringStage(scoring_engine))
        .with_stage(CorrelationStage(correlation_engine))
        .with_stage(DeduplicationStage(dedup_engine))
        .with_stage(EnrichmentStage(enrichment_engine))
        .with_stage(PersistenceStage(uow))
        .with_exporter(json_exporter)
        .with_exporter(csv_exporter)
        .build()
    )

    use_case = RunCollectionUseCase(pipeline=pipeline, event_bus=event_bus, uow=uow)
    registry = ConnectorRegistry()
    registry.discover()

    return {
        "use_case": use_case,
        "registry": registry,
        "opsec_layer": opsec_layer,
        "db": db,
    }


# ── Null repository stubs for CLI use (full repos need DB init) ───────────────

class _NullRuleRepo:
    async def list_enabled(self, rule_type=None): return []
    async def list_all(self): return []
    async def save(self, r): pass
    async def get_by_id(self, i): return None
    async def delete(self, i): pass

class _NullVIPRepo:
    async def list_enabled(self): return []
    async def list_all(self): return []
    async def save(self, v): pass
    async def get_by_id(self, i): return None
    async def delete(self, i): pass

class _NullKeywordRepo:
    async def list_enabled(self): return []
    async def list_all(self): return []
    async def save(self, k): pass
    async def get_by_id(self, i): return None
    async def delete(self, i): pass

class _NullActorRepo:
    async def list_all(self): return []
    async def save(self, a): pass
    async def get_by_id(self, i): return None
    async def get_by_name(self, n): return None
    async def delete(self, i): pass

class _NullFindingRepo:
    async def save(self, f): pass
    async def get_by_id(self, i): return None
    async def list(self, **kw): return []
    async def count(self, c=None): return 0
    async def delete(self, i): pass
    async def exists_by_hash(self, h): return False
    async def find_similar(self, f, t): return []

class _NullIndicatorRepo:
    async def save(self, i): pass
    async def get_by_id(self, i): return None
    async def get_by_value(self, t, v): return None
    async def list(self, **kw): return []
    async def count(self): return 0


@hunt_app.command("reddit")
def run_reddit(
    limit: int = typer.Option(50, help="Max posts to fetch"),
) -> None:
    """Run the Reddit connector."""
    _run_single("reddit", {"limit": limit})


@hunt_app.command("github")
def run_github(
    max_pages: int = typer.Option(2, help="Max result pages"),
) -> None:
    """Run the GitHub connector."""
    _run_single("github", {"max_pages": max_pages})


@hunt_app.command("threatfox")
def run_threatfox(
    days_back: int = typer.Option(1, help="Days to look back"),
) -> None:
    """Run the ThreatFox connector."""
    _run_single("threatfox", {"days_back": days_back})


@hunt_app.command("alienvault")
def run_alienvault(
    days_back: int = typer.Option(1, help="Days to look back"),
) -> None:
    """Run the AlienVault OTX connector."""
    _run_single("alienvault", {"days_back": days_back})


@hunt_app.command("urlhaus")
def run_urlhaus() -> None:
    """Run the URLhaus connector."""
    _run_single("urlhaus", {})


@hunt_app.command("paste")
def run_paste(limit: int = typer.Option(50, help="Max pastes")) -> None:
    """Run the Paste Sites connector."""
    _run_single("paste", {"limit": limit})


@hunt_app.command("rss")
def run_rss() -> None:
    """Run the RSS feed connector."""
    _run_single("rss", {})


@hunt_app.command("all")
def run_all(
    dry_run: bool = typer.Option(False, "--dry-run", help="List connectors without running"),
) -> None:
    """Run all enabled connectors."""
    container = _build_container()
    registry = container["registry"]
    enabled = [c["connector_id"] for c in registry.list_all() if c["enabled"] == "True"]
    console.print(f"[cyan]Running {len(enabled)} connectors: {', '.join(enabled)}[/]")
    if dry_run:
        return
    for cid in enabled:
        _run_single(cid, {}, container=container)


def _run_single(
    connector_id: str,
    params: dict,
    container: dict | None = None,
) -> None:
    """Run a single connector and print results."""
    if container is None:
        container = _build_container()

    use_case = container["use_case"]
    registry = container["registry"]
    opsec_layer = container["opsec_layer"]
    db = container["db"]

    async def _execute() -> None:
        await db.create_all()

        try:
            connector = registry.create(connector_id, opsec_layer=opsec_layer, config=params)
        except Exception as exc:
            console.print(f"[red]✗ Connector not found: {connector_id}[/] — {exc}")
            return

        from threat_hunting.core.domain.entities.connector_config import ConnectorConfig
        from threat_hunting.core.domain.value_objects.source import SourceType
        conn_config = ConnectorConfig(
            connector_id=connector_id,
            name=connector.connector_name,
            source_type=SourceType(connector.source_type),
        )

        with Progress(
            SpinnerColumn(),
            TextColumn(f"[cyan]Running {connector_id}...[/]"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            progress.add_task("run")
            result = await use_case.execute(connector, conn_config)

        status = "[green]✓[/]" if result.success else "[red]✗[/]"
        console.print(
            f"{status} [bold]{connector_id}[/] — "
            f"collected: {result.findings_collected}, "
            f"processed: {result.findings_processed}, "
            f"duration: {result.duration_seconds:.1f}s"
        )
        if result.error:
            console.print(f"  [red]Error: {result.error}[/]")

        await db.close()

    asyncio.run(_execute())
