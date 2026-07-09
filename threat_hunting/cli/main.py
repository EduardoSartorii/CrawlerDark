"""
Threat Hunting Platform — CLI Entry Point.

All platform operations are accessible via the `hunt` command.

Usage:
    hunt run reddit              — run Reddit connector
    hunt run github              — run GitHub connector
    hunt run all                 — run all enabled connectors
    hunt connector list          — list all connectors
    hunt connector enable reddit — enable a connector
    hunt connector disable reddit— disable a connector
    hunt scheduler run           — start the scheduler
    hunt export json             — export findings to JSON
    hunt export csv              — export findings to CSV
    hunt export stix             — export findings to STIX 2.1
    hunt export misp             — export findings to MISP
    hunt score test <text>       — test scoring on raw text
    hunt findings list           — list recent findings
    hunt findings show <id>      — show finding details
    hunt health                  — check platform health

Design: Typer app with subcommand groups
"""

from __future__ import annotations

import asyncio
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich import print as rprint

from ..config.logging import configure_logging
from ..config.settings import get_settings

app = typer.Typer(
    name="hunt",
    help="Threat Hunting Platform — CTI Collection & Analysis CLI",
    rich_markup_mode="rich",
    no_args_is_help=True,
)

# Sub-command groups
run_app = typer.Typer(help="Run collection connectors", no_args_is_help=True)
connector_app = typer.Typer(help="Manage connectors", no_args_is_help=True)
export_app = typer.Typer(help="Export findings", no_args_is_help=True)
findings_app = typer.Typer(help="Manage findings", no_args_is_help=True)
scheduler_app = typer.Typer(help="Manage the scheduler", no_args_is_help=True)

app.add_typer(run_app, name="run")
app.add_typer(connector_app, name="connector")
app.add_typer(export_app, name="export")
app.add_typer(findings_app, name="findings")
app.add_typer(scheduler_app, name="scheduler")

console = Console()


def _get_container() -> "PlatformContainer":  # type: ignore[name-defined]
    """Bootstrap and return the DI container."""
    from ..config.container import PlatformContainer
    settings = get_settings()
    container = PlatformContainer()
    return container


def _run_async(coro: Any) -> Any:  # type: ignore[misc]
    """Run an async function from sync CLI context."""
    return asyncio.run(coro)


# ── hunt run <connector> ───────────────────────────────────────────────────────


@run_app.command("reddit")
def run_reddit(
    dry_run: bool = typer.Option(False, "--dry-run", help="Don't persist findings"),
    limit: Optional[int] = typer.Option(None, "--limit", help="Max findings"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """[bold green]Run the Reddit connector[/bold green]."""
    _run_connector("reddit", dry_run=dry_run, limit=limit, verbose=verbose)


@run_app.command("github")
def run_github(
    dry_run: bool = typer.Option(False, "--dry-run"),
    limit: Optional[int] = typer.Option(None, "--limit"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """[bold green]Run the GitHub connector[/bold green]."""
    _run_connector("github", dry_run=dry_run, limit=limit, verbose=verbose)


@run_app.command("threatfox")
def run_threatfox(
    dry_run: bool = typer.Option(False, "--dry-run"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """[bold green]Run the ThreatFox IOC feed connector[/bold green]."""
    _run_connector("threatfox", dry_run=dry_run, verbose=verbose)


@run_app.command("rss")
def run_rss(
    dry_run: bool = typer.Option(False, "--dry-run"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """[bold green]Run the RSS/News feed connector[/bold green]."""
    _run_connector("rss", dry_run=dry_run, verbose=verbose)


@run_app.command("social")
def run_social(
    dry_run: bool = typer.Option(False, "--dry-run"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """[bold blue]Run all social media connectors[/bold blue]."""
    _run_group("social", dry_run=dry_run, verbose=verbose)


@run_app.command("feeds")
def run_feeds(
    dry_run: bool = typer.Option(False, "--dry-run"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """[bold blue]Run all intelligence feed connectors[/bold blue]."""
    _run_group("feeds", dry_run=dry_run, verbose=verbose)


@run_app.command("all")
def run_all(
    dry_run: bool = typer.Option(False, "--dry-run", help="Don't persist findings"),
    parallel: bool = typer.Option(True, "--parallel/--sequential"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """[bold red]Run ALL enabled connectors[/bold red]."""
    _run_group("all", dry_run=dry_run, verbose=verbose)


def _run_connector(
    connector_id: str,
    dry_run: bool = False,
    limit: int | None = None,
    verbose: bool = False,
) -> None:
    """Internal helper: run a single connector."""
    settings = get_settings()
    configure_logging(level="DEBUG" if verbose else settings.log_level)

    console.print(f"\n[bold cyan]🎯 Threat Hunting Platform[/bold cyan]")
    console.print(f"[dim]Running connector: [green]{connector_id}[/green][/dim]")
    if dry_run:
        console.print("[yellow]⚠ DRY RUN mode — findings will not be persisted[/yellow]")

    async def _run() -> None:
        from ..config.container import PlatformContainer
        from ..infrastructure.connectors import (
            RedditConnector, GitHubConnector, ThreatFoxConnector,
            RSSConnector, PasteSiteConnector
        )
        from ..infrastructure.detections.engine import DetectionEngine
        from ..infrastructure.scoring.engine import ScoringEngine
        from ..infrastructure.correlation.engine import CorrelationEngine
        from ..infrastructure.enrichment.engine import EnrichmentEngine
        from ..infrastructure.pipelines.collection_pipeline import CollectionPipeline, PipelineConfig
        from ..core.domain.services.deduplication_service import DeduplicationService
        from ..infrastructure.storage.database import DatabaseManager

        _connector_map = {
            "reddit": RedditConnector,
            "github": GitHubConnector,
            "threatfox": ThreatFoxConnector,
            "rss": RSSConnector,
            "paste_sites": PasteSiteConnector,
        }

        connector_class = _connector_map.get(connector_id)
        if not connector_class:
            console.print(f"[red]❌ Unknown connector: {connector_id}[/red]")
            raise typer.Exit(1)

        connector = connector_class()
        detection = DetectionEngine()
        scoring = ScoringEngine()
        correlation = CorrelationEngine()
        enrichment = EnrichmentEngine()
        enrichment.use_defaults()

        pipeline = CollectionPipeline(
            connector=connector,
            detection_engine=detection,
            scoring_engine=scoring,
            correlation_engine=correlation,
            enrichment_engine=enrichment,
            config=PipelineConfig(),
        )

        with console.status(f"[bold green]Running {connector_id}..."):
            findings = await pipeline.execute(
                connector_id=connector_id,
                dry_run=dry_run,
                limit=limit,
            )

        _print_findings_table(findings)

        if not dry_run and findings:
            db = DatabaseManager.sqlite()
            await db.create_tables()
            from ..infrastructure.storage.unit_of_work import SQLAlchemyUnitOfWork
            from ..core.domain.services.deduplication_service import DeduplicationService
            dedup = DeduplicationService()
            uow = SQLAlchemyUnitOfWork(db.session_factory)
            saved = 0
            async with uow:
                for finding in findings:
                    fingerprint = dedup.compute_fingerprint(finding)
                    existing = await uow.findings.get_by_fingerprint(fingerprint)
                    if not existing:
                        await uow.findings.save(finding)
                        saved += 1
            console.print(f"\n[green]✓ Saved {saved} new findings[/green]")

    _run_async(_run())


def _run_group(group: str, dry_run: bool = False, verbose: bool = False) -> None:
    """Run all connectors in a group."""
    settings = get_settings()
    configure_logging(level="DEBUG" if verbose else settings.log_level)
    console.print(f"[bold cyan]Running connector group: [yellow]{group}[/yellow][/bold cyan]")

    from ..infrastructure.plugins.registry import ConnectorRegistry
    registry = ConnectorRegistry.create()
    ids = registry.get_enabled_connector_ids(None if group == "all" else group)

    if not ids:
        console.print(f"[yellow]No enabled connectors in group '{group}'[/yellow]")
        return

    console.print(f"[dim]Connectors: {', '.join(ids)}[/dim]")
    for cid in ids:
        console.print(f"\n[bold]→ Running: {cid}[/bold]")
        _run_connector(cid, dry_run=dry_run, verbose=verbose)


def _print_findings_table(findings: list) -> None:
    """Print a Rich table of findings."""
    if not findings:
        console.print("[yellow]No findings produced[/yellow]")
        return

    table = Table(
        title=f"[bold]Findings ({len(findings)} total)[/bold]",
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("ID", style="dim", width=10)
    table.add_column("Title", max_width=50)
    table.add_column("Category", style="cyan")
    table.add_column("Severity", style="bold")
    table.add_column("Score", justify="right")
    table.add_column("Tags")

    for f in findings[:20]:
        severity_color = {
            "INFO": "white",
            "LOW": "green",
            "MEDIUM": "yellow",
            "HIGH": "orange1",
            "CRITICAL": "red",
        }.get(f.severity.level.name, "white")

        table.add_row(
            f.id[:8] + "…",
            f.title[:50],
            f.category.value,
            f"[{severity_color}]{f.severity.level.name}[/{severity_color}]",
            f"{f.score.value:.1f}",
            ", ".join(f.tags[:3]),
        )

    if len(findings) > 20:
        table.add_row("...", f"({len(findings) - 20} more)", "", "", "", "")

    console.print(table)


# ── hunt connector * ──────────────────────────────────────────────────────────


@connector_app.command("list")
def connector_list() -> None:
    """List all registered connectors."""
    from ..infrastructure.plugins.registry import ConnectorRegistry
    registry = ConnectorRegistry.create()

    table = Table(title="Registered Connectors", show_header=True, header_style="bold blue")
    table.add_column("ID", style="cyan")
    table.add_column("Group")
    table.add_column("Source Type")
    table.add_column("Enabled", justify="center")
    table.add_column("Description")

    for c in registry.list_connectors():
        enabled_str = "[green]✓[/green]" if c["enabled"] else "[red]✗[/red]"
        table.add_row(
            c["connector_id"],
            c["group"],
            str(c["source_type"]),
            enabled_str,
            c["description"][:50],
        )

    console.print(table)


@connector_app.command("enable")
def connector_enable(
    connector_id: str = typer.Argument(..., help="Connector ID to enable"),
) -> None:
    """Enable a connector."""
    from ..infrastructure.plugins.registry import ConnectorRegistry
    registry = ConnectorRegistry.create()
    registry.enable(connector_id)
    console.print(f"[green]✓ Connector '{connector_id}' enabled[/green]")


@connector_app.command("disable")
def connector_disable(
    connector_id: str = typer.Argument(..., help="Connector ID to disable"),
) -> None:
    """Disable a connector."""
    from ..infrastructure.plugins.registry import ConnectorRegistry
    registry = ConnectorRegistry.create()
    registry.disable(connector_id)
    console.print(f"[yellow]⏸ Connector '{connector_id}' disabled[/yellow]")


# ── hunt export * ─────────────────────────────────────────────────────────────


@export_app.command("json")
def export_json(
    output: str = typer.Option("./data/findings.json", "--output", "-o"),
    min_score: float = typer.Option(0.0, "--min-score"),
) -> None:
    """Export findings to JSON."""
    _export_findings("json", {"output_path": output}, min_score)


@export_app.command("csv")
def export_csv(
    output: str = typer.Option("./data/findings.csv", "--output", "-o"),
    min_score: float = typer.Option(0.0, "--min-score"),
) -> None:
    """Export findings to CSV."""
    _export_findings("csv", {"output_path": output}, min_score)


@export_app.command("stix")
def export_stix(
    output: str = typer.Option("./data/findings.stix.json", "--output", "-o"),
    min_score: float = typer.Option(5.0, "--min-score"),
) -> None:
    """Export findings to STIX 2.1."""
    _export_findings("stix", {"output_path": output}, min_score)


@export_app.command("misp")
def export_misp(
    min_score: float = typer.Option(7.0, "--min-score"),
) -> None:
    """Export high-confidence findings to MISP."""
    settings = get_settings()
    _export_findings(
        "misp",
        {"url": settings.misp.url, "key": settings.misp.key},
        min_score,
    )


def _export_findings(exporter_id: str, config: dict, min_score: float) -> None:
    """Internal: load findings from DB and export."""
    from ..infrastructure.exporters.json_exporter import JSONExporter
    from ..infrastructure.exporters.csv_exporter import CSVExporter
    from ..infrastructure.exporters.stix_exporter import STIX21Exporter
    from ..infrastructure.exporters.misp_exporter import MISPExporter

    exporters = {
        "json": JSONExporter,
        "csv": CSVExporter,
        "stix": STIX21Exporter,
        "misp": MISPExporter,
    }
    exporter_class = exporters.get(exporter_id)
    if not exporter_class:
        console.print(f"[red]Unknown exporter: {exporter_id}[/red]")
        raise typer.Exit(1)

    async def _run() -> None:
        from ..infrastructure.storage.database import DatabaseManager
        from ..infrastructure.storage.sqlalchemy_repository import SQLAlchemyFindingRepository
        from sqlalchemy.ext.asyncio import AsyncSession

        db = DatabaseManager.sqlite()
        await db.create_tables()

        async with db.session_factory() as session:
            repo = SQLAlchemyFindingRepository(session)
            findings_page = await repo.find_by_score_range(min_score)
            findings = findings_page.items

        if not findings:
            console.print("[yellow]No findings matching criteria[/yellow]")
            return

        exporter = exporter_class(config=config)
        result = await exporter.export(findings)

        if result.success:
            console.print(f"[green]✓ Exported {result.exported_count} findings via {exporter_id}[/green]")
        else:
            console.print(f"[red]Export failed: {result.errors}[/red]")

    _run_async(_run())


# ── hunt findings * ───────────────────────────────────────────────────────────


@findings_app.command("list")
def findings_list(
    limit: int = typer.Option(20, "--limit", "-n"),
    min_score: float = typer.Option(0.0, "--min-score"),
    category: Optional[str] = typer.Option(None, "--category"),
) -> None:
    """List recent findings from the database."""
    async def _run() -> None:
        from ..infrastructure.storage.database import DatabaseManager
        from ..infrastructure.storage.sqlalchemy_repository import SQLAlchemyFindingRepository
        from ..core.domain.repositories import PageSpec

        db = DatabaseManager.sqlite()
        await db.create_tables()
        async with db.session_factory() as session:
            repo = SQLAlchemyFindingRepository(session)
            page = await repo.find_by_score_range(
                min_score=min_score,
                page=PageSpec(page=1, page_size=limit),
            )
        _print_findings_table(page.items)
        console.print(f"[dim]Total: {page.total} findings[/dim]")

    _run_async(_run())


@findings_app.command("show")
def findings_show(
    finding_id: str = typer.Argument(..., help="Finding ID (full or partial)"),
) -> None:
    """Show detailed finding information."""
    async def _run() -> None:
        from ..infrastructure.storage.database import DatabaseManager
        from ..infrastructure.storage.sqlalchemy_repository import SQLAlchemyFindingRepository

        db = DatabaseManager.sqlite()
        async with db.session_factory() as session:
            repo = SQLAlchemyFindingRepository(session)
            f = await repo.get_by_id(finding_id)

        if not f:
            console.print(f"[red]Finding '{finding_id}' not found[/red]")
            return

        console.print(f"\n[bold cyan]Finding: {f.id}[/bold cyan]")
        console.print(f"[bold]{f.title}[/bold]")
        console.print()
        console.print(f"  Category:  [cyan]{f.category.value}[/cyan]")
        console.print(f"  Severity:  [bold]{f.severity.level.name}[/bold]")
        console.print(f"  Score:     [bold]{f.score.value:.1f}[/bold] (conf: {f.confidence:.0%})")
        console.print(f"  Source:    {f.source}")
        console.print(f"  Connector: {f.connector}")
        console.print(f"  TLP:       {f.tlp}")
        console.print(f"  Tags:      {', '.join(f.tags)}")
        if f.source_url:
            console.print(f"  URL:       {f.source_url}")
        if f.threat_actor:
            console.print(f"  Actor:     [red]{f.threat_actor}[/red]")
        console.print(f"  Created:   {f.created_at.isoformat()}")
        if f.description:
            console.print(f"\n[dim]{f.description[:500]}[/dim]")

    _run_async(_run())


# ── hunt scheduler * ──────────────────────────────────────────────────────────


@scheduler_app.command("run")
def scheduler_run(
    config_file: Optional[str] = typer.Option(None, "--config", "-c"),
) -> None:
    """Start the collection scheduler (runs indefinitely)."""
    configure_logging()
    console.print("[bold green]🕐 Starting Threat Hunting Scheduler[/bold green]")

    async def _run() -> None:
        import asyncio
        from ..infrastructure.scheduler.scheduler import CollectionScheduler

        sched = CollectionScheduler()
        # Default: run all connectors every hour
        from ..infrastructure.plugins.registry import ConnectorRegistry
        registry = ConnectorRegistry.create()
        enabled_ids = registry.get_enabled_connector_ids()

        for i, cid in enumerate(enabled_ids):
            sched.add_interval_job(
                job_id=f"auto_{cid}",
                connector_id=cid,
                minutes=60,
            )
            console.print(f"  [dim]Scheduled: {cid} (every 60 min)[/dim]")

        sched.start()
        console.print(f"[green]✓ Scheduler started with {len(enabled_ids)} jobs[/green]")
        console.print("[dim]Press Ctrl+C to stop[/dim]")

        try:
            while True:
                await asyncio.sleep(60)
        except (KeyboardInterrupt, asyncio.CancelledError):
            sched.shutdown()
            console.print("[yellow]Scheduler stopped[/yellow]")

    _run_async(_run())


@scheduler_app.command("list")
def scheduler_list() -> None:
    """List scheduled jobs."""
    console.print("[yellow]Start the scheduler with 'hunt scheduler run' to see live jobs[/yellow]")


# ── hunt health ───────────────────────────────────────────────────────────────


@app.command("health")
def health() -> None:
    """Check platform health status."""
    from ..infrastructure.plugins.registry import ConnectorRegistry

    console.print("[bold cyan]🏥 Platform Health Check[/bold cyan]\n")

    # Check connector registry
    registry = ConnectorRegistry.create()
    connector_count = len(registry)
    enabled_count = len(registry.get_enabled_connector_ids())
    console.print(f"  Connectors:  {connector_count} registered, {enabled_count} enabled [green]✓[/green]")

    # Check database
    async def _check_db() -> bool:
        from ..infrastructure.storage.database import DatabaseManager
        try:
            db = DatabaseManager.sqlite()
            await db.create_tables()
            return True
        except Exception:
            return False

    db_ok = _run_async(_check_db())
    db_status = "[green]✓[/green]" if db_ok else "[red]✗[/red]"
    console.print(f"  Database:    {'OK' if db_ok else 'FAILED'} {db_status}")

    console.print(f"\n[dim]Platform ready[/dim]")


# ── hunt score test ───────────────────────────────────────────────────────────


@app.command("score")
def score_test(
    text: str = typer.Argument(..., help="Text to score"),
) -> None:
    """Test the scoring engine on arbitrary text."""
    from ..infrastructure.detections.engine import DetectionEngine
    from ..infrastructure.scoring.engine import ScoringEngine
    from ..core.domain.entities.finding import Finding
    from ..core.domain.value_objects import ThreatCategory
    from ..core.domain.value_objects.source_type import SourceType

    finding = Finding.create(
        title=text[:100],
        source="cli-test",
        connector="test",
        category=ThreatCategory.UNKNOWN,
        source_type=SourceType.INTERNAL,
        description=text,
        raw_data=text,
    )

    detection = DetectionEngine()
    scoring = ScoringEngine()
    detection.evaluate(finding)
    score, breakdown = scoring.score(finding)
    finding.apply_score(score)

    console.print(f"\n[bold]Score Result[/bold]")
    console.print(f"  Score:    [bold]{score.value:.1f}[/bold]")
    console.print(f"  Severity: [bold]{finding.severity.level.name}[/bold]")
    console.print(f"  Confidence: {score.confidence:.0%}")
    console.print(f"\n[dim]{breakdown.explain()}[/dim]")


# Required for type hints in _run_connector
from typing import Any

if __name__ == "__main__":
    app()
