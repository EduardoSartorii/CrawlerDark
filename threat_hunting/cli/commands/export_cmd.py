"""
hunt export — Export Commands
==============================

Examples:
    hunt export json
    hunt export csv
    hunt export misp
    hunt export stix
    hunt export webhook
"""

from __future__ import annotations

import asyncio
from typing import Optional

import typer
from rich.console import Console

export_app = typer.Typer(help="Export findings to external platforms")
console = Console()


def _get_uow():
    from threat_hunting.config.settings import get_settings
    from threat_hunting.infrastructure.database.session import DatabaseSession
    from threat_hunting.infrastructure.storage.unit_of_work import SQLAlchemyUnitOfWork
    settings = get_settings()
    db = DatabaseSession(settings.database.url)
    return SQLAlchemyUnitOfWork(db), db


@export_app.command("json")
def export_json(
    limit: int = typer.Option(100, help="Max findings to export"),
    severity: Optional[str] = typer.Option(None, help="Filter by minimum severity"),
) -> None:
    """Export findings to JSON files."""
    from threat_hunting.core.application.use_cases.export_findings import (
        ExportCriteria, ExportFindingsUseCase,
    )
    from threat_hunting.infrastructure.exporters.json_exporter import JSONExporter
    from threat_hunting.config.settings import get_settings

    settings = get_settings()
    uow, db = _get_uow()
    exporter = JSONExporter(settings.exporters.json_output_path)
    use_case = ExportFindingsUseCase(uow)
    criteria = ExportCriteria(limit=limit, min_severity=severity)

    async def _run():
        await db.create_all()
        result = await use_case.execute(exporter, criteria)
        console.print(f"[green]✓[/] Exported {result.total_succeeded}/{result.total_attempted} findings to JSON")
        await db.close()

    asyncio.run(_run())


@export_app.command("csv")
def export_csv(limit: int = typer.Option(100, help="Max findings to export")) -> None:
    """Export findings to CSV files."""
    from threat_hunting.core.application.use_cases.export_findings import (
        ExportCriteria, ExportFindingsUseCase,
    )
    from threat_hunting.infrastructure.exporters.csv_exporter import CSVExporter
    from threat_hunting.config.settings import get_settings

    settings = get_settings()
    uow, db = _get_uow()
    exporter = CSVExporter(settings.exporters.csv_output_path)
    use_case = ExportFindingsUseCase(uow)
    criteria = ExportCriteria(limit=limit)

    async def _run():
        await db.create_all()
        result = await use_case.execute(exporter, criteria)
        console.print(f"[green]✓[/] Exported {result.total_succeeded}/{result.total_attempted} findings to CSV")
        await db.close()

    asyncio.run(_run())


@export_app.command("misp")
def export_misp(
    limit: int = typer.Option(50, help="Max findings to export"),
    min_score: float = typer.Option(6.0, help="Minimum score for MISP export"),
) -> None:
    """Export high-scoring findings to MISP."""
    from threat_hunting.core.application.use_cases.export_findings import (
        ExportCriteria, ExportFindingsUseCase,
    )
    from threat_hunting.infrastructure.exporters.misp_exporter import MISPExporter
    from threat_hunting.config.settings import get_settings
    import os

    settings = get_settings()
    misp_url = os.environ.get("MISP_URL", settings.misp.url)
    misp_key = os.environ.get("MISP_KEY", settings.misp.key)

    if not misp_url or not misp_key:
        console.print("[red]✗ MISP_URL and MISP_KEY must be configured.[/]")
        raise typer.Exit(1)

    uow, db = _get_uow()
    exporter = MISPExporter(misp_url, misp_key, settings.misp.verify_cert)
    use_case = ExportFindingsUseCase(uow)
    criteria = ExportCriteria(limit=limit, min_severity="high")

    async def _run():
        await db.create_all()
        result = await use_case.execute(exporter, criteria)
        console.print(f"[green]✓[/] Exported {result.total_succeeded}/{result.total_attempted} findings to MISP")
        await db.close()

    asyncio.run(_run())
