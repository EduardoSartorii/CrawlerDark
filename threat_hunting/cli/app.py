"""
Threat Hunting Platform CLI
============================

Entry point for all CLI operations.
Commands are registered as Typer sub-apps grouped by domain area.

Available command groups:
    hunt run <connector>          — run a connector immediately
    hunt connector <enable|disable|list> — manage connectors
    hunt scheduler run            — start the scheduler
    hunt export <platform>        — export findings
    hunt score test               — test scoring engine
    hunt health                   — check platform health
    hunt db init                  — initialize the database

All commands use async execution via asyncio.run().
Configuration is loaded from config/settings.yaml + .env.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from threat_hunting.cli.commands.connector import connector_app
from threat_hunting.cli.commands.export_cmd import export_app
from threat_hunting.cli.commands.hunt import hunt_app
from threat_hunting.cli.commands.scheduler_cmd import scheduler_app

app = typer.Typer(
    name="hunt",
    help="Threat Hunting Platform — Professional CTI Collection Tool",
    rich_markup_mode="rich",
    no_args_is_help=True,
    add_completion=True,
)

console = Console()

app.add_typer(hunt_app, name="run", help="Run one or more connectors")
app.add_typer(connector_app, name="connector", help="Manage connectors")
app.add_typer(export_app, name="export", help="Export findings")
app.add_typer(scheduler_app, name="scheduler", help="Manage the scheduler")


@app.command("health")
def health_check(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed health info"),
) -> None:
    """Check the health of all platform components."""
    from threat_hunting.infrastructure.observability.health import HealthChecker
    from threat_hunting.config.settings import get_settings
    from threat_hunting.infrastructure.observability.logging import configure_logging

    settings = get_settings()
    configure_logging(settings.log_level)

    async def _run() -> None:
        checker = HealthChecker()
        health = await checker.check_all()

        table = Table(title="Platform Health", show_header=True)
        table.add_column("Component", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Message")
        table.add_column("Latency")

        for component in health.components:
            status = "[green]✓ HEALTHY[/]" if component.healthy else "[red]✗ UNHEALTHY[/]"
            table.add_row(
                component.name,
                status,
                component.message[:60],
                f"{component.latency_ms:.0f}ms" if component.latency_ms > 0 else "-",
            )

        console.print(table)
        overall = "[green]PLATFORM HEALTHY[/]" if health.is_healthy else "[red]PLATFORM DEGRADED[/]"
        console.print(f"\n{overall}: {health.summary}")

    asyncio.run(_run())


@app.command("db")
def db_init(
    action: str = typer.Argument("init", help="Database action: init | reset"),
) -> None:
    """Manage the platform database."""
    from threat_hunting.infrastructure.database.session import DatabaseSession
    from threat_hunting.config.settings import get_settings

    settings = get_settings()

    async def _run() -> None:
        db = DatabaseSession(settings.database.url, echo=settings.database.echo)
        if action == "init":
            await db.create_all()
            console.print("[green]✓[/] Database initialized successfully.")
        elif action == "reset":
            confirm = typer.confirm("This will DELETE all data. Are you sure?")
            if confirm:
                await db.drop_all()
                await db.create_all()
                console.print("[yellow]⚠[/] Database reset complete.")
        await db.close()

    asyncio.run(_run())


@app.command("version")
def version() -> None:
    """Show the platform version."""
    from threat_hunting import __version__
    console.print(f"Threat Hunting Platform v{__version__}")


if __name__ == "__main__":
    app()
