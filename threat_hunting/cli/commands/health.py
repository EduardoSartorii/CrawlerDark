"""`hunt health` — health check consolidado (connectors + exporters)."""

from __future__ import annotations

import typer
from rich.console import Console
from rich.table import Table

from .._helpers import bootstrap, run_async


def health(config_dir: str = typer.Option("config", help="Diretório de configuração.")) -> None:
    """Executa health checks e imprime um relatório."""
    run_async(lambda: _health(config_dir))


async def _health(config_dir: str) -> None:
    console = Console()
    root = await bootstrap(config_dir)
    connectors = []
    for name in root.enabled_connector_names():
        try:
            connectors.append(root.build_connector(name))
        except Exception:  # noqa: BLE001
            continue
    report = await root.health_uc.execute(connectors, list(root.exporters.values()))

    table = Table(title="Health Report", header_style="bold magenta")
    table.add_column("Component")
    table.add_column("Kind")
    table.add_column("Healthy")
    for name, ok in report.connectors.items():
        table.add_row(name, "connector", "[green]yes[/green]" if ok else "[red]no[/red]")
    for name, ok in report.exporters.items():
        table.add_row(name, "exporter", "[green]yes[/green]" if ok else "[red]no[/red]")
    console.print(table)
    console.print(f"Overall: {'[green]HEALTHY[/green]' if report.healthy else '[yellow]DEGRADED[/yellow]'}")

    for c in connectors:
        try:
            await c.close()
        except Exception:  # noqa: BLE001
            pass
    await root.shutdown()
