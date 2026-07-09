"""
hunt connector — Connector Management Commands
===============================================

Examples:
    hunt connector list
    hunt connector enable reddit
    hunt connector disable github
    hunt connector health reddit
"""

from __future__ import annotations

import typer
from rich.console import Console
from rich.table import Table

connector_app = typer.Typer(help="Manage connectors")
console = Console()


@connector_app.command("list")
def list_connectors() -> None:
    """List all registered connectors and their status."""
    from threat_hunting.infrastructure.connectors.registry import ConnectorRegistry

    registry = ConnectorRegistry()
    registry.discover()

    table = Table(title="Registered Connectors", show_header=True)
    table.add_column("ID", style="cyan")
    table.add_column("Name")
    table.add_column("Source Type")
    table.add_column("Enabled")

    for c in registry.list_all():
        enabled = "[green]✓[/]" if c["enabled"] == "True" else "[red]✗[/]"
        table.add_row(c["connector_id"], c["name"], c["source_type"], enabled)

    console.print(table)
    console.print(f"\nTotal: {len(registry.registered_ids)} connectors registered")


@connector_app.command("enable")
def enable_connector(
    connector_id: str = typer.Argument(..., help="Connector ID to enable"),
) -> None:
    """Enable a connector."""
    from threat_hunting.infrastructure.connectors.registry import ConnectorRegistry

    registry = ConnectorRegistry()
    registry.discover()
    registry.enable(connector_id)
    console.print(f"[green]✓[/] Connector [bold]{connector_id}[/] enabled.")


@connector_app.command("disable")
def disable_connector(
    connector_id: str = typer.Argument(..., help="Connector ID to disable"),
) -> None:
    """Disable a connector."""
    from threat_hunting.infrastructure.connectors.registry import ConnectorRegistry

    registry = ConnectorRegistry()
    registry.discover()
    registry.disable(connector_id)
    console.print(f"[yellow]⚠[/] Connector [bold]{connector_id}[/] disabled.")
