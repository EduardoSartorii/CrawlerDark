"""`hunt connector list|enable|disable` — gestão dos conectores."""

from __future__ import annotations

from pathlib import Path

import typer
import yaml
from rich.console import Console
from rich.table import Table

from .._helpers import bootstrap, run_async

app = typer.Typer(help="Gerencia conectores.")
console = Console()


@app.command("list")
def list_(
    config_dir: str = typer.Option("config", help="Diretório de configuração."),
) -> None:
    """Lista conectores registrados e status."""
    run_async(lambda: _list(config_dir))


async def _list(config_dir: str) -> None:
    root = await bootstrap(config_dir)
    table = Table(title="Connectors", header_style="bold magenta")
    table.add_column("Name")
    table.add_column("Type")
    table.add_column("Enabled")
    table.add_column("OPSEC")
    for name in sorted(root.all_connector_names()):
        cfg = root._connector_configs[name]  # noqa: SLF001 — CLI conhece a estrutura
        status = "[green]yes[/green]" if cfg.enabled else "[red]no[/red]"
        table.add_row(name, cfg.type, status, cfg.opsec_profile)
    console.print(table)
    console.print(
        f"[dim]Total registered plugin classes:[/dim] "
        f"{len(root.connector_factory._opsec.profiles)} OPSEC profiles."  # type: ignore[attr-defined]
    )
    await root.shutdown()


@app.command("enable")
def enable(
    name: str = typer.Argument(..., help="Nome do conector."),
    config_dir: str = typer.Option("config", help="Diretório de configuração."),
) -> None:
    """Habilita um conector no YAML."""
    _toggle(name, config_dir, enabled=True)


@app.command("disable")
def disable(
    name: str = typer.Argument(..., help="Nome do conector."),
    config_dir: str = typer.Option("config", help="Diretório de configuração."),
) -> None:
    """Desabilita um conector no YAML."""
    _toggle(name, config_dir, enabled=False)


def _toggle(name: str, config_dir: str, *, enabled: bool) -> None:
    path = Path(config_dir) / "connectors.yaml"
    if not path.exists():
        console.print(f"[red]{path} não encontrado[/red]")
        raise typer.Exit(2)
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    connectors = data.get("connectors", {})
    if name not in connectors:
        console.print(f"[red]Connector não configurado[/red]: {name}")
        raise typer.Exit(2)
    connectors[name]["enabled"] = enabled
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    verb = "enabled" if enabled else "disabled"
    console.print(f"[green]Connector {name} {verb}[/green]")
