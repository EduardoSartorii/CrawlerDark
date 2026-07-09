"""`hunt export <target>` — exportação sob demanda."""

from __future__ import annotations

import typer
from rich.console import Console

from .._helpers import bootstrap, run_async

app = typer.Typer(help="Exporta findings para destinos configurados.")
console = Console()


@app.callback(invoke_without_command=True)
def _default(
    ctx: typer.Context,
    target: str | None = typer.Argument(None, help="Nome do exporter (misp, splunk, elastic, json, csv, stix, webhook)."),
    min_score: float = typer.Option(0.0, help="Score mínimo para exportação."),
    limit: int = typer.Option(500, help="Máximo de findings por batch."),
    config_dir: str = typer.Option("config", help="Diretório de configuração."),
) -> None:
    if ctx.invoked_subcommand is not None:
        return
    if not target:
        console.print("[red]Target obrigatório (ex: misp, stix, json)[/red]")
        raise typer.Exit(2)
    aliases = {"elastic": "opensearch"}
    target = aliases.get(target, target)
    run_async(lambda: _export(target, min_score, limit, config_dir))


async def _export(target: str, min_score: float, limit: int, config_dir: str) -> None:
    root = await bootstrap(config_dir, ensure_schema=True)
    exporter = root.exporters.get(target)
    if exporter is None:
        console.print(f"[red]Exporter não habilitado[/red]: {target}")
        console.print(f"[yellow]Habilitados[/yellow]: {list(root.exporters.keys())}")
        await root.shutdown()
        raise typer.Exit(2)
    count = await root.export_findings_uc.execute(exporter, min_score=min_score, limit=limit)
    console.print(f"[green]Exported {count} findings to {target}[/green]")
    await root.shutdown()
