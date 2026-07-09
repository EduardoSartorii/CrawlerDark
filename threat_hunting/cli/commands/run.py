"""`hunt run <connector|all>` — executa conectores pelo pipeline."""

from __future__ import annotations

import typer
from rich.console import Console
from rich.table import Table

from .._helpers import bootstrap, run_async

app = typer.Typer(help="Executa conectores.")
console = Console()


@app.callback(invoke_without_command=True)
def _default(
    ctx: typer.Context,
    connector: str | None = typer.Argument(None, help="Nome do conector (ou 'all')."),
    config_dir: str = typer.Option("config", help="Diretório de configuração."),
) -> None:
    if ctx.invoked_subcommand is not None:
        return
    if not connector:
        console.print("[red]Argumento obrigatório[/red]: connector (ou 'all').")
        raise typer.Exit(2)
    if connector == "all":
        run_async(lambda: _run_all(config_dir))
    else:
        run_async(lambda: _run_single(connector, config_dir))


@app.command("all")
def run_all(config_dir: str = typer.Option("config", help="Diretório de configuração.")) -> None:
    """Executa todos os conectores habilitados."""
    run_async(lambda: _run_all(config_dir))


@app.command("connector")
def run_connector(
    name: str = typer.Argument(..., help="Nome do conector."),
    config_dir: str = typer.Option("config", help="Diretório de configuração."),
) -> None:
    """Executa um único conector nomeado."""
    run_async(lambda: _run_single(name, config_dir))


async def _run_single(name: str, config_dir: str) -> None:
    root = await bootstrap(config_dir, ensure_schema=True)
    try:
        connector = root.build_connector(name)
    except KeyError:
        console.print(f"[red]Conector não configurado[/red]: {name}")
        raise typer.Exit(2)
    console.print(f"[bold cyan]▶ Running connector[/bold cyan]: {name}")
    job = await root.run_connector_uc.execute(connector)
    _print_job_summary(job)
    await root.shutdown()


async def _run_all(config_dir: str) -> None:
    root = await bootstrap(config_dir, ensure_schema=True)
    names = root.enabled_connector_names()
    if not names:
        console.print("[yellow]Nenhum conector habilitado em config/connectors.yaml[/yellow]")
        await root.shutdown()
        return
    for name in names:
        try:
            connector = root.build_connector(name)
        except Exception as exc:  # noqa: BLE001
            console.print(f"[red]Skip {name}[/red]: {exc}")
            continue
        console.print(f"[bold cyan]▶ Running connector[/bold cyan]: {name}")
        job = await root.run_connector_uc.execute(connector)
        _print_job_summary(job)
    await root.shutdown()


def _print_job_summary(job) -> None:  # type: ignore[no-untyped-def]
    table = Table(title=f"Job {job.connector}", show_header=True, header_style="bold magenta")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("status", job.status.value)
    table.add_row("collected", str(job.items_collected))
    table.add_row("persisted", str(job.items_persisted))
    if job.errors:
        table.add_row("errors", "\n".join(job.errors[:5]))
    console.print(table)
