"""Typer CLI — primary interface for threat hunting operations."""

from __future__ import annotations

import asyncio
import json
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from threat_hunting.core.application.commands import (
    DisableConnectorCommand,
    EnableConnectorCommand,
    ExportCommand,
    RunAllConnectorsCommand,
    RunConnectorCommand,
    RunConnectorGroupCommand,
    SchedulerRunCommand,
    ScoreTestCommand,
)
from threat_hunting.infrastructure.observability.setup import setup_logging

app = typer.Typer(
    name="hunt",
    help="Threat Hunting Collection Platform — corporate CTI collection and analysis.",
    no_args_is_help=True,
)
connector_app = typer.Typer(help="Manage connectors")
export_app = typer.Typer(help="Export findings")
score_app = typer.Typer(help="Scoring operations")
app.add_typer(connector_app, name="connector")
app.add_typer(export_app, name="export")
app.add_typer(score_app, name="score")

console = Console()

_ctx: dict | None = None


async def _get_ctx() -> dict:
    global _ctx
    if _ctx is None:
        from threat_hunting.config.container import bootstrap
        _ctx = await bootstrap()
    return _ctx


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


@app.command("run")
def run(
    target: str = typer.Argument(..., help="Connector name, group (social, darkweb), or 'all'"),
    keywords: Optional[str] = typer.Option(None, "--keywords", "-k", help="Comma-separated keywords"),
) -> None:
    """Run collection pipeline for a connector, group, or all connectors.

    Examples:
        hunt run reddit
        hunt run github
        hunt run social
        hunt run darkweb
        hunt run all
    """
    setup_logging()
    ctx = _run(_get_ctx())
    kw_list = [k.strip() for k in keywords.split(",")] if keywords else []

    if target == "all":
        results = _run(ctx["run_all_handler"].handle(RunAllConnectorsCommand()))
    elif target in ("social", "darkweb", "code", "feeds", "threat_intel", "enrichment"):
        results = _run(ctx["run_group_handler"].handle(RunConnectorGroupCommand(group_name=target)))
    else:
        results = [_run(ctx["run_handler"].handle(RunConnectorCommand(connector_name=target, keywords=kw_list)))]

    table = Table(title="Collection Results")
    table.add_column("Connector")
    table.add_column("Findings")
    table.add_column("Duration (s)")
    table.add_column("Status")

    items = results if isinstance(results, list) else [results]
    for r in items:
        if "error" in r:
            table.add_row(r.get("connector", target), "-", "-", f"ERROR: {r['error']}")
        else:
            table.add_row(
                r.get("connector", target),
                str(r.get("findings_count", 0)),
                str(r.get("duration_seconds", 0)),
                "OK" if not r.get("errors") else f"WARN: {r['errors']}",
            )

    console.print(table)


@connector_app.command("list")
def connector_list() -> None:
    """List all registered connectors."""
    ctx = _run(_get_ctx())
    names = ctx["registry"].list_names()
    for name in names:
        console.print(f"  • {name}")
    console.print(f"\n[bold]{len(names)}[/bold] connectors registered")


@connector_app.command("enable")
def connector_enable(name: str = typer.Argument(..., help="Connector name")) -> None:
    """Enable a connector."""
    ctx = _run(_get_ctx())
    result = _run(ctx["connector_config_handler"].enable(EnableConnectorCommand(connector_name=name)))
    console.print(f"Connector [green]{result['connector']}[/green] enabled={result['enabled']}")


@connector_app.command("disable")
def connector_disable(name: str = typer.Argument(..., help="Connector name")) -> None:
    """Disable a connector."""
    ctx = _run(_get_ctx())
    result = _run(ctx["connector_config_handler"].disable(DisableConnectorCommand(connector_name=name)))
    console.print(f"Connector [red]{result['connector']}[/red] enabled={result['enabled']}")


@export_app.command("misp")
def export_misp() -> None:
    """Export findings to MISP."""
    ctx = _run(_get_ctx())
    result = _run(ctx["export_handler"].handle(ExportCommand(export_format="misp")))
    console.print(json.dumps(result, indent=2, default=str))


@export_app.command("splunk")
def export_splunk() -> None:
    """Export findings to Splunk."""
    ctx = _run(_get_ctx())
    result = _run(ctx["export_handler"].handle(ExportCommand(export_format="splunk")))
    console.print(json.dumps(result, indent=2, default=str))


@export_app.command("elastic")
def export_elastic() -> None:
    """Export findings to Elasticsearch/OpenSearch."""
    ctx = _run(_get_ctx())
    result = _run(ctx["export_handler"].handle(ExportCommand(export_format="elastic")))
    console.print(json.dumps(result, indent=2, default=str))


@export_app.command("json")
def export_json() -> None:
    """Export findings to JSON."""
    ctx = _run(_get_ctx())
    result = _run(ctx["export_handler"].handle(ExportCommand(export_format="json")))
    console.print(json.dumps(result, indent=2, default=str))


@export_app.command("stix")
def export_stix() -> None:
    """Export findings as STIX 2.1 bundle."""
    ctx = _run(_get_ctx())
    result = _run(ctx["export_handler"].handle(ExportCommand(export_format="stix")))
    console.print(json.dumps(result, indent=2, default=str))


@score_app.command("test")
def score_test(
    title: str = typer.Option("Test Finding", "--title"),
    severity: str = typer.Option("medium", "--severity"),
) -> None:
    """Test scoring engine with sample data."""
    ctx = _run(_get_ctx())
    result = _run(ctx["score_test_handler"].handle(
        ScoreTestCommand(sample_data={"title": title, "severity": severity})
    ))
    console.print(json.dumps(result, indent=2))


@app.command("scheduler")
def scheduler_run() -> None:
    """Start the collection scheduler daemon."""
    setup_logging()
    ctx = _run(_get_ctx())
    sched = ctx["scheduler"]
    config = ctx["config"]

    for name, cfg in config.connectors.items():
        if cfg.get("enabled", True):
            cron = cfg.get("schedule_cron", "0 */6 * * *")
            sched.add_connector_job(name, cron, _scheduled_run)

    sched.start()
    console.print("[green]Scheduler started. Press Ctrl+C to stop.[/green]")
    try:
        asyncio.get_event_loop().run_forever()
    except KeyboardInterrupt:
        sched.stop()
        console.print("[yellow]Scheduler stopped.[/yellow]")


async def _scheduled_run(connector_name: str) -> None:
    ctx = await _get_ctx()
    await ctx["run_handler"].handle(RunConnectorCommand(connector_name=connector_name))


@app.command("health")
def health_check() -> None:
    """Run platform health checks."""
    ctx = _run(_get_ctx())
    console.print("[green]Platform bootstrapped successfully[/green]")
    console.print(f"Connectors: {len(ctx['registry'].list_names())}")


if __name__ == "__main__":
    app()
