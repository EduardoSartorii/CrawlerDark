"""Typer CLI — Command Pattern entrypoint.

Responsibility
--------------
Expose hunt commands. CLI only creates Commands and delegates to handlers.
No business logic lives here.

Examples
--------
  hunt run reddit
  hunt run github
  hunt run social
  hunt run darkweb
  hunt run all
  hunt connector enable reddit
  hunt connector disable reddit
  hunt scheduler run
  hunt export misp
  hunt export splunk
  hunt export elastic
  hunt score test
  hunt health
  hunt connectors list
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Optional

import typer

from threat_hunting.core.application.commands import (
    DisableConnectorCommand,
    EnableConnectorCommand,
    ExportFindingsCommand,
    HealthCheckCommand,
    RunHuntCommand,
    ScoreTestCommand,
)
from threat_hunting.infrastructure.di.container import Container, bootstrap
from threat_hunting.infrastructure.scheduler.hunt_scheduler import HuntScheduler

app = typer.Typer(
    name="hunt",
    help="Threat Hunting Collection Platform CLI",
    no_args_is_help=True,
    add_completion=False,
)
connector_app = typer.Typer(help="Manage connectors")
scheduler_app = typer.Typer(help="Scheduler operations")
export_app = typer.Typer(help="Export findings")
score_app = typer.Typer(help="Scoring utilities")

app.add_typer(connector_app, name="connector")
app.add_typer(scheduler_app, name="scheduler")
app.add_typer(export_app, name="export")
app.add_typer(score_app, name="score")

_container: Container | None = None


def get_container(config_dir: str = "config") -> Container:
    global _container
    if _container is None:
        _container = bootstrap(config_dir)
    return _container


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


@app.callback()
def main(
    ctx: typer.Context,
    config_dir: str = typer.Option("config", "--config-dir", help="Config directory"),
) -> None:
    """Threat Hunting Collection Platform."""
    ctx.ensure_object(dict)
    ctx.obj["config_dir"] = config_dir
    get_container(config_dir)


@app.command("run")
def run_hunt(
    ctx: typer.Context,
    target: str = typer.Argument(..., help="Connector name, group (social/darkweb/…) or 'all'"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Do not persist findings"),
    no_export: bool = typer.Option(False, "--no-export", help="Disable auto-export on threshold"),
) -> None:
    """Run hunt for a connector, group, or all."""
    container = get_container(ctx.obj.get("config_dir", "config"))
    handler = container.run_hunt_handler()
    jobs = _run(
        handler.handle(
            RunHuntCommand(
                connector=target,
                dry_run=dry_run,
                export_on_threshold=not no_export,
            )
        )
    )
    for job in jobs:
        typer.echo(
            json.dumps(
                {
                    "job_id": job.id,
                    "connector": job.connector,
                    "status": job.status.value,
                    "findings": job.findings_count,
                    "duplicates": job.duplicates_count,
                    "errors": job.errors_count,
                    "stats": job.stats,
                },
                indent=2,
            )
        )


@connector_app.command("enable")
def connector_enable(
    ctx: typer.Context,
    name: str = typer.Argument(...),
) -> None:
    """Enable a connector."""
    container = get_container(ctx.obj.get("config_dir", "config"))
    result = _run(container.connector_lifecycle_handler().enable(EnableConnectorCommand(name=name)))
    typer.echo(json.dumps(result, indent=2))


@connector_app.command("disable")
def connector_disable(
    ctx: typer.Context,
    name: str = typer.Argument(...),
) -> None:
    """Disable a connector."""
    container = get_container(ctx.obj.get("config_dir", "config"))
    result = _run(
        container.connector_lifecycle_handler().disable(DisableConnectorCommand(name=name))
    )
    typer.echo(json.dumps(result, indent=2))


@connector_app.command("list")
def connector_list(ctx: typer.Context) -> None:
    """List available connectors."""
    container = get_container(ctx.obj.get("config_dir", "config"))
    factory = container.connector_factory()
    names = list(factory.list_available())
    typer.echo(json.dumps({"connectors": names, "count": len(names)}, indent=2))


@scheduler_app.command("run")
def scheduler_run(
    ctx: typer.Context,
    target: str = typer.Option("all", "--target", help="Connector or group to run once"),
) -> None:
    """Run scheduler once (immediate execution)."""
    container = get_container(ctx.obj.get("config_dir", "config"))
    scheduler = HuntScheduler(run_handler=container.run_hunt_handler())
    jobs = _run(scheduler.run_once(target))
    typer.echo(json.dumps({"ran": len(jobs), "target": target}, indent=2))


@export_app.command("run")
def export_run(
    ctx: typer.Context,
    format_name: str = typer.Argument(..., help="Export format (misp|splunk|elastic|json|…)"),
    limit: int = typer.Option(100, "--limit"),
    path: Optional[str] = typer.Option(None, "--path"),
) -> None:
    """Export findings: hunt export run misp|splunk|elastic|json|csv|stix21|…"""
    fmt = "opensearch" if format_name.lower() in {"elastic", "elasticsearch"} else format_name
    container = get_container(ctx.obj.get("config_dir", "config"))
    options: dict[str, Any] = {}
    if path:
        options["path"] = path
    result = _run(
        container.export_handler().handle(
            ExportFindingsCommand(format=fmt, limit=limit, options=options)
        )
    )
    typer.echo(json.dumps(result, indent=2))


# Shorthand: hunt export <format> via Typer multi-command aliases
for _fmt in (
    "misp",
    "splunk",
    "elastic",
    "opensearch",
    "json",
    "csv",
    "stix21",
    "opencti",
    "webhook",
    "taxii21",
):

    def _make_export_cmd(fmt: str):
        def _cmd(
            ctx: typer.Context,
            limit: int = typer.Option(100, "--limit"),
            path: Optional[str] = typer.Option(None, "--path"),
        ) -> None:
            export_run(ctx, format_name=fmt, limit=limit, path=path)

        _cmd.__name__ = f"export_{fmt}"
        return _cmd

    export_app.command(name=_fmt)(_make_export_cmd(_fmt))


@score_app.command("test")
def score_test(
    ctx: typer.Context,
    text: str = typer.Option(
        "Credential leak password dump for vip@acme.com card 4111111111111111",
        "--text",
        help="Sample text to score",
    ),
) -> None:
    """Test scoring engine against sample text."""
    container = get_container(ctx.obj.get("config_dir", "config"))
    result = _run(container.score_test_handler().handle(ScoreTestCommand(text=text)))
    typer.echo(json.dumps(result, indent=2))


@app.command("health")
def health_cmd(ctx: typer.Context) -> None:
    """Run platform health checks."""
    container = get_container(ctx.obj.get("config_dir", "config"))
    result = _run(container.health_handler().handle(HealthCheckCommand()))
    typer.echo(json.dumps(result, indent=2, default=str))


@app.command("version")
def version_cmd() -> None:
    from threat_hunting import __version__

    typer.echo(__version__)


# Allow `python -m threat_hunting.cli.app`
if __name__ == "__main__":
    app()
