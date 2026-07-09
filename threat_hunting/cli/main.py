"""Typer CLI entrypoint for threat hunting operations."""

from __future__ import annotations

import os
from pathlib import Path

import typer
import yaml

from threat_hunting.application.use_cases import ExportFindingsCommand, RunConnectorCommand
from threat_hunting.infrastructure.container import AppContainer
from threat_hunting.infrastructure.logging import configure_logging
from threat_hunting.plugins.discovery import build_registry
from threat_hunting.scheduler.service import SchedulerService


app = typer.Typer(help="Threat hunting platform CLI.")
run_app = typer.Typer(help="Run hunts for connectors.")
connector_app = typer.Typer(help="Manage connector lifecycle.")
scheduler_app = typer.Typer(help="Run scheduler actions.")
export_app = typer.Typer(help="Export findings.")
score_app = typer.Typer(help="Score engine utilities.")

app.add_typer(run_app, name="run")
app.add_typer(connector_app, name="connector")
app.add_typer(scheduler_app, name="scheduler")
app.add_typer(export_app, name="export")
app.add_typer(score_app, name="score")


def _build_runtime() -> tuple[AppContainer, object]:
    container = AppContainer()
    configure_logging()
    registry = build_registry(container.settings(), container.connector_registry())
    return container, registry


@run_app.command("reddit")
@run_app.command("github")
@run_app.command("telegram")
@run_app.command("darkweb")
def run_single(ctx: typer.Context) -> None:
    """Run a single connector by command name."""
    connector_name = str(ctx.info_name)
    _run_connector(connector_name)


@run_app.command("social")
def run_social() -> None:
    """Run social connector bundle."""
    for connector_name in ["reddit", "telegram", "github"]:
        _run_connector(connector_name)


@run_app.command("all")
def run_all() -> None:
    """Run all discovered connectors."""
    container, registry = _build_runtime()
    pipeline = container.pipeline()
    for connector_name in registry.names():
        command = RunConnectorCommand(connector_name=connector_name, pipeline=pipeline, registry=registry)
        findings = command.execute()
        typer.echo(f"{connector_name}: {len(findings)} findings")


@connector_app.command("enable")
def enable_connector(name: str) -> None:
    """Enable a connector in config."""
    _set_connector_state(name, enabled=True)
    typer.echo(f"connector '{name}' enabled")


@connector_app.command("disable")
def disable_connector(name: str) -> None:
    """Disable a connector in config."""
    _set_connector_state(name, enabled=False)
    typer.echo(f"connector '{name}' disabled")


@scheduler_app.command("run")
def scheduler_run() -> None:
    """Run one scheduler execution cycle in foreground."""
    container, registry = _build_runtime()
    scheduler = SchedulerService(pipeline=container.pipeline(), registry=registry)
    scheduler.run_all_once()
    typer.echo("scheduler run completed")


@export_app.command("misp")
@export_app.command("splunk")
@export_app.command("elastic")
@export_app.command("opensearch")
@export_app.command("json")
def export_findings(ctx: typer.Context) -> None:
    """Export persisted findings using selected exporter."""
    exporter_name = str(ctx.info_name)
    container, _ = _build_runtime()
    command = ExportFindingsCommand(
        exporter_name=exporter_name,
        pipeline=container.pipeline(),
        uow=container.uow(),
    )
    exported_count = command.execute()
    typer.echo(f"exported {exported_count} findings to {exporter_name}")


@score_app.command("test")
def score_test() -> None:
    """Run one connector and print score diagnostics."""
    container, registry = _build_runtime()
    command = RunConnectorCommand(connector_name="reddit", pipeline=container.pipeline(), registry=registry)
    findings = command.execute()
    if not findings:
        typer.echo("no findings")
        return
    finding = findings[0]
    typer.echo(f"finding={finding.title} score={finding.score} severity={finding.severity.value}")


def _run_connector(connector_name: str) -> None:
    container, registry = _build_runtime()
    command = RunConnectorCommand(connector_name=connector_name, pipeline=container.pipeline(), registry=registry)
    findings = command.execute()
    typer.echo(f"{connector_name}: {len(findings)} findings")


def _set_connector_state(name: str, enabled: bool) -> None:
    config_path = Path(os.getenv("THREAT_HUNTING_CONFIG", "config/default.yml"))
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    enabled_connectors = raw.setdefault("enabled_connectors", {})
    enabled_connectors[name] = enabled
    config_path.write_text(yaml.safe_dump(raw, sort_keys=True), encoding="utf-8")


def main() -> None:
    """CLI entrypoint for poetry scripts and python -m execution."""
    app()


if __name__ == "__main__":
    main()
