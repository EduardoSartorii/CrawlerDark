"""Typer CLI for threat hunting platform operations."""

from __future__ import annotations

from pathlib import Path

import typer

from threat_hunting.application.commands import (
    ExportFindingsCommand,
    RunHuntCommand,
    RunSchedulerCommand,
    ScoreTestCommand,
    ToggleConnectorCommand,
)
from threat_hunting.application.container import bootstrap_container
from threat_hunting.application.use_cases import HuntExecutionResult

app = typer.Typer(help="Threat Hunting Collection Platform CLI")
connector_app = typer.Typer(help="Connector management commands")
scheduler_app = typer.Typer(help="Scheduler commands")
app.add_typer(connector_app, name="connector")
app.add_typer(scheduler_app, name="scheduler")


def _command_bus(config_dir: Path | None = None):
    container = bootstrap_container(config_dir=config_dir)
    return container.command_bus()


@app.command("run")
def run(target: str = typer.Argument(..., help="Connector or group (reddit/github/telegram/social/darkweb/all)")) -> None:
    """Run threat hunt pipeline for target connector or group."""
    result = _command_bus().execute(RunHuntCommand(target=target))
    if isinstance(result, HuntExecutionResult):
        typer.echo(
            f"run_id={result.run_id} connectors={','.join(result.connectors)} findings={result.findings_count}"
        )
    else:
        typer.echo(str(result))


@connector_app.command("enable")
def connector_enable(connector_name: str = typer.Argument(..., help="Connector name")) -> None:
    """Enable connector."""
    result = _command_bus().execute(ToggleConnectorCommand(connector_name=connector_name, enabled=True))
    typer.echo(f"{result['connector']} {result['status']}")


@connector_app.command("disable")
def connector_disable(connector_name: str = typer.Argument(..., help="Connector name")) -> None:
    """Disable connector."""
    result = _command_bus().execute(ToggleConnectorCommand(connector_name=connector_name, enabled=False))
    typer.echo(f"{result['connector']} {result['status']}")


@scheduler_app.command("run")
def scheduler_run() -> None:
    """Run scheduler cycle once."""
    result = _command_bus().execute(RunSchedulerCommand())
    typer.echo(result["status"])


@app.command("export")
def export(target: str = typer.Argument(..., help="Exporter target (misp/splunk/elastic/json/csv/opencti)")) -> None:
    """Export recent findings to selected destination."""
    normalized_target = "opensearch" if target.lower() == "elastic" else target.lower()
    result = _command_bus().execute(ExportFindingsCommand(target=normalized_target))
    typer.echo(f"exported {result['count']} findings to {result['target']}")


@app.command("score")
def score(
    action: str = typer.Argument(..., help="Action name, use 'test'"),
) -> None:
    """Run scoring command."""
    if action.lower() != "test":
        raise typer.BadParameter("Only 'test' action is currently supported")
    result = _command_bus().execute(ScoreTestCommand())
    typer.echo(f"score={result['score']:.2f} confidence={result['confidence']:.2f}")


@app.command("health")
def health() -> None:
    """Run simple platform health checks."""
    container = bootstrap_container()
    registry = container.health_registry()
    registry.register("db_session_factory", lambda: bool(container.session_factory()))
    registry.register("connector_registry", lambda: bool(container.connector_registry()))
    result = registry.run()
    typer.echo(str(result))


if __name__ == "__main__":
    app()
