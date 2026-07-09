"""Command-line interface for threat hunting operations."""

from __future__ import annotations

from pathlib import Path

import typer

from threat_hunting.core.application.commands import ExportCommand, RunHuntCommand, ToggleConnectorCommand
from threat_hunting.core.domain.entities import Finding
from threat_hunting.infrastructure.config import PlatformSettings
from threat_hunting.infrastructure.container import ApplicationContainer
from threat_hunting.infrastructure.logging import configure_logging

app = typer.Typer(help="Threat Hunting Collection Platform")
connector_app = typer.Typer(help="Connector administration")
scheduler_app = typer.Typer(help="Scheduler operations")
score_app = typer.Typer(help="Scoring operations")
app.add_typer(connector_app, name="connector")
app.add_typer(scheduler_app, name="scheduler")
app.add_typer(score_app, name="score")


def build_container(config_path: Path) -> ApplicationContainer:
    """Create the DI container for a CLI invocation."""

    settings = PlatformSettings.from_yaml(config_path)
    configure_logging()
    container = ApplicationContainer()
    container.settings.override(settings)
    return container


@app.command()
def run(
    target: str = typer.Argument("all", help="Connector or group: reddit, github, telegram, social, darkweb, all."),
    config: Path = typer.Option(Path("config/default.yml"), "--config", "-c"),
    limit: int | None = typer.Option(None, "--limit"),
    no_export: bool = typer.Option(False, "--no-export"),
) -> None:
    """Run the full collection pipeline for one connector or group."""

    use_case = build_container(config).run_hunt_use_case()
    findings = use_case.execute(RunHuntCommand(target=target, limit=limit, export=not no_export))
    typer.echo(f"collected={len(findings)} target={target}")


@connector_app.command("enable")
def connector_enable(name: str, config: Path = typer.Option(Path("config/default.yml"), "--config", "-c")) -> None:
    """Enable a connector at runtime."""

    use_case = build_container(config).toggle_connector_use_case()
    use_case.execute(ToggleConnectorCommand(connector_name=name, enabled=True))
    typer.echo(f"connector={name} enabled=true")


@connector_app.command("disable")
def connector_disable(name: str, config: Path = typer.Option(Path("config/default.yml"), "--config", "-c")) -> None:
    """Disable a connector at runtime."""

    use_case = build_container(config).toggle_connector_use_case()
    use_case.execute(ToggleConnectorCommand(connector_name=name, enabled=False))
    typer.echo(f"connector={name} enabled=false")


@app.command()
def export(
    exporter: str = typer.Argument(..., help="Exporter name: misp, splunk, elastic, json, csv, stix21, taxii21."),
    config: Path = typer.Option(Path("config/default.yml"), "--config", "-c"),
    minimum_score: float = typer.Option(0.0, "--minimum-score"),
) -> None:
    """Export persisted findings through a named exporter."""

    use_case = build_container(config).export_findings_use_case()
    count = use_case.execute(ExportCommand(exporter_name=exporter, minimum_score=minimum_score))
    typer.echo(f"exported={count} exporter={exporter}")


@score_app.command("test")
def score_test(config: Path = typer.Option(Path("config/default.yml"), "--config", "-c")) -> None:
    """Run scoring smoke test with configured rules."""

    container = build_container(config)
    finding = Finding(
        title="Score smoke test",
        description="api_key credential admin@acme.test",
        source="github",
        connector="github",
        category="code",
    )
    matches = container.detection_engine().evaluate(finding)
    scored = container.scoring_engine().score(finding, matches)
    typer.echo(f"score={scored.score}")


@scheduler_app.command("run")
def scheduler_run(config: Path = typer.Option(Path("config/default.yml"), "--config", "-c")) -> None:
    """Start configured APScheduler jobs."""

    from threat_hunting.scheduler.service import SchedulerService

    SchedulerService(build_container(config)).run_forever()


if __name__ == "__main__":
    app()
