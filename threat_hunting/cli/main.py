"""Operational CLI for the Threat Hunting Collection platform."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from threat_hunting.core.domain.entities import Finding
from threat_hunting.infrastructure.config.settings import AppSettings, load_settings
from threat_hunting.infrastructure.container import ApplicationContainer
from threat_hunting.infrastructure.logging import configure_logging
from threat_hunting.scheduler.runner import SchedulerRunner

app = typer.Typer(help="Threat Hunting Collection platform")
run_app = typer.Typer(help="Run connectors")
connector_app = typer.Typer(help="Manage connector definitions")
scheduler_app = typer.Typer(help="Run scheduled jobs")
export_app = typer.Typer(help="Export findings")
score_app = typer.Typer(help="Test scoring policies")

app.add_typer(run_app, name="run")
app.add_typer(connector_app, name="connector")
app.add_typer(scheduler_app, name="scheduler")
app.add_typer(export_app, name="export")
app.add_typer(score_app, name="score")


def _container(config_path: str) -> tuple[AppSettings, ApplicationContainer]:
    settings = load_settings(config_path)
    configure_logging()
    container = ApplicationContainer(settings=settings)
    container.registry().discover()
    return settings, container


def _run_connector(name: str, config_path: str) -> list[Finding]:
    settings, container = _container(config_path)
    registry = container.registry()
    pipeline = container.pipeline()
    names = [definition.name for definition in registry.list(enabled_only=True)]
    selected = names if name == "all" else [name]
    if name == "social":
        selected = [item for item in names if item in {"reddit", "facebook", "instagram", "x", "telegram", "discord"}]
    if name == "darkweb":
        selected = [item for item in names if "dark" in item or item in {"forums", "marketplaces"}]
    findings: list[Finding] = []
    for connector_name in selected:
        findings.extend(pipeline.run(registry.get(connector_name), export=True))
    typer.echo(json.dumps({"processed": len(findings), "environment": settings.environment}, indent=2))
    return findings


CONFIG_OPTION = typer.Option("config/default.yml", "--config", "-c", help="Path to the YAML configuration file.")


@run_app.command("reddit")
def run_reddit(config: str = CONFIG_OPTION) -> None:
    """Run the Reddit connector."""

    _run_connector("reddit", config)


@run_app.command("github")
def run_github(config: str = CONFIG_OPTION) -> None:
    """Run the GitHub connector."""

    _run_connector("github", config)


@run_app.command("telegram")
def run_telegram(config: str = CONFIG_OPTION) -> None:
    """Run the Telegram connector."""

    _run_connector("telegram", config)


@run_app.command("social")
def run_social(config: str = CONFIG_OPTION) -> None:
    """Run social connectors."""

    _run_connector("social", config)


@run_app.command("darkweb")
def run_darkweb(config: str = CONFIG_OPTION) -> None:
    """Run dark web connectors."""

    _run_connector("darkweb", config)


@run_app.command("all")
def run_all(config: str = CONFIG_OPTION) -> None:
    """Run every enabled connector."""

    _run_connector("all", config)


@connector_app.command("enable")
def enable_connector(name: str, config: str = CONFIG_OPTION) -> None:
    """Enable a connector in the YAML configuration."""

    _set_connector_state(name, True, config)


@connector_app.command("disable")
def disable_connector(name: str, config: str = CONFIG_OPTION) -> None:
    """Disable a connector in the YAML configuration."""

    _set_connector_state(name, False, config)


def _set_connector_state(name: str, enabled: bool, config: str) -> None:
    path = Path(config)
    payload = load_settings(path).model_dump(mode="json")
    found = False
    for connector in payload["connectors"]:
        if connector["name"] == name:
            connector["enabled"] = enabled
            found = True
    if not found:
        raise typer.BadParameter(f"Connector '{name}' not found")
    import yaml

    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    typer.echo(json.dumps({"connector": name, "enabled": enabled}))


@scheduler_app.command("run")
def run_scheduler(config: str = CONFIG_OPTION) -> None:
    """Start APScheduler jobs."""

    settings, container = _container(config)
    runner = SchedulerRunner(container.registry(), container.pipeline(), settings.scheduler.interval_minutes)
    runner.start()
    typer.echo(json.dumps({"scheduler": "running", "interval_minutes": settings.scheduler.interval_minutes}))


@export_app.command("misp")
def export_misp(config: str = CONFIG_OPTION) -> None:
    """Run all connectors and export findings that exceed MISP threshold."""

    _run_connector("all", config)


@export_app.command("splunk")
def export_splunk(config: str = CONFIG_OPTION) -> None:
    """Run all connectors with configured Splunk exporter."""

    _run_connector("all", config)


@export_app.command("elastic")
def export_elastic(config: str = CONFIG_OPTION) -> None:
    """Run all connectors with configured Elasticsearch/OpenSearch exporter."""

    _run_connector("all", config)


@score_app.command("test")
def score_test(config: str = CONFIG_OPTION) -> None:
    """Score a synthetic finding using configured rules and weights."""

    _, container = _container(config)
    finding = Finding(
        title="VIP credential leak for example.com",
        description="admin@example.com leaked with password and card 4111 1111 1111 1111",
        source="test",
        connector="score-test",
        category="credential_hunting",
    )
    finding = container.extractor().extract(finding)
    finding = container.detection_engine().detect(finding)
    finding = container.scoring_engine().score(finding)
    typer.echo(finding.model_dump_json(indent=2))
