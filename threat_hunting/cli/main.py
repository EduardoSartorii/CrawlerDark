"""Typer CLI entrypoint (``hunt``).

Responsibility
--------------
Provide the operator interface. Every command is a thin adapter that builds the
DI :class:`Container` and invokes an application service (Command Pattern). No
domain logic lives here — the CLI only translates arguments to use-case calls
and renders results.

Commands
--------
* ``hunt run <target>``             -- run the pipeline for a connector/group/all
* ``hunt connector list``           -- list discovered connectors
* ``hunt connector enable/disable`` -- toggle a connector (persisted to settings)
* ``hunt scheduler run``            -- run the scheduler loop
* ``hunt export <target>``          -- export stored findings via an exporter
* ``hunt score test``               -- score the sample corpus and show breakdown
* ``hunt health``                   -- print an aggregated health report
"""

from __future__ import annotations

import json

import typer

from threat_hunting.config.container import Container
from threat_hunting.config.settings import load_settings

app = typer.Typer(help="Threat Hunting Collection Platform CLI", no_args_is_help=True)
connector_app = typer.Typer(help="Manage connectors.", no_args_is_help=True)
scheduler_app = typer.Typer(help="Run the collection scheduler.", no_args_is_help=True)
score_app = typer.Typer(help="Scoring utilities.", no_args_is_help=True)
app.add_typer(connector_app, name="connector")
app.add_typer(scheduler_app, name="scheduler")
app.add_typer(score_app, name="score")


def _container(config: str | None) -> Container:
    """Build the DI container from the (optional) config path."""
    return Container(load_settings(config))


@app.command()
def run(
    target: str = typer.Argument(..., help="Connector name, group (e.g. social), or 'all'."),
    config: str = typer.Option(None, "--config", "-c", help="Path to settings.yml."),
) -> None:
    """Run the collection pipeline for ``target`` and print a run summary."""
    container = _container(config)
    summary = container.run_collection_service.run(target)
    typer.echo(json.dumps(summary.model_dump(mode="json"), indent=2))


@connector_app.command("list")
def connector_list(
    config: str = typer.Option(None, "--config", "-c", help="Path to settings.yml."),
) -> None:
    """List every discovered connector with its metadata."""
    container = _container(config)
    for meta in container.registry.all():
        status = "enabled" if meta.enabled else "disabled"
        typer.echo(
            f"{meta.name:14} [{status:8}] {meta.source.value:14} "
            f"groups={','.join(meta.groups) or '-'}"
        )


@connector_app.command("enable")
def connector_enable(
    name: str = typer.Argument(..., help="Connector to enable."),
    config: str = typer.Option(None, "--config", "-c"),
) -> None:
    """Enable a connector for this run (registry override)."""
    container = _container(config)
    container.registry.set_enabled(name, True)
    typer.echo(f"connector '{name}' enabled")


@connector_app.command("disable")
def connector_disable(
    name: str = typer.Argument(..., help="Connector to disable."),
    config: str = typer.Option(None, "--config", "-c"),
) -> None:
    """Disable a connector for this run (registry override)."""
    container = _container(config)
    container.registry.set_enabled(name, False)
    typer.echo(f"connector '{name}' disabled")


@scheduler_app.command("run")
def scheduler_run(
    targets: str = typer.Option("all", "--targets", "-t", help="Comma-separated targets."),
    interval: int = typer.Option(3600, "--interval", "-i", help="Seconds between cycles."),
    once: bool = typer.Option(True, "--once/--loop", help="Run one cycle or loop forever."),
    config: str = typer.Option(None, "--config", "-c"),
) -> None:
    """Run the scheduler over the given targets (one cycle by default)."""
    from threat_hunting.infrastructure.scheduler.runner import SchedulerRunner

    container = _container(config)
    runner = SchedulerRunner(container.run_collection_service)
    summaries = runner.run_cycle([t.strip() for t in targets.split(",") if t.strip()])
    for summary in summaries:
        typer.echo(json.dumps(summary.model_dump(mode="json"), indent=2))
    if not once:
        runner.loop(
            [t.strip() for t in targets.split(",") if t.strip()], interval_seconds=interval
        )


@app.command()
def export(
    target: str = typer.Argument(..., help="Exporter: json | csv | stix | webhook | misp."),
    min_score: float = typer.Option(0.0, "--min-score", help="Only export score >= value."),
    config: str = typer.Option(None, "--config", "-c"),
) -> None:
    """Export stored findings through the named exporter."""
    container = _container(config)
    result = container.export_service.export(target, min_score=min_score)
    typer.echo(json.dumps(result.model_dump(mode="json"), indent=2))


@score_app.command("test")
def score_test(
    config: str = typer.Option(None, "--config", "-c"),
) -> None:
    """Run the sample corpus through the pipeline and show the score breakdown."""
    container = _container(config)
    summary = container.run_collection_service.run("sample_paste")
    with container.unit_of_work as uow:
        findings = uow.findings.list()
    for finding in findings:
        typer.echo(
            f"[{finding.severity.value:8}] {finding.score.value:6.1f}  {finding.title[:48]}"
        )
        for component, points in sorted(finding.score.breakdown.items()):
            typer.echo(f"      {component:24} {points:+.1f}")
    typer.echo(f"\nrun_id={summary.run_id} findings={len(findings)}")


@app.command()
def health(
    config: str = typer.Option(None, "--config", "-c"),
) -> None:
    """Print an aggregated health report for storage and connectors."""
    container = _container(config)
    connectors = [m.name for m in container.registry.all()]
    report = container.health_check.run(connectors=connectors)
    typer.echo(json.dumps(report.model_dump(mode="json"), indent=2))


@app.command()
def version() -> None:
    """Print the platform version."""
    from threat_hunting import __version__

    typer.echo(__version__)


if __name__ == "__main__":  # pragma: no cover
    app()
