"""The ``hunt`` command-line interface.

Responsibility
--------------
Expose the platform's use cases as ergonomic commands (Typer). The CLI is a thin
interface adapter: it builds the DI container, resolves the relevant use case and
renders the result. It contains no business logic.

Commands
--------
* ``hunt run <target>``            — run one connector, a group, or ``all``.
* ``hunt connector list``          — list discovered connectors + status.
* ``hunt connector enable/disable``— toggle a connector for this process.
* ``hunt scheduler run``           — run recurring collection.
* ``hunt export <name>``           — export stored findings.
* ``hunt score test``              — score the built-in sample corpus.
* ``hunt health``                  — health-check connectors and storage.
"""

from __future__ import annotations

import asyncio
import json
from typing import Optional

import typer

from threat_hunting.infrastructure.di.container import (
    build_container,
    build_export_use_case,
    build_run_hunt_use_case,
)
from threat_hunting.infrastructure.scheduler.aps_scheduler import HuntScheduler

app = typer.Typer(
    help="Threat Hunting Collection Platform CLI.",
    no_args_is_help=True,
    add_completion=False,
)
connector_app = typer.Typer(help="Manage collection connectors.", no_args_is_help=True)
scheduler_app = typer.Typer(help="Run the collection scheduler.", no_args_is_help=True)
score_app = typer.Typer(help="Scoring utilities.", no_args_is_help=True)
app.add_typer(connector_app, name="connector")
app.add_typer(scheduler_app, name="scheduler")
app.add_typer(score_app, name="score")

#: Logical connector groups resolved to concrete connector names at runtime.
_GROUPS: dict[str, set[str]] = {
    "social": {"reddit", "facebook", "instagram", "x", "telegram", "discord"},
    "darkweb": {"darkweb", "deepweb", "forum", "marketplace", "paste"},
    "feeds": {"threatfox", "misp", "opencti", "urlhaus", "otx"},
}

_SETTINGS_OPT = typer.Option("config/settings.yml", "--config", "-c", help="Settings YAML path.")


def _print(obj: object) -> None:
    """Render a result as pretty JSON to stdout."""
    typer.echo(json.dumps(obj, indent=2, default=str))


@app.command()
def run(
    target: str = typer.Argument(..., help="Connector name, group, or 'all'."),
    config: str = _SETTINGS_OPT,
) -> None:
    """Run the collection pipeline for a connector, a group, or all."""
    container = build_container(config)
    use_case = build_run_hunt_use_case(container)
    registry = container.registry()
    available = set(registry.names(include_disabled=False))

    async def _run() -> dict:
        if target == "all":
            result = await use_case.run_all()
        elif target in _GROUPS:
            names = sorted(_GROUPS[target] & available)
            result = await use_case.run_many(names)
        else:
            result = await use_case.run_one(target)
        return {
            "target": target,
            "collected": result.collected,
            "persisted": result.persisted,
            "duplicates": result.duplicates,
            "exported": result.exported,
            "errors": result.errors,
        }

    _print(asyncio.run(_run()))


@connector_app.command("list")
def connector_list(config: str = _SETTINGS_OPT) -> None:
    """List all discovered connectors and whether they are enabled."""
    container = build_container(config)
    registry = container.registry()
    _print(
        {
            name: {"enabled": registry.is_enabled(name)}
            for name in registry.names(include_disabled=True)
        }
    )


@connector_app.command("enable")
def connector_enable(name: str, config: str = _SETTINGS_OPT) -> None:
    """Enable a connector for this process."""
    registry = build_container(config).registry()
    registry.enable(name)
    _print({"connector": name, "enabled": registry.is_enabled(name)})


@connector_app.command("disable")
def connector_disable(name: str, config: str = _SETTINGS_OPT) -> None:
    """Disable a connector for this process."""
    registry = build_container(config).registry()
    registry.disable(name)
    _print({"connector": name, "enabled": registry.is_enabled(name)})


@scheduler_app.command("run")
def scheduler_run(
    interval: int = typer.Option(3600, help="Seconds between collection rounds."),
    iterations: Optional[int] = typer.Option(
        None, help="Run N rounds then stop (default: run forever)."
    ),
    config: str = _SETTINGS_OPT,
) -> None:
    """Run recurring collection over all enabled connectors."""
    container = build_container(config)
    scheduler = HuntScheduler(
        use_case=build_run_hunt_use_case(container), interval_seconds=interval
    )
    asyncio.run(scheduler.run(iterations=iterations))


@app.command("export")
def export(
    name: str = typer.Argument(..., help="Exporter: json|csv|stix|misp."),
    min_score: float = typer.Option(0.0, help="Only export findings >= this score."),
    config: str = _SETTINGS_OPT,
) -> None:
    """Export stored findings via the named exporter."""
    use_case = build_export_use_case(build_container(config))
    count = use_case.export(name, min_score=min_score)
    _print({"exporter": name, "exported": count})


@score_app.command("test")
def score_test(config: str = _SETTINGS_OPT) -> None:
    """Run the sample connector through detection+scoring and show contributions."""
    from threat_hunting.infrastructure.connectors.builtins.sample import SampleConnector
    from threat_hunting.infrastructure.extractors.ioc_extractor import RegexIOCExtractor
    from threat_hunting.infrastructure.parsers.html_parser import HtmlTextParser

    container = build_container(config)
    parser = HtmlTextParser()
    extractor = RegexIOCExtractor()
    normalizer = container.normalizer()
    detection = container.detection()
    scoring = container.scoring()

    async def _score() -> list[dict]:
        connector = SampleConnector()
        await connector.connect()
        out: list[dict] = []
        for record in await connector.collect():
            parsed = parser.parse(connector.parse(record))
            finding = normalizer.normalize(connector.normalize(parsed), parsed)
            for indicator in extractor.extract(parsed):
                finding.add_indicator(indicator)
            detection.detect(finding)
            scoring.score(finding)
            out.append(
                {
                    "title": finding.title,
                    "score": finding.score,
                    "severity": finding.severity.value,
                    "confidence": finding.confidence.value,
                    "matched": detection.matches(finding),
                    "contributions": finding.metadata.get("scoring", {}).get(
                        "contributions", {}
                    ),
                    "indicators": [i.fingerprint() for i in finding.indicators],
                }
            )
        return out

    _print(asyncio.run(_score()))


@app.command("health")
def health(config: str = _SETTINGS_OPT) -> None:
    """Health-check all enabled connectors and the storage backend."""
    report = build_container(config).health_checker().check_sync()
    _print(
        {
            "healthy": report.healthy,
            "connectors": report.connectors,
            "storage": report.storage,
        }
    )


if __name__ == "__main__":  # pragma: no cover
    app()
