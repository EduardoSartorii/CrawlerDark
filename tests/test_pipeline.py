"""Integration tests for pipeline orchestration and domain behavior."""

from __future__ import annotations

from threat_hunting.application.use_cases import ExportFindingsCommand, RunConnectorCommand
from threat_hunting.infrastructure.container import AppContainer
from threat_hunting.plugins.discovery import build_registry


def test_run_connector_pipeline_persists_and_scores(test_config_path: object) -> None:
    """Run one connector and validate canonical finding lifecycle fields."""
    container = AppContainer()
    registry = build_registry(container.settings(), container.connector_registry())
    command = RunConnectorCommand(connector_name="reddit", pipeline=container.pipeline(), registry=registry)

    findings = command.execute()

    assert len(findings) == 1
    finding = findings[0]
    assert finding.connector == "reddit"
    assert finding.score > 0
    assert "matched_rules" in finding.metadata
    assert any(tag.startswith("rule:") for tag in finding.tags)

    persisted = list(container.finding_repository().list_all())
    assert len(persisted) == 1

    misp_exporter = container.exporters()[0]
    assert len(misp_exporter.sent_findings) == 1


def test_run_all_connectors_creates_correlations(test_config_path: object) -> None:
    """Run all connectors and confirm relationship/correlation behavior."""
    container = AppContainer()
    registry = build_registry(container.settings(), container.connector_registry())

    all_findings = []
    for connector_name in registry.names():
        command = RunConnectorCommand(
            connector_name=connector_name,
            pipeline=container.pipeline(),
            registry=registry,
        )
        all_findings.extend(command.execute())

    assert len(all_findings) >= 4
    assert any(finding.relationships for finding in all_findings)


def test_export_command_uses_configured_exporter(test_config_path: object) -> None:
    """Persist then export findings through json exporter command."""
    container = AppContainer()
    registry = build_registry(container.settings(), container.connector_registry())
    run_command = RunConnectorCommand(connector_name="github", pipeline=container.pipeline(), registry=registry)
    run_command.execute()

    export_command = ExportFindingsCommand(
        exporter_name="json",
        pipeline=container.pipeline(),
        uow=container.uow(),
    )
    exported_count = export_command.execute()

    assert exported_count >= 1
