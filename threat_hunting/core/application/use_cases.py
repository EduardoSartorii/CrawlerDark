"""Application use cases invoked by CLI, scheduler, API, and future Django UI."""

from __future__ import annotations

from threat_hunting.connectors.registry import ConnectorRegistry
from threat_hunting.core.application.commands import ExportCommand, RunHuntCommand, ToggleConnectorCommand
from threat_hunting.core.application.pipeline import CollectionPipeline
from threat_hunting.core.application.ports import Exporter, UnitOfWork
from threat_hunting.core.domain.entities import Finding


class RunHuntUseCase:
    """Run one connector, a connector group, or every enabled connector."""

    def __init__(self, registry: ConnectorRegistry, pipeline: CollectionPipeline) -> None:
        self.registry = registry
        self.pipeline = pipeline

    def execute(self, command: RunHuntCommand) -> list[Finding]:
        """Execute collection and return persisted findings."""

        findings: list[Finding] = []
        for connector in self.registry.resolve(command.target):
            findings.extend(self.pipeline.run(connector, limit=command.limit, export=command.export))
        return findings


class ToggleConnectorUseCase:
    """Enable or disable a connector in the registry."""

    def __init__(self, registry: ConnectorRegistry) -> None:
        self.registry = registry

    def execute(self, command: ToggleConnectorCommand) -> None:
        """Apply connector enabled state."""

        self.registry.set_enabled(command.connector_name, command.enabled)


class ExportFindingsUseCase:
    """Export persisted findings through a selected exporter."""

    def __init__(self, unit_of_work: UnitOfWork, exporters: dict[str, Exporter]) -> None:
        self.unit_of_work = unit_of_work
        self.exporters = exporters

    def execute(self, command: ExportCommand) -> int:
        """Export findings and return the number of exported records."""

        exporter = self.exporters[command.exporter_name]
        with self.unit_of_work as uow:
            findings = [finding for finding in uow.findings.list() if finding.score >= command.minimum_score]
        exporter.export(findings)
        return len(findings)
