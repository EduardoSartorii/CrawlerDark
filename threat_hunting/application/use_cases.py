"""Application use cases modeled as commands."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from threat_hunting.application.pipeline import HuntingPipeline
from threat_hunting.core.contracts import ConnectorRegistryPort, UnitOfWorkPort
from threat_hunting.domain.entities import ExecutionContext, Finding


class Command(Protocol):
    """Command pattern protocol for application operations."""

    def execute(self) -> object:
        """Execute command logic."""


@dataclass(slots=True)
class RunConnectorCommand:
    """Execute one connector through the full pipeline."""

    connector_name: str
    pipeline: HuntingPipeline
    registry: ConnectorRegistryPort
    command_name: str = "hunt run"

    def execute(self) -> list[Finding]:
        """Execute full processing for one connector plugin."""
        connector = self.registry.get(self.connector_name)
        context = ExecutionContext(command=self.command_name, connector_name=self.connector_name)
        return list(self.pipeline.run(connector, context))


@dataclass(slots=True)
class ExportFindingsCommand:
    """Export persisted findings through a named exporter."""

    exporter_name: str
    pipeline: HuntingPipeline
    uow: UnitOfWorkPort
    command_name: str = "hunt export"

    def execute(self) -> int:
        """Export all findings currently persisted by repository."""
        with self.uow as unit:
            findings = list(unit.findings.list_all())
        context = ExecutionContext(command=self.command_name, connector_name="all")
        self.pipeline.export(findings, context, self.exporter_name)
        return len(findings)
