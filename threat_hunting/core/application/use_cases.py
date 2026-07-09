"""Application use cases orchestrating domain contracts.

The use case is intentionally small: detailed work happens behind ports, while
the command decides which connector and pipeline to run.
"""

from __future__ import annotations

from dataclasses import dataclass

from threat_hunting.core.application.ports import BaseConnector
from threat_hunting.core.domain.entities import Finding


@dataclass(frozen=True)
class HuntCommand:
    """Command object representing one hunting execution request."""

    connector_name: str
    export: bool = True


class PipelinePort:
    """Runtime protocol for the collection pipeline."""

    def run(self, connector: BaseConnector, export: bool = True) -> list[Finding]:
        """Execute one connector through the full pipeline."""


class RunHuntUseCase:
    """Run one connector through the configured hunting pipeline."""

    def __init__(self, registry: object, pipeline: PipelinePort) -> None:
        self._registry = registry
        self._pipeline = pipeline

    def execute(self, command: HuntCommand) -> list[Finding]:
        """Resolve a connector and execute the pipeline."""

        connector = self._registry.get(command.connector_name)
        return self._pipeline.run(connector, export=command.export)
