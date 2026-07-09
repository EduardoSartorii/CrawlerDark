"""
RunCollection Use Case.

Orchestrates the full threat hunting collection cycle for a connector or group.

Responsibilities:
    1. Resolve which connectors to run
    2. Execute the collection pipeline for each connector
    3. Coordinate domain services (deduplication, scoring, etc.)
    4. Persist results via Unit of Work
    5. Trigger export if score threshold is exceeded

This use case is the primary entry point for all automated collection jobs.
It depends ONLY on domain interfaces (ports), never on concrete adapters.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

import structlog

from ...domain.entities.finding import Finding
from ...domain.repositories import AbstractUnitOfWork
from ...domain.services.deduplication_service import DeduplicationService
from ..commands import RunConnectorCommand, RunPipelineCommand

logger = structlog.get_logger(__name__)


class CollectionPipelinePort(Protocol):
    """
    Port for the collection pipeline.
    Concrete implementation lives in infrastructure/pipelines/.
    The use case depends on this protocol, not the concrete class.
    """

    async def execute(self, connector_id: str, dry_run: bool = False) -> list[Finding]:
        """Run the full pipeline for a connector and return produced findings."""
        ...


class ConnectorRegistryPort(Protocol):
    """Port for discovering and managing connectors."""

    def get_enabled_connector_ids(self, group: str | None = None) -> list[str]:
        """Return IDs of all enabled connectors, optionally filtered by group."""
        ...

    def get_connector_id(self, name: str) -> str | None:
        """Resolve a connector by name."""
        ...


@dataclass
class CollectionResult:
    """Result summary from a collection run."""

    connector_id: str
    findings_collected: int = 0
    findings_new: int = 0
    findings_duplicate: int = 0
    findings_exported: int = 0
    errors: list[str] = field(default_factory=list)
    dry_run: bool = False

    @property
    def success(self) -> bool:
        return len(self.errors) == 0


@dataclass
class PipelineResult:
    """Aggregated result from a full pipeline run."""

    group: str
    connector_results: list[CollectionResult] = field(default_factory=list)

    @property
    def total_findings(self) -> int:
        return sum(r.findings_collected for r in self.connector_results)

    @property
    def total_new(self) -> int:
        return sum(r.findings_new for r in self.connector_results)

    @property
    def total_duplicates(self) -> int:
        return sum(r.findings_duplicate for r in self.connector_results)

    @property
    def errors(self) -> list[str]:
        return [e for r in self.connector_results for e in r.errors]


class RunCollectionUseCase:
    """
    Orchestrates a collection run for one or more connectors.

    Depends on:
        - CollectionPipelinePort: executes connector → pipeline
        - ConnectorRegistryPort: resolves connector IDs
        - AbstractUnitOfWork: persistence
        - DeduplicationService: prevents duplicate findings
    """

    def __init__(
        self,
        pipeline: CollectionPipelinePort,
        registry: ConnectorRegistryPort,
        uow: AbstractUnitOfWork,
        dedup_service: DeduplicationService,
        export_threshold: float = 7.0,
    ) -> None:
        self._pipeline = pipeline
        self._registry = registry
        self._uow = uow
        self._dedup = dedup_service
        self._export_threshold = export_threshold

    async def run_connector(self, cmd: RunConnectorCommand) -> CollectionResult:
        """Execute collection for a single connector."""
        log = logger.bind(connector=cmd.connector_id, dry_run=cmd.dry_run)
        log.info("collection.start")

        result = CollectionResult(
            connector_id=cmd.connector_id,
            dry_run=cmd.dry_run,
        )

        try:
            findings = await self._pipeline.execute(
                connector_id=cmd.connector_id,
                dry_run=cmd.dry_run,
            )
            result.findings_collected = len(findings)
            log.info("collection.pipeline_complete", count=len(findings))

            if cmd.dry_run:
                log.info("collection.dry_run_skip_persist")
                result.findings_new = len(findings)
                return result

            async with self._uow:
                for finding in findings:
                    fingerprint = self._dedup.compute_fingerprint(finding)
                    existing = await self._uow.findings.get_by_fingerprint(fingerprint)

                    if existing:
                        result.findings_duplicate += 1
                        log.debug(
                            "collection.duplicate_skipped",
                            fingerprint=fingerprint[:16],
                        )
                        continue

                    await self._uow.findings.save(finding)
                    result.findings_new += 1

                    if finding.should_auto_export:
                        result.findings_exported += 1
                        log.info(
                            "collection.auto_export_queued",
                            finding_id=finding.id,
                            score=finding.score.value,
                        )

        except Exception as exc:
            error_msg = f"Connector {cmd.connector_id} failed: {exc}"
            result.errors.append(error_msg)
            log.error("collection.error", error=str(exc), exc_info=True)

        log.info(
            "collection.complete",
            new=result.findings_new,
            duplicates=result.findings_duplicate,
            errors=len(result.errors),
        )
        return result

    async def run_pipeline(self, cmd: RunPipelineCommand) -> PipelineResult:
        """Execute collection pipeline for a group of connectors."""
        connector_ids = self._registry.get_enabled_connector_ids(
            group=None if cmd.group == "all" else cmd.group
        )

        logger.info(
            "pipeline.start",
            group=cmd.group,
            connector_count=len(connector_ids),
            dry_run=cmd.dry_run,
        )

        pipeline_result = PipelineResult(group=cmd.group)

        for connector_id in connector_ids:
            connector_cmd = RunConnectorCommand(
                connector_id=connector_id,
                dry_run=cmd.dry_run,
            )
            result = await self.run_connector(connector_cmd)
            pipeline_result.connector_results.append(result)

        logger.info(
            "pipeline.complete",
            group=cmd.group,
            total_findings=pipeline_result.total_findings,
            total_new=pipeline_result.total_new,
            total_duplicates=pipeline_result.total_duplicates,
            total_errors=len(pipeline_result.errors),
        )
        return pipeline_result
