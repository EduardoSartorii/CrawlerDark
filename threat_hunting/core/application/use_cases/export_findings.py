"""
ExportFindingsUseCase
=====================

Exports Findings matching given criteria to one or more external platforms.

Supports:
    - Export by severity threshold
    - Export by connector
    - Export by category
    - Export by date range
    - Export a specific Finding by ID

Used by the CLI 'hunt export' command.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from threat_hunting.core.domain.ports.exporters import IExporter
    from threat_hunting.core.domain.ports.storage import IUnitOfWork

logger = structlog.get_logger(__name__)


@dataclass
class ExportCriteria:
    """Filters for selecting Findings to export."""

    finding_ids: list[str] = field(default_factory=list)
    min_severity: str | None = None
    connector: str | None = None
    category: str | None = None
    since: datetime | None = None
    until: datetime | None = None
    tags: list[str] = field(default_factory=list)
    limit: int = 1000


@dataclass
class ExportResult:
    """Result of a bulk export operation."""

    exporter_id: str
    total_attempted: int = 0
    total_succeeded: int = 0
    failed_ids: list[str] = field(default_factory=list)
    error: str | None = None


class ExportFindingsUseCase:
    """Export Findings to external platforms."""

    def __init__(self, uow: "IUnitOfWork") -> None:
        self._uow = uow

    async def execute(
        self, exporter: "IExporter", criteria: ExportCriteria
    ) -> ExportResult:
        """Export Findings matching criteria using the given exporter.

        Args:
            exporter: The configured exporter to use.
            criteria: Selection criteria for Findings.

        Returns:
            ExportResult with success/failure statistics.
        """
        log = logger.bind(exporter=exporter.exporter_id)
        result = ExportResult(exporter_id=exporter.exporter_id)

        async with self._uow as uow:
            if criteria.finding_ids:
                findings = [
                    f
                    for fid in criteria.finding_ids
                    if (f := await uow.findings.get_by_id(fid)) is not None
                ]
            else:
                findings = await uow.findings.list(
                    connector=criteria.connector,
                    severity=criteria.min_severity,
                    category=criteria.category,
                    since=criteria.since,
                    until=criteria.until,
                    tags=criteria.tags or None,
                    limit=criteria.limit,
                )

        result.total_attempted = len(findings)
        log.info("export_start", total=result.total_attempted)

        batch_results = await exporter.export_batch(findings)
        for finding_id, success in batch_results.items():
            if success:
                result.total_succeeded += 1
            else:
                result.failed_ids.append(finding_id)

        log.info(
            "export_complete",
            succeeded=result.total_succeeded,
            failed=len(result.failed_ids),
        )
        return result
