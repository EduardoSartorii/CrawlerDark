"""
Pipeline Stages
===============

Each stage wraps one engine and applies it to a Finding.
Stages are composable — the Pipeline assembles them in order.
Stages implement the Command Pattern: they encapsulate an operation and can
be logged, retried, and timed independently.

All stages handle exceptions gracefully:
    - Non-fatal errors are logged and the Finding continues through the pipeline.
    - Fatal errors propagate and abort the pipeline for that Finding.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from threat_hunting.core.domain.entities.finding import Finding
    from threat_hunting.core.domain.ports.engines import (
        ICorrelationEngine,
        IDeduplicationEngine,
        IDetectionEngine,
        IEnrichmentEngine,
        IScoringEngine,
    )
    from threat_hunting.core.domain.ports.storage import IUnitOfWork


class PipelineStage(ABC):
    """Abstract pipeline stage (Command Pattern)."""

    stage_name: str = "unknown"

    @abstractmethod
    async def execute(self, finding: "Finding") -> "Finding":
        """Process the Finding and return the (potentially modified) Finding."""


class DetectionStage(PipelineStage):
    """Runs the Detection Engine against the Finding."""

    stage_name = "detection"

    def __init__(self, engine: "IDetectionEngine") -> None:
        self._engine = engine

    async def execute(self, finding: "Finding") -> "Finding":
        return await self._engine.run(finding)


class ScoringStage(PipelineStage):
    """Runs the Scoring Engine to assign a risk score."""

    stage_name = "scoring"

    def __init__(self, engine: "IScoringEngine") -> None:
        self._engine = engine

    async def execute(self, finding: "Finding") -> "Finding":
        return await self._engine.score(finding)


class CorrelationStage(PipelineStage):
    """Runs the Correlation Engine to link related Findings."""

    stage_name = "correlation"

    def __init__(self, engine: "ICorrelationEngine") -> None:
        self._engine = engine

    async def execute(self, finding: "Finding") -> "Finding":
        return await self._engine.correlate(finding)


class DeduplicationStage(PipelineStage):
    """Runs the Deduplication Engine to mark duplicates."""

    stage_name = "deduplication"

    def __init__(self, engine: "IDeduplicationEngine") -> None:
        self._engine = engine

    async def execute(self, finding: "Finding") -> "Finding":
        return await self._engine.deduplicate(finding)


class EnrichmentStage(PipelineStage):
    """Runs the Enrichment Engine to add context to Indicators."""

    stage_name = "enrichment"

    def __init__(self, engine: "IEnrichmentEngine") -> None:
        self._engine = engine

    async def execute(self, finding: "Finding") -> "Finding":
        return await self._engine.enrich(finding)


class PersistenceStage(PipelineStage):
    """Saves the processed Finding to storage via the Unit of Work."""

    stage_name = "persistence"

    def __init__(self, uow: "IUnitOfWork") -> None:
        self._uow = uow

    async def execute(self, finding: "Finding") -> "Finding":
        from threat_hunting.core.domain.entities.finding import FindingStatus

        async with self._uow as uow:
            await uow.findings.save(finding)
            await uow.commit()
        finding.advance_status(FindingStatus.PERSISTED)
        return finding
