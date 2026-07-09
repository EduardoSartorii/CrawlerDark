"""
Pipeline — Orchestrates Finding Processing
==========================================

The Pipeline is the central orchestrator of the Threat Hunting Platform.
It accepts a Finding from a connector and runs it through each stage
sequentially, collecting metrics and handling errors at every step.

Design:
    - Builder Pattern: use PipelineBuilder to compose stage lists.
    - Each stage is fully independent (Command Pattern).
    - A failed stage does not abort the pipeline unless it raises a fatal error.
    - Metrics are collected per-stage for observability.
    - The pipeline emits domain events at key transitions.

Pipeline execution order (mandated by business rules):
    1. DetectionStage
    2. ScoringStage
    3. CorrelationStage
    4. DeduplicationStage
    5. EnrichmentStage
    6. PersistenceStage
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import structlog

from threat_hunting.core.application.pipeline.stages import PipelineStage
from threat_hunting.core.domain.entities.finding import FindingStatus
from threat_hunting.core.domain.events.finding_events import FindingPersisted
from threat_hunting.core.domain.events.detection_events import ThreatDetected

if TYPE_CHECKING:
    from threat_hunting.core.domain.entities.finding import Finding
    from threat_hunting.core.domain.ports.event_bus import IEventBus
    from threat_hunting.core.domain.ports.exporters import IExporter

logger = structlog.get_logger(__name__)


@dataclass
class StageResult:
    """Metrics collected for a single pipeline stage execution."""

    stage_name: str
    success: bool
    duration_ms: float
    error: str | None = None


@dataclass
class PipelineResult:
    """Aggregated result of a full pipeline run for one Finding."""

    finding_id: str
    success: bool
    stages: list[StageResult] = field(default_factory=list)
    total_duration_ms: float = 0.0
    exported_to: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def failed_stages(self) -> list[str]:
        return [s.stage_name for s in self.stages if not s.success]


class Pipeline:
    """
    Core processing pipeline.

    Processes one Finding through all registered stages.
    After persistence, triggers auto-export if the score threshold is met.
    """

    def __init__(
        self,
        stages: list[PipelineStage],
        event_bus: "IEventBus",
        exporters: list["IExporter"] | None = None,
        auto_export_threshold: float = 7.5,
    ) -> None:
        self._stages = stages
        self._event_bus = event_bus
        self._exporters = exporters or []
        self._auto_export_threshold = auto_export_threshold

    async def process(self, finding: "Finding") -> PipelineResult:
        """Run the Finding through all pipeline stages.

        Args:
            finding: A normalized Finding from a connector.

        Returns:
            PipelineResult with execution details and metrics.
        """
        pipeline_start = time.perf_counter()
        result = PipelineResult(finding_id=finding.id, success=True)

        log = logger.bind(finding_id=finding.id, connector=finding.connector)
        log.info("pipeline_start", title=finding.title)

        for stage in self._stages:
            stage_start = time.perf_counter()
            try:
                finding = await stage.execute(finding)
                duration = (time.perf_counter() - stage_start) * 1000
                result.stages.append(StageResult(stage.stage_name, True, duration))
                log.debug("stage_complete", stage=stage.stage_name, duration_ms=f"{duration:.1f}")
            except Exception as exc:
                duration = (time.perf_counter() - stage_start) * 1000
                result.stages.append(
                    StageResult(stage.stage_name, False, duration, error=str(exc))
                )
                log.error(
                    "stage_failed",
                    stage=stage.stage_name,
                    error=str(exc),
                    exc_info=True,
                )
                # Non-fatal: continue to next stage unless it is persistence.
                if stage.stage_name == "persistence":
                    result.success = False
                    result.error = str(exc)
                    break

        # Auto-export when score exceeds configured threshold.
        if (
            finding.status != FindingStatus.DISMISSED
            and not finding.is_duplicate
            and finding.score.value >= self._auto_export_threshold
        ):
            result.exported_to = await self._auto_export(finding, log)

        result.total_duration_ms = (time.perf_counter() - pipeline_start) * 1000
        log.info(
            "pipeline_complete",
            success=result.success,
            score=finding.score.value,
            severity=finding.severity.value,
            duration_ms=f"{result.total_duration_ms:.1f}",
        )

        # Emit domain events.
        await self._event_bus.publish(
            FindingPersisted(
                aggregate_id=finding.id,
                storage_backend="configured_backend",
            )
        )

        if finding.severity.value in ("high", "critical"):
            await self._event_bus.publish(
                ThreatDetected(
                    aggregate_id=finding.id,
                    finding_id=finding.id,
                    score=finding.score.value,
                    severity=finding.severity.value,
                    category=finding.category.value,
                    connector=finding.connector,
                    matched_rules=finding.matched_rules,
                )
            )

        return result

    async def _auto_export(self, finding: "Finding", log: structlog.BoundLogger) -> list[str]:
        """Attempt to export a high-scoring Finding to all configured exporters."""
        exported: list[str] = []
        for exporter in self._exporters:
            try:
                success = await exporter.export(finding)
                if success:
                    finding.record_export(exporter.exporter_id)
                    exported.append(exporter.exporter_id)
                    log.info("auto_exported", exporter=exporter.exporter_id)
            except Exception as exc:
                log.error("auto_export_failed", exporter=exporter.exporter_id, error=str(exc))
        return exported


class PipelineBuilder:
    """
    Builder Pattern — fluent API for constructing a Pipeline.

    Example:
        pipeline = (
            PipelineBuilder(event_bus)
            .with_detection(detection_engine)
            .with_scoring(scoring_engine)
            .with_correlation(correlation_engine)
            .with_deduplication(deduplication_engine)
            .with_enrichment(enrichment_engine)
            .with_persistence(uow)
            .with_exporter(misp_exporter)
            .build()
        )
    """

    def __init__(self, event_bus: "IEventBus", auto_export_threshold: float = 7.5) -> None:
        self._event_bus = event_bus
        self._stages: list[PipelineStage] = []
        self._exporters: list["IExporter"] = []
        self._auto_export_threshold = auto_export_threshold

    def with_stage(self, stage: PipelineStage) -> "PipelineBuilder":
        self._stages.append(stage)
        return self

    def with_exporter(self, exporter: "IExporter") -> "PipelineBuilder":
        self._exporters.append(exporter)
        return self

    def build(self) -> Pipeline:
        return Pipeline(
            stages=self._stages,
            event_bus=self._event_bus,
            exporters=self._exporters,
            auto_export_threshold=self._auto_export_threshold,
        )
