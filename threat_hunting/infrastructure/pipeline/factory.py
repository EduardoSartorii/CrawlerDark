"""Pipeline factory.

Responsibility
--------------
Assemble the concrete stages in the mandatory order and wrap them in a
:class:`PipelineOrchestrator`. Centralising the ordering here means the order
constraint is expressed in exactly one place, and callers just ask for "the
default pipeline".
"""

from __future__ import annotations

from threat_hunting.core.application.ports.event_bus import EventBus
from threat_hunting.core.application.ports.repository import UnitOfWork
from threat_hunting.core.application.pipeline.orchestrator import PipelineOrchestrator
from threat_hunting.infrastructure.detections.engine import DetectionEngine
from threat_hunting.infrastructure.enrichment.engine import EnrichmentEngine
from threat_hunting.infrastructure.pipeline.stages import (
    CollectStage,
    CorrelationStage,
    DeduplicationStage,
    DetectionStage,
    EnrichmentStage,
    ExportStage,
    ExtractStage,
    NormalizeStage,
    ParseStage,
    PersistenceStage,
    ScoringStage,
)
from threat_hunting.infrastructure.scoring.engine import ScoringEngine


def build_default_pipeline(
    *,
    detection_engine: DetectionEngine,
    scoring_engine: ScoringEngine,
    enrichment_engine: EnrichmentEngine,
    unit_of_work: UnitOfWork,
    event_bus: EventBus | None = None,
    export_threshold: float = 70.0,
    fail_fast: bool = False,
) -> PipelineOrchestrator:
    """Return an orchestrator with the mandatory stages in the required order."""
    stages = [
        CollectStage(),
        ParseStage(event_bus=event_bus),
        ExtractStage(),
        NormalizeStage(),
        DetectionStage(detection_engine),
        ScoringStage(scoring_engine, event_bus=event_bus),
        CorrelationStage(),
        DeduplicationStage(),
        EnrichmentStage(enrichment_engine),
        PersistenceStage(unit_of_work, event_bus=event_bus),
        ExportStage(export_threshold, event_bus=event_bus),
    ]
    return PipelineOrchestrator(stages, event_bus=event_bus, fail_fast=fail_fast)
