"""Concrete pipeline stages and the pipeline factory.

Each stage adapts an engine/connector to the core
:class:`~threat_hunting.core.application.ports.pipeline.PipelineStage` port.
:func:`build_default_pipeline` assembles them in the mandatory order into a
:class:`~threat_hunting.core.application.pipeline.orchestrator.PipelineOrchestrator`.
"""

from threat_hunting.infrastructure.pipeline.stages import (
    CollectStage,
    ParseStage,
    ExtractStage,
    NormalizeStage,
    DetectionStage,
    ScoringStage,
    CorrelationStage,
    DeduplicationStage,
    EnrichmentStage,
    PersistenceStage,
    ExportStage,
)
from threat_hunting.infrastructure.pipeline.factory import build_default_pipeline

__all__ = [
    "CollectStage",
    "ParseStage",
    "ExtractStage",
    "NormalizeStage",
    "DetectionStage",
    "ScoringStage",
    "CorrelationStage",
    "DeduplicationStage",
    "EnrichmentStage",
    "PersistenceStage",
    "ExportStage",
    "build_default_pipeline",
]
