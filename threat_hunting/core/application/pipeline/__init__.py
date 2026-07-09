"""Pipeline canônico do sistema.

Cada estágio é uma implementação de ``PipelineStage``. O orquestrador
compõe os estágios na ordem definida por configuração (não hardcoded).
"""

from .context import PipelineContext
from .orchestrator import PipelineOrchestrator
from .stage import PipelineStage
from .stages import (
    CanonicalizeStage,
    CorrelateStage,
    DeduplicateStage,
    DetectStage,
    EnrichStage,
    ExportStage,
    ExtractStage,
    NormalizeStage,
    ParseStage,
    PersistStage,
    ScoreStage,
)

__all__ = [
    "CanonicalizeStage",
    "CorrelateStage",
    "DeduplicateStage",
    "DetectStage",
    "EnrichStage",
    "ExportStage",
    "ExtractStage",
    "NormalizeStage",
    "ParseStage",
    "PersistStage",
    "PipelineContext",
    "PipelineOrchestrator",
    "PipelineStage",
    "ScoreStage",
]
