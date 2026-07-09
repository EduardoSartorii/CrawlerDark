"""Application use cases — orchestration of domain logic."""

from .run_collection import (
    CollectionResult,
    PipelineResult,
    RunCollectionUseCase,
)

__all__ = [
    "RunCollectionUseCase",
    "CollectionResult",
    "PipelineResult",
]
