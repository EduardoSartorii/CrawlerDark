"""Pipeline ports: PipelineStage and PipelineContext.

Responsibility
--------------
Define the contract for a single, decoupled pipeline stage and the mutable
context passed between stages. The mandatory stage order (Connector → Parser →
Extractor → Normalizer → Detection → Scoring → Correlation → Deduplication →
Enrichment → Persistence → Export) is enforced by the orchestrator, but each
stage only knows about this contract, never its neighbours.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Protocol, runtime_checkable
from uuid import uuid4

from pydantic import BaseModel, Field

from threat_hunting.core.domain.entities.finding import Finding
from threat_hunting.core.domain.entities.raw_item import RawItem


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class PipelineContext(BaseModel):
    """Carries the working state through the pipeline stages.

    Stages read/write this single object, which decouples them: a stage never
    calls the next stage, it merely transforms the context and returns it.
    """

    run_id: str = Field(default_factory=lambda: uuid4().hex)
    connector_name: str
    raw_items: list[RawItem] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    stats: dict[str, float] = Field(default_factory=dict)
    state: dict[str, Any] = Field(default_factory=dict)
    started_at: datetime = Field(default_factory=_utcnow)

    def bump(self, key: str, amount: float = 1.0) -> None:
        """Increment a numeric statistic (used for metrics/summaries)."""
        self.stats[key] = self.stats.get(key, 0.0) + amount


@runtime_checkable
class PipelineStage(Protocol):
    """A single decoupled step transforming the :class:`PipelineContext`."""

    name: str

    def process(self, context: PipelineContext) -> PipelineContext:
        """Transform and return the context (may be the same instance)."""
        ...
