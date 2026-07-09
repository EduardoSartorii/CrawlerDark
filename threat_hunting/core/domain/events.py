"""Domain events for event-driven architecture.

Events are published by the application layer and consumed by observers
(audit, metrics, auto-export) without coupling pipeline stages.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from threat_hunting.core.domain.entities import Finding


class DomainEvent(BaseModel):
    """Base domain event with correlation metadata."""

    event_id: UUID = Field(default_factory=uuid4)
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    event_type: str = ""


class FindingDetected(DomainEvent):
    """Emitted when detection engine tags a finding."""

    event_type: str = "finding.detected"
    finding: Finding
    matched_rules: list[str] = Field(default_factory=list)


class ScoringCompleted(DomainEvent):
    """Emitted after scoring engine calculates final score."""

    event_type: str = "scoring.completed"
    finding_id: UUID
    score: float
    confidence: float


class CorrelationFound(DomainEvent):
    """Emitted when correlation engine links entities."""

    event_type: str = "correlation.found"
    source_id: UUID
    target_id: str
    correlation_type: str
    confidence: float


class FindingPersisted(DomainEvent):
    """Emitted after successful persistence."""

    event_type: str = "finding.persisted"
    finding_id: UUID
    connector: str


class ExportTriggered(DomainEvent):
    """Emitted when export is initiated."""

    event_type: str = "export.triggered"
    finding_id: UUID
    export_format: str
    destination: str


class ConnectorExecuted(DomainEvent):
    """Emitted after connector pipeline run completes."""

    event_type: str = "connector.executed"
    connector: str
    findings_count: int
    duration_seconds: float
    errors: list[str] = Field(default_factory=list)


class PipelineStageCompleted(DomainEvent):
    """Emitted after each pipeline stage for observability."""

    event_type: str = "pipeline.stage.completed"
    stage: str
    connector: str
    items_processed: int
    duration_seconds: float
    metadata: dict[str, Any] = Field(default_factory=dict)
