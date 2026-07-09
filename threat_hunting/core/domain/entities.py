"""Domain entities — aggregate roots and entities.

The Finding aggregate is the central intelligence unit produced by all connectors.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from threat_hunting.core.domain.enums import (
    FindingCategory,
    IndicatorType,
    Severity,
    SourceType,
)


class Indicator(BaseModel):
    """Extracted IOC or observable indicator."""

    type: IndicatorType
    value: str
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    context: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class Artifact(BaseModel):
    """Evidence artifact attached to a finding."""

    type: str
    uri: str = ""
    content_hash: str = ""
    mime_type: str = ""
    size_bytes: int = 0
    metadata: dict[str, Any] = Field(default_factory=dict)


class Relationship(BaseModel):
    """Graph relationship between findings or external entities."""

    target_id: str
    relation_type: str
    target_type: str = "finding"
    metadata: dict[str, Any] = Field(default_factory=dict)


class TimelineEvent(BaseModel):
    """Chronological event within a finding lifecycle."""

    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    event_type: str
    description: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    """Central intelligence aggregate root.

    All connectors MUST produce findings conforming to this model.
    Business rule: score and confidence must be between 0.0 and 100.0 / 1.0.
    """

    id: UUID = Field(default_factory=uuid4)
    title: str
    description: str = ""
    source: SourceType
    connector: str
    category: FindingCategory = FindingCategory.GENERAL
    severity: Severity = Severity.INFO
    score: float = Field(default=0.0, ge=0.0, le=100.0)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    raw_data: dict[str, Any] = Field(default_factory=dict)
    normalized_data: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    artifacts: list[Artifact] = Field(default_factory=list)
    indicators: list[Indicator] = Field(default_factory=list)
    relationships: list[Relationship] = Field(default_factory=list)
    timeline: list[TimelineEvent] = Field(default_factory=list)

    def touch(self) -> None:
        """Update the modification timestamp."""
        self.updated_at = datetime.now(UTC)

    def add_indicator(self, indicator: Indicator) -> None:
        """Append an indicator avoiding exact duplicates."""
        if not any(i.type == indicator.type and i.value == indicator.value for i in self.indicators):
            self.indicators.append(indicator)
            self.touch()

    def add_tag(self, tag: str) -> None:
        """Append a unique tag."""
        if tag not in self.tags:
            self.tags.append(tag)
            self.touch()

    def add_timeline_event(self, event_type: str, description: str = "") -> None:
        """Record a lifecycle event."""
        self.timeline.append(TimelineEvent(event_type=event_type, description=description))
        self.touch()


class FindingDraft(BaseModel):
    """Pre-persistence finding produced by normalizers before pipeline enrichment."""

    title: str
    description: str = ""
    source: SourceType
    connector: str
    category: FindingCategory = FindingCategory.GENERAL
    raw_data: dict[str, Any] = Field(default_factory=dict)
    normalized_data: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    artifacts: list[Artifact] = Field(default_factory=list)
    indicators: list[Indicator] = Field(default_factory=list)

    def to_finding(self) -> Finding:
        """Materialize a full Finding entity from draft state."""
        return Finding(
            title=self.title,
            description=self.description,
            source=self.source,
            connector=self.connector,
            category=self.category,
            raw_data=self.raw_data,
            normalized_data=self.normalized_data,
            metadata=self.metadata,
            tags=self.tags,
            artifacts=self.artifacts,
            indicators=self.indicators,
        )


class WatchlistEntry(BaseModel):
    """Monitored entity for detection and scoring."""

    id: UUID = Field(default_factory=uuid4)
    watchlist_type: str
    value: str
    label: str = ""
    enabled: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class DetectionRule(BaseModel):
    """Dynamically loaded detection rule."""

    id: UUID = Field(default_factory=uuid4)
    name: str
    rule_type: str
    pattern: str
    enabled: bool = True
    severity: Severity = Severity.MEDIUM
    category: FindingCategory = FindingCategory.GENERAL
    weight: float = 1.0
    metadata: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)


class ScoreWeight(BaseModel):
    """Configurable weight for a scoring dimension."""

    dimension: str
    weight: float = Field(default=1.0, ge=0.0)
    enabled: bool = True


class ScoreProfile(BaseModel):
    """Aggregate scoring configuration profile."""

    id: UUID = Field(default_factory=uuid4)
    name: str
    weights: list[ScoreWeight] = Field(default_factory=list)
    threshold_auto_export: float = Field(default=70.0, ge=0.0, le=100.0)


class ConnectorConfig(BaseModel):
    """Connector operational configuration."""

    name: str
    enabled: bool = True
    schedule_cron: str = ""
    opsec_profile: str = "default"
    metadata: dict[str, Any] = Field(default_factory=dict)


class CorrelationLink(BaseModel):
    """Link between correlated entities."""

    id: UUID = Field(default_factory=uuid4)
    source_id: UUID
    target_id: str
    correlation_type: str
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ExportJob(BaseModel):
    """Export job tracking entity."""

    id: UUID = Field(default_factory=uuid4)
    finding_id: UUID
    format: str
    destination: str
    status: str = "pending"
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None
    error: str = ""


class AuditLog(BaseModel):
    """Immutable audit trail entry."""

    id: UUID = Field(default_factory=uuid4)
    action: str
    actor: str = "system"
    resource_type: str = ""
    resource_id: str = ""
    details: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
