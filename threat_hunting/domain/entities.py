"""Domain entities and value objects for threat intelligence findings."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


class Severity(StrEnum):
    """Standardized severity for findings."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Indicator(BaseModel):
    """A normalized indicator extracted from source data."""

    model_config = ConfigDict(extra="allow")

    type: str
    value: str
    confidence: float = Field(default=0.5, ge=0, le=1)
    metadata: dict[str, Any] = Field(default_factory=dict)


class Artifact(BaseModel):
    """Artifact attached to a finding, such as screenshot or document."""

    model_config = ConfigDict(extra="allow")

    type: str
    reference: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class Relationship(BaseModel):
    """Relationship edge to other entities/findings."""

    target_type: str
    target_id: str
    relation_type: str
    confidence: float = Field(default=0.5, ge=0, le=1)


class TimelineEvent(BaseModel):
    """Time-series event associated to a finding lifecycle."""

    timestamp: datetime
    label: str
    details: dict[str, Any] = Field(default_factory=dict)


class ScoreBreakdown(BaseModel):
    """Transparent score contribution map."""

    factors: dict[str, float] = Field(default_factory=dict)
    total: float = 0.0


class Finding(BaseModel):
    """Canonical finding model produced by every connector."""

    model_config = ConfigDict(extra="allow")

    id: UUID = Field(default_factory=uuid4)
    title: str
    description: str
    source: str
    connector: str
    category: str = "generic"
    severity: Severity = Severity.LOW
    score: float = Field(default=0.0, ge=0)
    confidence: float = Field(default=0.5, ge=0, le=1)
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
    score_breakdown: ScoreBreakdown = Field(default_factory=ScoreBreakdown)

    def add_tag(self, tag: str) -> None:
        """Append non-duplicated tag value."""
        normalized = tag.strip().lower()
        if normalized and normalized not in self.tags:
            self.tags.append(normalized)

    def touch(self) -> None:
        """Update last modification timestamp."""
        self.updated_at = datetime.now(UTC)


class ExecutionContext(BaseModel):
    """Request-scoped execution metadata shared by all pipeline stages."""

    run_id: UUID = Field(default_factory=uuid4)
    command: str
    connector_name: str
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    profile: str = "default"
    options: dict[str, Any] = Field(default_factory=dict)
