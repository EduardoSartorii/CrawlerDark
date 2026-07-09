"""
Finding Entity — Primary Aggregate Root
========================================

A Finding is the central artifact of the platform. Every connector,
regardless of source, produces Findings. The pipeline processes Findings
through detection, scoring, correlation, deduplication, enrichment, and export.

Architecture:
    Finding is the Aggregate Root of the Collection bounded context.
    All pipeline stages consume and/or enrich Findings.
    The Finding is immutable once exported (status=EXPORTED).

Domain Rules:
    - Every Finding has a globally unique ID.
    - Score and severity are always derived — never set manually.
    - Raw data and normalized data are separate concerns.
    - Tags are cumulative — pipeline stages add, never remove tags.
    - A Finding is only exported once per exporter (tracked in export_log).
    - Relationships are soft references by ID — no foreign-key coupling.

Builder Pattern:
    Use FindingBuilder to construct Findings in tests and connectors.
    Direct construction is discouraged for complex cases.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, model_validator

from threat_hunting.core.domain.value_objects.category import Category
from threat_hunting.core.domain.value_objects.score import Score
from threat_hunting.core.domain.value_objects.severity import Severity
from threat_hunting.core.domain.value_objects.source import SourceType


class FindingStatus(str, Enum):
    """Lifecycle state of a Finding through the pipeline."""

    RAW = "raw"
    PARSED = "parsed"
    NORMALIZED = "normalized"
    DETECTED = "detected"
    SCORED = "scored"
    CORRELATED = "correlated"
    DEDUPLICATED = "deduplicated"
    ENRICHED = "enriched"
    PERSISTED = "persisted"
    EXPORTED = "exported"
    DISMISSED = "dismissed"
    FALSE_POSITIVE = "false_positive"


class Artifact(BaseModel):
    """A binary or textual artifact extracted from raw data (screenshot, file, etc.)."""

    type: str
    name: str
    content: str | None = None
    url: str | None = None
    hash: str | None = None
    size: int | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class Relationship(BaseModel):
    """Soft reference to a related entity (another Finding, Indicator, ThreatActor, etc.)."""

    target_type: str
    target_id: str
    relationship_type: str
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    metadata: dict[str, Any] = Field(default_factory=dict)


class TimelineEntry(BaseModel):
    """Chronological event entry for audit trail."""

    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    event: str
    actor: str = "system"
    details: dict[str, Any] = Field(default_factory=dict)


class DetectionResult(BaseModel):
    """Output of a single detection rule match."""

    rule_id: str
    rule_name: str
    rule_type: str
    matched: bool = True
    match_data: dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)


class Finding(BaseModel):
    """
    Primary aggregate root of the Threat Hunting Platform.

    Every connector produces Finding objects. The pipeline enriches this
    object as it progresses through each stage.
    """

    model_config = {"validate_assignment": True}

    # ── Identity ──────────────────────────────────────────────────────────────
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))

    # ── Core metadata ─────────────────────────────────────────────────────────
    title: str
    description: str = ""
    source: SourceType
    connector: str
    category: Category = Category.GENERAL
    status: FindingStatus = FindingStatus.RAW

    # ── Risk assessment (set by scoring engine) ───────────────────────────────
    severity: Severity = Severity.INFO
    score: Score = Field(default_factory=Score.zero)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)

    # ── Timestamps ────────────────────────────────────────────────────────────
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source_published_at: datetime | None = None

    # ── Data ──────────────────────────────────────────────────────────────────
    raw_data: str | dict[str, Any] | None = None
    normalized_data: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    # ── Classification ─────────────────────────────────────────────────────────
    tags: list[str] = Field(default_factory=list)

    # ── Extracted elements ────────────────────────────────────────────────────
    artifacts: list[Artifact] = Field(default_factory=list)
    indicators: list[str] = Field(default_factory=list)  # Indicator IDs

    # ── Correlation / relationships ───────────────────────────────────────────
    relationships: list[Relationship] = Field(default_factory=list)
    duplicate_of: str | None = None
    correlation_group: str | None = None

    # ── Detection results ─────────────────────────────────────────────────────
    detection_results: list[DetectionResult] = Field(default_factory=list)

    # ── Export tracking ───────────────────────────────────────────────────────
    export_log: dict[str, datetime] = Field(default_factory=dict)

    # ── Audit trail ───────────────────────────────────────────────────────────
    timeline: list[TimelineEntry] = Field(default_factory=list)

    # ── Source-specific URL ───────────────────────────────────────────────────
    source_url: str | None = None
    source_id: str | None = None

    @model_validator(mode="after")
    def ensure_timeline_start(self) -> "Finding":
        if not self.timeline:
            self.timeline.append(
                TimelineEntry(event="finding_created", details={"connector": self.connector})
            )
        return self

    # ── Mutation helpers ──────────────────────────────────────────────────────

    def add_tag(self, tag: str) -> None:
        """Add a tag if not already present."""
        normalized = tag.lower().strip().replace(" ", "_")
        if normalized and normalized not in self.tags:
            self.tags.append(normalized)

    def add_tags(self, tags: list[str]) -> None:
        for tag in tags:
            self.add_tag(tag)

    def set_score(self, score: Score) -> None:
        """Assign score and derive severity automatically."""
        self.score = score
        self.confidence = score.confidence
        self.severity = Severity.from_score(score.value)
        self.updated_at = datetime.now(timezone.utc)

    def add_indicator(self, indicator_id: str) -> None:
        if indicator_id not in self.indicators:
            self.indicators.append(indicator_id)

    def add_detection(self, result: DetectionResult) -> None:
        self.detection_results.append(result)

    def add_relationship(self, rel: Relationship) -> None:
        self.relationships.append(rel)

    def add_artifact(self, artifact: Artifact) -> None:
        self.artifacts.append(artifact)

    def record_export(self, exporter_id: str) -> None:
        """Mark this Finding as exported to a given exporter."""
        self.export_log[exporter_id] = datetime.now(timezone.utc)

    def advance_status(self, new_status: FindingStatus, details: dict[str, Any] | None = None) -> None:
        """Move the Finding to the next pipeline status and log the transition."""
        self.status = new_status
        self.updated_at = datetime.now(timezone.utc)
        self.timeline.append(
            TimelineEntry(
                event=f"status_{new_status.value}",
                details=details or {},
            )
        )

    def mark_false_positive(self, reason: str) -> None:
        self.status = FindingStatus.FALSE_POSITIVE
        self.updated_at = datetime.now(timezone.utc)
        self.timeline.append(TimelineEntry(event="false_positive", details={"reason": reason}))

    def mark_duplicate(self, original_id: str) -> None:
        self.duplicate_of = original_id
        self.status = FindingStatus.DEDUPLICATED
        self.updated_at = datetime.now(timezone.utc)

    @property
    def is_duplicate(self) -> bool:
        return self.duplicate_of is not None

    @property
    def is_exported(self) -> bool:
        return bool(self.export_log)

    @property
    def has_iocs(self) -> bool:
        return bool(self.indicators)

    @property
    def matched_rules(self) -> list[str]:
        return [r.rule_name for r in self.detection_results if r.matched]

    def __repr__(self) -> str:
        return (
            f"Finding(id={self.id!r}, title={self.title!r}, "
            f"score={self.score.value:.2f}, severity={self.severity.value!r})"
        )
