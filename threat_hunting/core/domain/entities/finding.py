"""
Finding Entity — Core Aggregate Root.

The Finding is the central aggregate in the CTI platform.
Every connector, engine, and exporter ultimately produces or consumes Findings.

Domain Rules:
    - A Finding is the authoritative record of a detected threat signal
    - Its lifecycle: raw → parsed → normalized → detected → scored → correlated → exported
    - Score and severity are computed (never arbitrary) and must be traceable
    - A Finding may contain multiple IOCs (Indicators), artifacts, and relationships
    - Duplicate Findings are prevented by the Deduplication Engine before persistence
    - Findings can be promoted to MISP events when score exceeds configured threshold
    - TLP (Traffic Light Protocol) governs sharing restrictions

Aggregate Root responsibilities:
    - Owns its Indicators (via IDs for loose coupling)
    - Owns its Artifacts and Relationships
    - Emits domain events on significant state transitions
    - Enforces invariants (e.g., score range, required fields)
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import Field, field_validator

from ..value_objects import Score, Severity, SeverityLevel, ThreatCategory
from ..value_objects.source_type import SourceType
from .base import BaseEntity, DomainEvent, _utcnow


class FindingStatus(StrEnum):
    """Lifecycle state of a Finding within the platform."""

    NEW = "new"
    PROCESSING = "processing"
    REVIEWED = "reviewed"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    EXPORTED = "exported"
    ARCHIVED = "archived"


class ArtifactType(StrEnum):
    """Types of artifacts that can be attached to a Finding."""

    SCREENSHOT = "screenshot"
    RAW_TEXT = "raw_text"
    HTML = "html"
    JSON = "json"
    FILE = "file"
    LOG = "log"
    PCAP = "pcap"


class Artifact(BaseEntity):
    """
    An artifact attached to a Finding.
    Contains raw evidence supporting the threat signal.
    """

    artifact_type: ArtifactType
    content: str = Field(default="", description="Content or file path")
    mime_type: str = Field(default="text/plain")
    size_bytes: int = Field(default=0, ge=0)
    metadata: dict[str, Any] = Field(default_factory=dict)


class Relationship(BaseEntity):
    """
    A directed relationship between two Findings or between a Finding and an entity.

    Implements the CTI relationship model from STIX 2.1:
    - source → relationship_type → target
    """

    source_id: str
    target_id: str
    relationship_type: str  # e.g. "attributed-to", "uses", "related-to", "indicates"
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    description: str = Field(default="")
    metadata: dict[str, Any] = Field(default_factory=dict)


class TimelineEvent(BaseEntity):
    """A timestamped event in a Finding's timeline."""

    timestamp: datetime = Field(default_factory=_utcnow)
    actor: str = Field(default="system")
    action: str
    detail: str = Field(default="")


# ─── Domain Events ─────────────────────────────────────────────────────────────


class FindingCreatedEvent(DomainEvent):
    event_type: str = "finding.created"


class FindingConfirmedEvent(DomainEvent):
    event_type: str = "finding.confirmed"


class FindingFalsePositiveEvent(DomainEvent):
    event_type: str = "finding.false_positive"


class FindingScoredEvent(DomainEvent):
    event_type: str = "finding.scored"


class FindingExportedEvent(DomainEvent):
    event_type: str = "finding.exported"


# ─── Finding Aggregate Root ────────────────────────────────────────────────────


class Finding(BaseEntity):
    """
    Core aggregate root of the CTI platform.

    Represents a single, normalized, enriched threat intelligence signal.
    All connectors produce Findings; all exporters consume them.
    """

    # Core identification
    title: str = Field(..., min_length=1, max_length=512)
    description: str = Field(default="")
    source: str = Field(..., description="Human-readable source name")
    source_type: SourceType = Field(default=SourceType.UNKNOWN)
    connector: str = Field(..., description="Connector ID that produced this finding")
    category: ThreatCategory = Field(default=ThreatCategory.UNKNOWN)
    status: FindingStatus = Field(default=FindingStatus.NEW)

    # Risk assessment
    score: Score = Field(default_factory=Score.zero)
    severity: Severity = Field(default_factory=Severity.info)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)

    # Content
    raw_data: str = Field(default="", description="Unprocessed source content")
    normalized_data: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    # Classification
    tags: list[str] = Field(default_factory=list)
    tlp: str = Field(default="WHITE", description="TLP: WHITE, GREEN, AMBER, RED")
    language: str = Field(default="en")

    # Relationships to other domain entities (ID references — no ORM here)
    indicator_ids: list[str] = Field(default_factory=list)
    artifact_ids: list[str] = Field(default_factory=list)

    # Embedded value collections
    artifacts: list[Artifact] = Field(default_factory=list)
    relationships: list[Relationship] = Field(default_factory=list)
    timeline: list[TimelineEvent] = Field(default_factory=list)

    # Deduplication fingerprint (hash of normalized content)
    fingerprint: str = Field(default="")

    # External references
    source_url: str | None = Field(default=None)
    source_id: str | None = Field(default=None, description="ID in the original source")
    misp_event_id: str | None = Field(default=None)
    opencti_id: str | None = Field(default=None)

    # Enrichment fields
    threat_actor: str | None = Field(default=None)
    campaign: str | None = Field(default=None)
    malware_family: str | None = Field(default=None)
    affected_brands: list[str] = Field(default_factory=list)
    affected_domains: list[str] = Field(default_factory=list)
    country: str | None = Field(default=None)

    @field_validator("tlp")
    @classmethod
    def validate_tlp(cls, v: str) -> str:
        valid = {"WHITE", "GREEN", "AMBER", "AMBER+STRICT", "RED"}
        if v.upper() not in valid:
            raise ValueError(f"Invalid TLP '{v}'. Valid: {valid}")
        return v.upper()

    @field_validator("title")
    @classmethod
    def strip_title(cls, v: str) -> str:
        return v.strip()

    # ─── Factory ─────────────────────────────────────────────────────────────

    @classmethod
    def create(
        cls,
        title: str,
        source: str,
        connector: str,
        category: ThreatCategory = ThreatCategory.UNKNOWN,
        source_type: SourceType = SourceType.UNKNOWN,
        description: str = "",
        raw_data: str = "",
        tags: list[str] | None = None,
    ) -> "Finding":
        """
        Factory method — the primary way to create new Findings.
        Emits FindingCreatedEvent.
        """
        finding = cls(
            title=title,
            source=source,
            connector=connector,
            category=category,
            source_type=source_type,
            description=description,
            raw_data=raw_data,
            tags=tags or [],
        )
        finding.raise_event(
            FindingCreatedEvent(
                aggregate_id=finding.id,
                payload={
                    "title": title,
                    "source": source,
                    "connector": connector,
                    "category": category.value,
                },
            )
        )
        return finding

    # ─── Domain Behavior ─────────────────────────────────────────────────────

    def apply_score(self, score: Score) -> None:
        """
        Apply a computed score to this finding.
        Automatically derives severity from the new score value.
        """
        self.score = score
        self.severity = Severity.from_score(score.value)
        self.confidence = score.confidence
        self.touch()
        self.raise_event(
            FindingScoredEvent(
                aggregate_id=self.id,
                payload={
                    "score": score.value,
                    "confidence": score.confidence,
                    "severity": self.severity.level.name,
                },
            )
        )

    def confirm(self, analyst: str = "system") -> None:
        """Mark finding as confirmed by an analyst."""
        self.status = FindingStatus.CONFIRMED
        self._add_timeline("confirmed", analyst, "Finding confirmed as true positive")
        self.raise_event(
            FindingConfirmedEvent(
                aggregate_id=self.id,
                payload={"analyst": analyst},
            )
        )

    def mark_false_positive(self, reason: str, analyst: str = "system") -> None:
        """Dismiss finding as a false positive."""
        self.status = FindingStatus.FALSE_POSITIVE
        self.metadata["fp_reason"] = reason
        self._add_timeline("false_positive", analyst, f"FP: {reason}")
        self.raise_event(
            FindingFalsePositiveEvent(
                aggregate_id=self.id,
                payload={"analyst": analyst, "reason": reason},
            )
        )

    def mark_exported(self, destination: str) -> None:
        """Record that this finding was exported to an external platform."""
        self.status = FindingStatus.EXPORTED
        self.metadata[f"exported_to_{destination}"] = _utcnow().isoformat()
        self._add_timeline("exported", "system", f"Exported to {destination}")
        self.raise_event(
            FindingExportedEvent(
                aggregate_id=self.id,
                payload={"destination": destination},
            )
        )

    def add_tag(self, tag: str) -> None:
        """Add a classification tag (deduplicated)."""
        tag = tag.lower().strip()
        if tag and tag not in self.tags:
            self.tags.append(tag)
            self.touch()

    def add_indicator_id(self, indicator_id: str) -> None:
        """Link an IOC to this finding."""
        if indicator_id not in self.indicator_ids:
            self.indicator_ids.append(indicator_id)
            self.touch()

    def add_relationship(self, relationship: Relationship) -> None:
        """Add a STIX-style relationship."""
        self.relationships.append(relationship)
        self.touch()

    def attach_artifact(self, artifact: Artifact) -> None:
        """Attach evidence artifact."""
        self.artifacts.append(artifact)
        self.artifact_ids.append(artifact.id)
        self.touch()

    def _add_timeline(self, action: str, actor: str, detail: str) -> None:
        self.timeline.append(
            TimelineEvent(action=action, actor=actor, detail=detail)
        )
        self.touch()

    # ─── Computed Properties ──────────────────────────────────────────────────

    @property
    def is_critical(self) -> bool:
        return self.severity.level == SeverityLevel.CRITICAL

    @property
    def is_high_or_above(self) -> bool:
        return self.severity.level >= SeverityLevel.HIGH

    @property
    def should_auto_export(self) -> bool:
        """True when score qualifies for automatic export to MISP/OpenCTI."""
        return self.score.adjusted >= 7.0

    @property
    def ioc_count(self) -> int:
        return len(self.indicator_ids)

    def __str__(self) -> str:
        return (
            f"Finding({self.id[:8]}… | {self.severity} | "
            f"{self.category.value} | score={self.score.value:.1f} | {self.title[:60]})"
        )
