"""Domain entities — Finding aggregate root and related entities.

Responsibility
--------------
Finding is the canonical intelligence unit produced by every connector.
All pipeline stages mutate/enrich Findings through domain methods that
emit domain events. No infrastructure imports allowed.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, field_validator

from threat_hunting.core.domain.enums import FindingCategory, Severity
from threat_hunting.core.domain.events.base import DomainEvent
from threat_hunting.core.domain.value_objects import (
    Artifact,
    Confidence,
    ContentHash,
    DetectionMatch,
    FindingId,
    FindingMetadata,
    Indicator,
    Relationship,
    Score,
    Tag,
    TimelineEvent,
    utc_now,
)

_SEVERITY_RANK = {
    Severity.INFORMATIONAL: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Finding(BaseModel):
    """Aggregate Root — canonical threat intelligence finding.

    Business rules
    --------------
    - Every connector MUST produce Findings (never source-specific models).
    - Score/confidence are updated only via domain methods.
    - Timeline records every significant mutation.
    - Content hash supports deduplication.
    """

    model_config = ConfigDict(validate_assignment=True)

    id: FindingId = Field(default_factory=FindingId.generate)
    title: str
    description: str = ""
    source: str
    connector: str
    category: FindingCategory = FindingCategory.OTHER
    severity: Severity = Severity.INFORMATIONAL
    score: Score = Field(default_factory=Score)
    confidence: Confidence = Field(default_factory=Confidence)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    raw_data: dict[str, Any] = Field(default_factory=dict)
    normalized_data: dict[str, Any] = Field(default_factory=dict)
    metadata: FindingMetadata = Field(default_factory=FindingMetadata)
    tags: list[Tag] = Field(default_factory=list)
    artifacts: list[Artifact] = Field(default_factory=list)
    indicators: list[Indicator] = Field(default_factory=list)
    relationships: list[Relationship] = Field(default_factory=list)
    timeline: list[TimelineEvent] = Field(default_factory=list)
    detections: list[DetectionMatch] = Field(default_factory=list)
    content_hash: str | None = None
    is_duplicate: bool = False
    duplicate_of: str | None = None

    # Transient domain events (not persisted)
    _events: list[DomainEvent] = PrivateAttr(default_factory=list)

    @field_validator("title")
    @classmethod
    def title_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Finding title cannot be empty")
        return v.strip()

    def model_post_init(self, __context: Any) -> None:
        if self.content_hash is None:
            self.content_hash = ContentHash.from_text(
                f"{self.title}|{self.description}|{self.source}"
            ).value

    # --- Domain behaviors ---

    def add_tag(self, name: str) -> None:
        tag = Tag(name=name)
        if tag not in self.tags:
            self.tags.append(tag)
            self._touch("tag_added", f"Tag '{tag.name}' added")

    def add_indicator(self, indicator: Indicator) -> None:
        fps = {i.fingerprint() for i in self.indicators}
        if indicator.fingerprint() not in fps:
            self.indicators.append(indicator)
            self._touch("indicator_added", f"IOC {indicator.type}:{indicator.value}")

    def add_artifact(self, artifact: Artifact) -> None:
        self.artifacts.append(artifact)
        self._touch("artifact_added", f"Artifact {artifact.name}")

    def add_relationship(self, relationship: Relationship) -> None:
        self.relationships.append(relationship)
        self._touch("relationship_added", f"Relationship {relationship.type}")

    def apply_detection(self, match: DetectionMatch) -> None:
        self.detections.append(match)
        if match.matched and match.score_delta:
            self.update_score(self.score.with_delta(match.score_delta))
        if match.matched and _SEVERITY_RANK[match.severity] > _SEVERITY_RANK[self.severity]:
            self.severity = match.severity
        self._touch("detection_applied", f"Rule {match.rule_id} matched={match.matched}")

    def update_score(self, score: Score) -> None:
        self.score = score
        self._touch("score_updated", f"Score set to {score.value}")

    def update_confidence(self, confidence: Confidence) -> None:
        self.confidence = confidence
        self._touch("confidence_updated", f"Confidence set to {confidence.value}")

    def mark_duplicate(self, original_id: str) -> None:
        self.is_duplicate = True
        self.duplicate_of = original_id
        self._touch("marked_duplicate", f"Duplicate of {original_id}")

    def enrich(self, data: dict[str, Any]) -> None:
        merged = {**self.normalized_data, **data}
        self.normalized_data = merged
        self._touch("enriched", f"Enriched with keys: {list(data.keys())}")

    def collect_events(self) -> list[DomainEvent]:
        events = list(self._events)
        self._events.clear()
        return events

    def register_event(self, event: DomainEvent) -> None:
        self._events.append(event)

    def _touch(self, event_type: str, description: str) -> None:
        self.updated_at = utc_now()
        self.timeline.append(
            TimelineEvent(event_type=event_type, description=description)
        )

    def to_export_dict(self) -> dict[str, Any]:
        """Serialize for exporters (STIX/MISP/JSON)."""
        return {
            "id": str(self.id),
            "title": self.title,
            "description": self.description,
            "source": self.source,
            "connector": self.connector,
            "category": self.category.value,
            "severity": self.severity.value,
            "score": float(self.score),
            "confidence": float(self.confidence),
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "tags": [t.name for t in self.tags],
            "indicators": [
                {"type": i.type.value, "value": i.value, "context": i.context}
                for i in self.indicators
            ],
            "metadata": self.metadata.model_dump(),
            "normalized_data": self.normalized_data,
            "content_hash": self.content_hash,
            "is_duplicate": self.is_duplicate,
        }
