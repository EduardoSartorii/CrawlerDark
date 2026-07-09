"""Finding entity + FindingBuilder.

Responsibility
--------------
:class:`Finding` is *the* canonical output of the platform. Every connector,
regardless of source, must ultimately produce this exact model so that the
detection/scoring/correlation/dedup/enrichment/export stages are source
agnostic. This uniformity is the backbone of the Open/Closed design: new
sources plug in without changing any downstream stage.

:class:`FindingBuilder` (Builder Pattern) provides a fluent, validated way to
assemble a complex finding (many indicators/artifacts/relationships) without a
telescoping constructor and while guaranteeing the aggregate is always valid.

Business rules
--------------
* ``severity``/``score``/``confidence`` are always present and within range.
* Indicators, artifacts and relationships are de-duplicated on add.
* Mutations record a :class:`TimelineEvent` for auditability and refresh
  ``updated_at``.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

from threat_hunting.core.domain.enums import Category, Severity
from threat_hunting.core.domain.value_objects.artifact import Artifact
from threat_hunting.core.domain.value_objects.indicator import Indicator
from threat_hunting.core.domain.value_objects.relationship import Relationship
from threat_hunting.core.domain.value_objects.score import DetectionMatch, Score
from threat_hunting.core.domain.value_objects.timeline import TimelineEvent


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Finding(BaseModel):
    """The single canonical unit of intelligence produced by the pipeline."""

    id: str = Field(default_factory=lambda: uuid4().hex)
    title: str = Field(min_length=1)
    description: str = ""
    source: str = Field(description="Human-readable source name/URL.")
    connector: str = Field(description="Connector that produced this finding.")
    category: Category = Category.OTHER
    severity: Severity = Severity.INFO
    score: Score = Field(default_factory=Score.zero)
    confidence: int = Field(default=50, ge=0, le=100)
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)

    raw_data: dict[str, Any] = Field(default_factory=dict)
    normalized_data: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    tags: list[str] = Field(default_factory=list)
    artifacts: list[Artifact] = Field(default_factory=list)
    indicators: list[Indicator] = Field(default_factory=list)
    relationships: list[Relationship] = Field(default_factory=list)
    detections: list[DetectionMatch] = Field(default_factory=list)
    timeline: list[TimelineEvent] = Field(default_factory=list)

    # -- mutation helpers (keep invariants + audit trail) -----------------
    def _touch(self) -> None:
        object.__setattr__(self, "updated_at", _utcnow())

    def record(self, stage: str, message: str = "", **details: str) -> None:
        """Append a timeline event and refresh ``updated_at`` (audit trail)."""
        self.timeline.append(TimelineEvent(stage=stage, message=message, details=details))
        self._touch()

    def add_tag(self, tag: str) -> None:
        """Add a tag if not already present."""
        if tag and tag not in self.tags:
            self.tags.append(tag)
            self._touch()

    def add_indicator(self, indicator: Indicator) -> None:
        """Add an indicator, de-duplicating on its stable key."""
        keys = {i.key for i in self.indicators}
        if indicator.key not in keys:
            self.indicators.append(indicator)
            self._touch()

    def add_artifact(self, artifact: Artifact) -> None:
        """Add an artifact (dedup on sha256 when available, else name)."""
        existing = {a.sha256 or a.name for a in self.artifacts}
        if (artifact.sha256 or artifact.name) not in existing:
            self.artifacts.append(artifact)
            self._touch()

    def add_relationship(self, relationship: Relationship) -> None:
        """Add a relationship, de-duplicating on its key."""
        keys = {r.key for r in self.relationships}
        if relationship.key not in keys:
            self.relationships.append(relationship)
            self._touch()

    def add_detection(self, match: DetectionMatch) -> None:
        """Record a detection match."""
        self.detections.append(match)
        self._touch()

    def set_score(self, score: Score) -> None:
        """Set the score and re-derive severity from it."""
        object.__setattr__(self, "score", score)
        object.__setattr__(self, "severity", Severity.from_score(score.value))
        self._touch()

    @property
    def indicator_keys(self) -> set[str]:
        """Set of indicator keys — used by correlation/dedup engines."""
        return {i.key for i in self.indicators}


class FindingBuilder:
    """Fluent builder assembling a valid :class:`Finding` step by step."""

    def __init__(self, title: str, connector: str, source: str) -> None:
        self._data: dict[str, Any] = {
            "title": title,
            "connector": connector,
            "source": source,
        }
        self._indicators: list[Indicator] = []
        self._artifacts: list[Artifact] = []
        self._tags: list[str] = []
        self._relationships: list[Relationship] = []

    def description(self, text: str) -> "FindingBuilder":
        self._data["description"] = text
        return self

    def category(self, category: Category) -> "FindingBuilder":
        self._data["category"] = category
        return self

    def severity(self, severity: Severity) -> "FindingBuilder":
        self._data["severity"] = severity
        return self

    def confidence(self, confidence: int) -> "FindingBuilder":
        self._data["confidence"] = confidence
        return self

    def raw_data(self, data: dict[str, Any]) -> "FindingBuilder":
        self._data["raw_data"] = data
        return self

    def metadata(self, data: dict[str, Any]) -> "FindingBuilder":
        self._data["metadata"] = data
        return self

    def add_indicator(self, indicator: Indicator) -> "FindingBuilder":
        self._indicators.append(indicator)
        return self

    def add_artifact(self, artifact: Artifact) -> "FindingBuilder":
        self._artifacts.append(artifact)
        return self

    def add_tag(self, tag: str) -> "FindingBuilder":
        self._tags.append(tag)
        return self

    def add_relationship(self, relationship: Relationship) -> "FindingBuilder":
        self._relationships.append(relationship)
        return self

    def build(self) -> Finding:
        """Materialise the finding, applying dedup helpers for collections."""
        finding = Finding(**self._data)
        for indicator in self._indicators:
            finding.add_indicator(indicator)
        for artifact in self._artifacts:
            finding.add_artifact(artifact)
        for tag in self._tags:
            finding.add_tag(tag)
        for relationship in self._relationships:
            finding.add_relationship(relationship)
        finding.record("collected", "finding created by connector")
        return finding
