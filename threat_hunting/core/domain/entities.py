"""Domain entities and the ``Finding`` aggregate root.

Responsibility
--------------
Define the canonical intelligence model. **Every connector, regardless of
source, produces the exact same ``Finding`` shape.** This uniformity is what
allows the detection / scoring / correlation / dedup / enrichment engines to be
completely source-agnostic.

Business rules
--------------
* A ``Finding`` owns its indicators, artifacts, relationships and timeline —
  they are part of the aggregate and are mutated only through the finding.
* Mutations that change intelligence (score, severity, new indicator, new
  relationship) append a ``TimelineEvent`` and bump ``updated_at`` so the whole
  history is auditable.
* Pydantic v2 validates every field on assignment, guaranteeing invariants even
  when findings are rebuilt from persisted rows.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from threat_hunting.core.domain.enums import (
    Category,
    ConfidenceLevel,
    IndicatorType,
    RelationshipType,
    Severity,
)


def _utcnow() -> datetime:
    """Return an aware UTC timestamp (never naive)."""
    return datetime.now(timezone.utc)


def _new_id() -> str:
    """Generate a stable, URL-safe unique identifier."""
    return uuid.uuid4().hex


class _DomainModel(BaseModel):
    """Base for domain models: validates on assignment, forbids typos."""

    model_config = ConfigDict(
        validate_assignment=True,
        extra="forbid",
        use_enum_values=False,
    )


class Indicator(_DomainModel):
    """An atomic observable (IOC) extracted from collected content."""

    id: str = Field(default_factory=_new_id)
    type: IndicatorType
    value: str
    defanged: bool = False
    first_seen: datetime = Field(default_factory=_utcnow)
    context: dict[str, Any] = Field(default_factory=dict)

    def normalized_value(self) -> str:
        """Return a canonical form used for equality/deduplication."""
        return self.value.strip().lower()

    def fingerprint(self) -> str:
        """Return ``type:value`` used as a correlation/dedup key."""
        return f"{self.type.value}:{self.normalized_value()}"


class Artifact(_DomainModel):
    """A collected object attached to a finding (screenshot, file, raw HTML)."""

    id: str = Field(default_factory=_new_id)
    kind: str
    uri: str | None = None
    sha256: str | None = None
    size_bytes: int | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class Relationship(_DomainModel):
    """A typed edge between this finding and another entity/finding."""

    id: str = Field(default_factory=_new_id)
    type: RelationshipType
    target_ref: str
    confidence: ConfidenceLevel = ConfidenceLevel.UNKNOWN
    reason: str | None = None
    created_at: datetime = Field(default_factory=_utcnow)


class TimelineEvent(_DomainModel):
    """An auditable event in the life of a finding."""

    id: str = Field(default_factory=_new_id)
    at: datetime = Field(default_factory=_utcnow)
    stage: str
    message: str
    data: dict[str, Any] = Field(default_factory=dict)


class Finding(_DomainModel):
    """The canonical unit of intelligence and the aggregate root.

    The field set is fixed by the platform contract; connectors fill it
    progressively as the finding travels through the pipeline.
    """

    id: str = Field(default_factory=_new_id)
    title: str
    description: str = ""
    source: str
    connector: str
    category: Category = Category.UNCLASSIFIED
    severity: Severity = Severity.INFO
    score: float = 0.0
    confidence: ConfidenceLevel = ConfidenceLevel.UNKNOWN
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)
    raw_data: dict[str, Any] = Field(default_factory=dict)
    normalized_data: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    artifacts: list[Artifact] = Field(default_factory=list)
    indicators: list[Indicator] = Field(default_factory=list)
    relationships: list[Relationship] = Field(default_factory=list)
    timeline: list[TimelineEvent] = Field(default_factory=list)

    # -- aggregate behaviour ------------------------------------------------

    def touch(self) -> None:
        """Update the modification timestamp."""
        self.updated_at = _utcnow()

    def record(self, stage: str, message: str, **data: Any) -> None:
        """Append a timeline event and refresh ``updated_at`` (audit trail)."""
        self.timeline.append(TimelineEvent(stage=stage, message=message, data=data))
        self.touch()

    def add_indicator(self, indicator: Indicator) -> bool:
        """Add an indicator if not already present. Returns ``True`` if added."""
        existing = {i.fingerprint() for i in self.indicators}
        if indicator.fingerprint() in existing:
            return False
        self.indicators.append(indicator)
        self.touch()
        return True

    def add_relationship(self, relationship: Relationship) -> None:
        """Attach a correlation edge and audit it."""
        self.relationships.append(relationship)
        self.record(
            "correlation",
            f"linked via {relationship.type.value} -> {relationship.target_ref}",
        )

    def add_tag(self, tag: str) -> None:
        """Attach a deduplicated tag."""
        if tag not in self.tags:
            self.tags.append(tag)
            self.touch()

    def set_score(self, value: float, *, reason: str = "scoring") -> None:
        """Set the score, derive the severity band and audit the change."""
        self.score = float(value)
        self.severity = Severity.from_score(self.score)
        self.record(reason, f"score set to {self.score:.2f} ({self.severity.value})")

    def indicator_fingerprints(self) -> set[str]:
        """Return the set of indicator fingerprints (used by correlation)."""
        return {i.fingerprint() for i in self.indicators}
