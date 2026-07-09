"""Domain value objects.

Responsibility
--------------
Immutable, self-validating value objects that compose domain entities.
Business rules for identity, scoring bounds, and IOC typing live here.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from threat_hunting.core.domain.enums import (
    ArtifactType,
    IndicatorType,
    RelationshipType,
    Severity,
)


def utc_now() -> datetime:
    """Return timezone-aware UTC now."""
    return datetime.now(UTC)


class FindingId(BaseModel):
    """Strongly-typed Finding identity (UUID4)."""

    model_config = ConfigDict(frozen=True)

    value: str = Field(default_factory=lambda: str(uuid.uuid4()))

    def __str__(self) -> str:
        return self.value

    @classmethod
    def generate(cls) -> FindingId:
        return cls()

    @classmethod
    def from_string(cls, value: str) -> FindingId:
        return cls(value=value)


class Score(BaseModel):
    """Risk/relevance score in [0, 100]."""

    model_config = ConfigDict(frozen=True)

    value: float = Field(ge=0.0, le=100.0, default=0.0)

    def __float__(self) -> float:
        return self.value

    def exceeds(self, threshold: float) -> bool:
        return self.value >= threshold

    def with_delta(self, delta: float) -> Score:
        return Score(value=max(0.0, min(100.0, self.value + delta)))


class Confidence(BaseModel):
    """Confidence in [0.0, 1.0]."""

    model_config = ConfigDict(frozen=True)

    value: float = Field(ge=0.0, le=1.0, default=0.5)

    def __float__(self) -> float:
        return self.value


class Tag(BaseModel):
    """Normalized tag label."""

    model_config = ConfigDict(frozen=True)

    name: str

    @field_validator("name")
    @classmethod
    def normalize(cls, v: str) -> str:
        cleaned = v.strip().lower().replace(" ", "_")
        if not cleaned:
            raise ValueError("Tag name cannot be empty")
        return cleaned


class Indicator(BaseModel):
    """Typed Indicator of Compromise."""

    model_config = ConfigDict(frozen=True)

    type: IndicatorType
    value: str
    context: str | None = None
    confidence: Confidence = Field(default_factory=Confidence)

    @field_validator("value")
    @classmethod
    def strip_value(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("Indicator value cannot be empty")
        return cleaned

    def fingerprint(self) -> str:
        payload = f"{self.type.value}:{self.value.lower()}"
        return hashlib.sha256(payload.encode()).hexdigest()


class Artifact(BaseModel):
    """Evidence artifact attached to a Finding."""

    model_config = ConfigDict(frozen=True)

    type: ArtifactType
    name: str
    content: str | bytes | None = None
    uri: str | None = None
    content_hash: str | None = None
    mime_type: str | None = None
    size_bytes: int | None = None
    collected_at: datetime = Field(default_factory=utc_now)

    def compute_hash(self) -> str:
        if self.content is None:
            return self.content_hash or ""
        data = self.content if isinstance(self.content, bytes) else self.content.encode()
        return hashlib.sha256(data).hexdigest()


class Relationship(BaseModel):
    """Directed relationship between domain objects."""

    model_config = ConfigDict(frozen=True)

    type: RelationshipType
    source_id: str
    target_id: str
    description: str | None = None
    confidence: Confidence = Field(default_factory=Confidence)
    metadata: dict[str, Any] = Field(default_factory=dict)


class TimelineEvent(BaseModel):
    """Chronological event in a Finding lifecycle."""

    model_config = ConfigDict(frozen=True)

    timestamp: datetime = Field(default_factory=utc_now)
    event_type: str
    description: str
    actor: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class FindingMetadata(BaseModel):
    """Extensible metadata bag for Findings."""

    model_config = ConfigDict(frozen=True)

    url: str | None = None
    author: str | None = None
    language: str | None = None
    geo: str | None = None
    extra: dict[str, Any] = Field(default_factory=dict)


class DetectionMatch(BaseModel):
    """Result of a single detection rule evaluation."""

    model_config = ConfigDict(frozen=True)

    rule_id: str
    rule_type: str
    matched: bool
    matched_values: list[str] = Field(default_factory=list)
    severity: Severity = Severity.INFORMATIONAL
    score_delta: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)


class HealthStatus(BaseModel):
    """Health check result value object."""

    model_config = ConfigDict(frozen=True)

    component: str
    state: str
    message: str = ""
    latency_ms: float | None = None
    checked_at: datetime = Field(default_factory=utc_now)
    details: dict[str, Any] = Field(default_factory=dict)


class OpsecProfile(BaseModel):
    """OPSEC transport profile (value object, config-driven)."""

    model_config = ConfigDict(frozen=True)

    name: str
    proxy: str | None = None
    user_agent: str = "ThreatHuntingPlatform/1.0"
    rate_limit_rps: float = 1.0
    max_retries: int = 3
    backoff_factor: float = 2.0
    timeout_seconds: float = 30.0
    credentials_ref: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    verify_tls: bool = True


class Keyword(BaseModel):
    """Monitored keyword entry."""

    model_config = ConfigDict(frozen=True)

    value: str
    case_sensitive: bool = False
    whole_word: bool = False

    def matches(self, text: str) -> bool:
        flags = 0 if self.case_sensitive else re.IGNORECASE
        if self.whole_word:
            pattern = rf"\b{re.escape(self.value)}\b"
            return re.search(pattern, text, flags) is not None
        if self.case_sensitive:
            return self.value in text
        return self.value.lower() in text.lower()


class VipProfile(BaseModel):
    """VIP monitoring profile."""

    model_config = ConfigDict(frozen=True)

    name: str
    aliases: list[str] = Field(default_factory=list)
    emails: list[str] = Field(default_factory=list)
    titles: list[str] = Field(default_factory=list)
    company: str | None = None
    priority: int = Field(default=1, ge=1, le=10)


class ContentHash(BaseModel):
    """Content fingerprint for deduplication."""

    model_config = ConfigDict(frozen=True)

    algorithm: str = "sha256"
    value: str

    @classmethod
    def from_text(cls, text: str) -> ContentHash:
        normalized = " ".join(text.lower().split())
        digest = hashlib.sha256(normalized.encode()).hexdigest()
        return cls(value=digest)

    @classmethod
    def from_bytes(cls, data: bytes) -> ContentHash:
        return cls(value=hashlib.sha256(data).hexdigest())


__all__ = [
    "FindingId",
    "Score",
    "Confidence",
    "Tag",
    "Indicator",
    "Artifact",
    "Relationship",
    "TimelineEvent",
    "FindingMetadata",
    "DetectionMatch",
    "HealthStatus",
    "OpsecProfile",
    "Keyword",
    "VipProfile",
    "ContentHash",
    "utc_now",
]
