"""Domain entities and value objects.

Business rule: every connector, regardless of source, emits the same
``Finding`` aggregate so downstream engines can be composed without knowing
where the intelligence came from.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


def utc_now() -> datetime:
    """Return timezone-aware UTC timestamps for auditable records."""

    return datetime.now(timezone.utc)


class Severity(StrEnum):
    """Normalized finding severity used by scoring and exports."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IndicatorType(StrEnum):
    """Supported IOC and fraud artifact types."""

    DOMAIN = "domain"
    IP = "ip"
    URL = "url"
    EMAIL = "email"
    HASH = "hash"
    CPF = "cpf"
    CNPJ = "cnpj"
    CARD = "card"
    WALLET = "wallet"
    USERNAME = "username"
    ASN = "asn"
    CERTIFICATE = "certificate"
    MALWARE = "malware"
    THREAT_ACTOR = "threat_actor"
    CAMPAIGN = "campaign"
    OTHER = "other"


class Artifact(BaseModel):
    """Evidence object extracted from raw collection data."""

    model_config = ConfigDict(frozen=True)

    type: str
    value: str
    context: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class Indicator(BaseModel):
    """Normalized IOC or business watch artifact."""

    model_config = ConfigDict(frozen=True)

    type: IndicatorType
    value: str
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    source: str | None = None
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("value")
    @classmethod
    def normalize_value(cls, value: str) -> str:
        """Normalize comparisons while preserving raw value in metadata when needed."""

        return value.strip()


class Relationship(BaseModel):
    """Relationship between findings, indicators, campaigns, and actors."""

    model_config = ConfigDict(frozen=True)

    source_ref: str
    target_ref: str
    relationship_type: str
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    metadata: dict[str, Any] = Field(default_factory=dict)


class TimelineEvent(BaseModel):
    """Timeline entry for a finding lifecycle or campaign observation."""

    timestamp: datetime = Field(default_factory=utc_now)
    event_type: str
    description: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    """Canonical threat hunting finding emitted by all connectors."""

    id: UUID = Field(default_factory=uuid4)
    title: str
    description: str
    source: str
    connector: str
    category: str
    severity: Severity = Severity.INFO
    score: float = Field(default=0.0, ge=0.0, le=100.0)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    raw_data: dict[str, Any] = Field(default_factory=dict)
    normalized_data: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    artifacts: list[Artifact] = Field(default_factory=list)
    indicators: list[Indicator] = Field(default_factory=list)
    relationships: list[Relationship] = Field(default_factory=list)
    timeline: list[TimelineEvent] = Field(default_factory=list)

    def with_score(self, score: float, severity: Severity) -> "Finding":
        """Return an updated finding after scoring without mutating the aggregate."""

        return self.model_copy(
            update={"score": min(max(score, 0.0), 100.0), "severity": severity, "updated_at": utc_now()}
        )

    def fingerprint_payload(self) -> str:
        """Build deterministic content used by deduplication strategies."""

        indicator_values = sorted(f"{indicator.type}:{indicator.value.lower()}" for indicator in self.indicators)
        return "|".join(
            [
                self.source.lower(),
                self.connector.lower(),
                self.category.lower(),
                self.title.strip().lower(),
                *indicator_values,
            ]
        )


class Watchlist(BaseModel):
    """Managed collection of keywords, VIPs, brands, IOCs, and rule references."""

    id: UUID = Field(default_factory=uuid4)
    name: str
    category: str
    values: list[str]
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
