"""Business entities for collected threat intelligence.

The domain model is deliberately persistence-free. Every connector, parser and
engine exchanges the same ``Finding`` aggregate so that business rules can evolve
without coupling to source-specific payloads or storage backends.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, computed_field


class Severity(StrEnum):
    """Normalized severity used by detection and export policies."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IndicatorType(StrEnum):
    """Supported IOC and entity categories for correlation."""

    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    HASH = "hash"
    CPF = "cpf"
    CNPJ = "cnpj"
    CARD = "card"
    WALLET = "wallet"
    ASN = "asn"
    CERTIFICATE = "certificate"
    THREAT_ACTOR = "threat_actor"
    CAMPAIGN = "campaign"
    NICKNAME = "nickname"
    GITHUB = "github"
    TELEGRAM = "telegram"
    MALWARE = "malware"
    BRAND = "brand"
    INFRASTRUCTURE = "infrastructure"


class Artifact(BaseModel):
    """Collected evidence such as screenshots, documents or raw files."""

    model_config = ConfigDict(frozen=True)

    kind: str
    value: str
    mime_type: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class Indicator(BaseModel):
    """Normalized indicator of compromise or fraud entity."""

    model_config = ConfigDict(frozen=True)

    type: IndicatorType
    value: str
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    metadata: dict[str, Any] = Field(default_factory=dict)


class Relationship(BaseModel):
    """Graph edge connecting findings, campaigns, actors and infrastructure."""

    model_config = ConfigDict(frozen=True)

    source: str
    target: str
    kind: str
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    metadata: dict[str, Any] = Field(default_factory=dict)


class TimelineEvent(BaseModel):
    """Temporal event observed during collection or enrichment."""

    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    title: str
    description: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    """Canonical aggregate emitted by every connector and pipeline stage."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    title: str
    description: str = ""
    source: str
    connector: str
    category: str
    severity: Severity = Severity.INFO
    score: float = Field(default=0.0, ge=0.0, le=100.0)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
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

    @computed_field
    @property
    def content_hash(self) -> str:
        """Stable hash used by deduplication across storage backends."""

        material = "|".join(
            [
                self.source,
                self.connector,
                self.title.lower().strip(),
                self.description.lower().strip(),
                ",".join(sorted(ind.value.lower() for ind in self.indicators)),
            ]
        )
        return sha256(material.encode("utf-8")).hexdigest()


class Watchlist(BaseModel):
    """Business-owned monitoring scope for brands, VIPs, IOCs and patterns."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    name: str
    category: str
    values: list[str] = Field(default_factory=list)
    enabled: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)


class DetectionRule(BaseModel):
    """Dynamic detection rule loaded from configuration or repositories."""

    id: str
    name: str
    kind: str
    pattern: str
    severity: Severity = Severity.INFO
    tags: list[str] = Field(default_factory=list)
    weight: float = 1.0
    enabled: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)


class ScorePolicy(BaseModel):
    """Configurable scoring weights and export threshold."""

    weights: dict[str, float] = Field(default_factory=dict)
    export_threshold: float = 80.0
    severity_thresholds: dict[Severity, float] = Field(
        default_factory=lambda: {
            Severity.INFO: 0,
            Severity.LOW: 20,
            Severity.MEDIUM: 40,
            Severity.HIGH: 70,
            Severity.CRITICAL: 90,
        }
    )


class ConnectorDefinition(BaseModel):
    """Configuration record that enables connector discovery and execution."""

    name: str
    type: str
    source: str
    enabled: bool = True
    opsec_profile: str = "default"
    config: dict[str, Any] = Field(default_factory=dict)
