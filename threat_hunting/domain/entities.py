"""Domain entities for findings, watchlists and rules.

This module centralizes immutable business language used by every layer.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator


class Severity(StrEnum):
    """Severity scale used across detections and exports."""

    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Finding(BaseModel):
    """Canonical finding entity produced by all connectors and pipeline stages."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    title: str
    description: str
    source: str
    connector: str
    category: str
    severity: Severity = Severity.info
    score: float = 0.0
    confidence: float = 0.0
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    raw_data: dict[str, Any] = Field(default_factory=dict)
    normalized_data: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    artifacts: list[dict[str, Any]] = Field(default_factory=list)
    indicators: list[dict[str, Any]] = Field(default_factory=list)
    relationships: list[dict[str, Any]] = Field(default_factory=list)
    timeline: list[dict[str, Any]] = Field(default_factory=list)

    @field_validator("score", "confidence")
    @classmethod
    def validate_percentage(cls, value: float) -> float:
        """Ensure score/confidence are bounded between 0 and 100."""
        if value < 0 or value > 100:
            msg = "score/confidence must be between 0 and 100"
            raise ValueError(msg)
        return value

    @property
    def fingerprint(self) -> str:
        """Deterministic dedup fingerprint across critical finding dimensions."""
        seed = "|".join(
            [
                self.title.lower().strip(),
                self.source.lower().strip(),
                self.connector.lower().strip(),
                str(self.normalized_data.get("ioc", "")),
                str(self.normalized_data.get("domain", "")),
                str(self.normalized_data.get("email", "")),
            ]
        )
        return sha256(seed.encode("utf-8")).hexdigest()


class RuleType(StrEnum):
    """Dynamic detection rule types."""

    regex = "regex"
    yara = "yara"
    sigma = "sigma"
    keyword = "keyword"
    ioc_match = "ioc_match"
    threat_actor_match = "threat_actor_match"
    whitelist = "whitelist"
    blacklist = "blacklist"
    threshold = "threshold"
    composite = "composite"


class DetectionRule(BaseModel):
    """Runtime detection rule loaded from configuration."""

    id: str
    name: str
    enabled: bool = True
    type: RuleType
    pattern: str | None = None
    tags: list[str] = Field(default_factory=list)
    weight: float = 1.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class ScoringPolicy(BaseModel):
    """Configurable scoring weights and threshold configuration."""

    threshold_misp_auto_export: float = 80.0
    weights: dict[str, float] = Field(default_factory=dict)

    def weight_for(self, signal_name: str) -> float:
        """Resolve weight for a signal with safe default."""
        return float(self.weights.get(signal_name, 0.0))


class WatchlistProfile(BaseModel):
    """Collection targets and monitored assets for threat hunting."""

    keywords: list[str] = Field(default_factory=list)
    watchlists: list[str] = Field(default_factory=list)
    vips: list[str] = Field(default_factory=list)
    companies: list[str] = Field(default_factory=list)
    executives: list[str] = Field(default_factory=list)
    brands: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    threat_actors: list[str] = Field(default_factory=list)
    emails: list[str] = Field(default_factory=list)
    cpfs: list[str] = Field(default_factory=list)
    cnpjs: list[str] = Field(default_factory=list)
    cards: list[str] = Field(default_factory=list)
    wallets: list[str] = Field(default_factory=list)
    telegram_handles: list[str] = Field(default_factory=list)
    github_handles: list[str] = Field(default_factory=list)
    ioc_lists: list[str] = Field(default_factory=list)
    yara_rules: list[str] = Field(default_factory=list)
    regex_rules: list[str] = Field(default_factory=list)
    sigma_rules: list[str] = Field(default_factory=list)
