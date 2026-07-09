"""
Indicator Entity
================

Represents an Indicator of Compromise (IOC) extracted from raw threat data.
An Indicator is an entity (has identity) rather than a value object because
it accumulates enrichment data over its lifetime and participates in
correlation relationships.

Aggregate: Indicator is a first-class aggregate root within the Detection
bounded context. The Finding aggregate references Indicators by ID.

Domain rules:
- Every indicator has a unique (type, value) pair within the platform.
- Enrichment data is always additive — existing facts are never overwritten.
- Confidence degrades over time (time-decay not implemented here but designed for).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

from threat_hunting.core.domain.value_objects.indicator_type import IndicatorType


class EnrichmentData(BaseModel):
    """Structured container for enrichment metadata attached to an Indicator."""

    model_config = {"extra": "allow"}

    # IP enrichment
    asn: str | None = None
    asn_org: str | None = None
    country: str | None = None
    city: str | None = None
    is_tor: bool | None = None
    is_proxy: bool | None = None
    is_vpn: bool | None = None
    abuse_score: int | None = None

    # Domain enrichment
    registrar: str | None = None
    creation_date: datetime | None = None
    expiration_date: datetime | None = None
    nameservers: list[str] = Field(default_factory=list)
    mx_records: list[str] = Field(default_factory=list)

    # File enrichment
    file_type: str | None = None
    file_size: int | None = None
    malware_family: str | None = None
    vt_detections: int | None = None
    vt_total: int | None = None

    # Generic
    tags: list[str] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)


class Indicator(BaseModel):
    """
    IOC entity.

    Equality is by (type, value) — the same IOC from different sources
    is the same entity.
    """

    model_config = {"validate_assignment": True}

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    type: IndicatorType
    value: str
    context: str | None = None
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    tags: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)
    enrichment: EnrichmentData = Field(default_factory=EnrichmentData)
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    is_whitelisted: bool = False
    is_blacklisted: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("value")
    @classmethod
    def value_must_not_be_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Indicator value must not be empty")
        return v.strip().lower() if len(v.strip()) < 256 else v.strip()

    @model_validator(mode="after")
    def update_last_seen(self) -> "Indicator":
        if self.last_seen < self.first_seen:
            self.last_seen = self.first_seen
        return self

    def merge_enrichment(self, data: dict[str, Any]) -> None:
        """Merge new enrichment facts without overwriting existing ones."""
        current = self.enrichment.model_dump(exclude_none=True)
        for key, val in data.items():
            if key not in current or current[key] is None:
                setattr(self.enrichment, key, val)
        self.enrichment.raw.update(data)

    def add_source(self, source: str) -> None:
        """Track which connectors have reported this indicator."""
        if source not in self.sources:
            self.sources.append(source)

    def add_finding(self, finding_id: str) -> None:
        """Register a Finding that contains this indicator."""
        if finding_id not in self.finding_ids:
            self.finding_ids.append(finding_id)

    def touch(self) -> None:
        """Update the last_seen timestamp to now."""
        self.last_seen = datetime.now(timezone.utc)

    @property
    def unique_key(self) -> str:
        """Canonical deduplication key: type + normalized value."""
        return f"{self.type.value}:{self.value}"

    def __hash__(self) -> int:
        return hash(self.unique_key)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Indicator):
            return NotImplemented
        return self.unique_key == other.unique_key

    def __repr__(self) -> str:
        return f"Indicator(type={self.type.value!r}, value={self.value!r})"
