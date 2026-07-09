"""
Campaign Entity
===============

Represents a coordinated malicious campaign (e.g., phishing wave, ransomware
campaign, credential stuffing operation). A Campaign aggregates Findings and
Indicators, and is associated with zero or more ThreatActors.

Domain rules:
- A Campaign has a time window (start/end) that bounds its activity.
- Findings are correlated into a Campaign by the CorrelationEngine.
- The score of a Campaign is the maximum score of its associated Findings.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field, field_validator

from threat_hunting.core.domain.value_objects.category import Category


class Campaign(BaseModel):
    """Coordinated threat campaign entity."""

    model_config = {"validate_assignment": True}

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str = ""
    category: Category = Category.CAMPAIGN
    tags: list[str] = Field(default_factory=list)
    threat_actor_ids: list[str] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)
    indicator_ids: list[str] = Field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    is_active: bool = True
    ttps: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("name")
    @classmethod
    def name_must_not_be_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Campaign name must not be empty")
        return v.strip()

    def add_finding(self, finding_id: str) -> None:
        if finding_id not in self.finding_ids:
            self.finding_ids.append(finding_id)
            self.updated_at = datetime.now(timezone.utc)

    def __repr__(self) -> str:
        return f"Campaign(name={self.name!r}, findings={len(self.finding_ids)})"
