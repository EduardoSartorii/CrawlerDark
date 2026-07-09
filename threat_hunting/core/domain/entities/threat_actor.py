"""
ThreatActor Entity
==================

Represents a known threat actor (APT group, criminal group, individual)
tracked by the platform. ThreatActor enriches Findings via correlation.

Domain rules:
- Aliases are case-insensitive for matching purposes.
- Associated infrastructure (IPs, domains) is tracked as Indicator IDs.
- Country attribution is optional and carries uncertainty.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field, field_validator


class ThreatActor(BaseModel):
    """Known threat actor or adversarial group."""

    model_config = {"validate_assignment": True}

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    aliases: list[str] = Field(default_factory=list)
    description: str = ""
    motivation: list[str] = Field(default_factory=list)
    capability: str | None = None
    country: str | None = None
    sectors_targeted: list[str] = Field(default_factory=list)
    ttps: list[str] = Field(default_factory=list)
    associated_indicators: list[str] = Field(default_factory=list)
    associated_campaigns: list[str] = Field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    tags: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("name")
    @classmethod
    def name_must_not_be_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("ThreatActor name must not be empty")
        return v.strip()

    @property
    def all_names(self) -> list[str]:
        """All known names including aliases, lower-cased for matching."""
        return [n.lower() for n in [self.name, *self.aliases]]

    def matches(self, text: str) -> bool:
        """Check if the actor name or any alias appears in text."""
        text_lower = text.lower()
        return any(alias in text_lower for alias in self.all_names)

    def __repr__(self) -> str:
        return f"ThreatActor(name={self.name!r}, aliases={self.aliases})"
