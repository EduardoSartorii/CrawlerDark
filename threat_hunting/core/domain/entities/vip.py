"""
VIP Entity
==========

Represents a protected entity subject to VIP Monitoring:
- C-level executives (CEO, CFO, CTO, CISO, ...)
- Board members
- High-profile employees
- Corporate assets (brands, domains)

When a VIP entity is mentioned in collected data, the Detection Engine
raises the severity and the Scoring Engine applies the vip_match weight.

Domain rules:
- A VIP has a unique identity (person or asset).
- Multiple identifiers (emails, social handles, aliases) belong to one VIP.
- Alert notifications are sent immediately when vip_match is triggered.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class VIPType(str, Enum):
    """Type of the monitored VIP entity."""

    PERSON = "person"
    BRAND = "brand"
    DOMAIN = "domain"
    ASSET = "asset"


class VIP(BaseModel):
    """Protected entity for VIP Monitoring."""

    model_config = {"validate_assignment": True}

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    type: VIPType = VIPType.PERSON
    description: str = ""
    organization: str | None = None
    role: str | None = None
    is_enabled: bool = True

    # Identifiers used for detection
    emails: list[str] = Field(default_factory=list)
    aliases: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    social_handles: dict[str, str] = Field(default_factory=dict)
    phones: list[str] = Field(default_factory=list)

    tags: list[str] = Field(default_factory=list)
    alert_on_mention: bool = True
    match_count: int = 0
    last_match: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("name")
    @classmethod
    def name_must_not_be_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("VIP name must not be empty")
        return v.strip()

    @property
    def all_identifiers(self) -> list[str]:
        """All searchable identifiers for this VIP."""
        identifiers = [self.name, *self.aliases, *self.emails, *self.domains]
        identifiers.extend(self.social_handles.values())
        return [i.lower() for i in identifiers if i]

    def record_match(self) -> None:
        """Increment match counter."""
        self.match_count += 1
        self.last_match = datetime.now(timezone.utc)
        self.updated_at = datetime.now(timezone.utc)

    def matches_text(self, text: str) -> bool:
        """Check if any identifier appears in text."""
        text_lower = text.lower()
        return any(ident in text_lower for ident in self.all_identifiers)

    def __repr__(self) -> str:
        return f"VIP(name={self.name!r}, type={self.type.value!r})"
