"""
Keyword Entity
==============

Represents a search term used by connectors to filter collected data.
Keywords drive the collection layer and are evaluated by the Detection Engine.

Types of keywords:
- Plain keyword/phrase
- Brand name / company name
- Domain name
- Executive / VIP name
- Email address
- CPF / CNPJ
- Regex pattern
- IOC value
- Threat actor name
- Wallet address
- Telegram / GitHub identifiers

Domain rules:
- A disabled keyword is not passed to connectors.
- The match_count is incremented by the Detection Engine on every hit.
- Exact keywords are lower-cased before storage for consistent matching.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class KeywordType(str, Enum):
    """Semantic classification of a keyword."""

    PLAIN = "plain"
    BRAND = "brand"
    DOMAIN = "domain"
    EXECUTIVE = "executive"
    VIP = "vip"
    EMAIL = "email"
    CPF = "cpf"
    CNPJ = "cnpj"
    REGEX = "regex"
    IOC = "ioc"
    THREAT_ACTOR = "threat_actor"
    WALLET = "wallet"
    TELEGRAM = "telegram"
    GITHUB = "github"
    YARA = "yara"
    SIGMA = "sigma"


class Keyword(BaseModel):
    """Search term entity."""

    model_config = {"validate_assignment": True}

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    value: str
    type: KeywordType = KeywordType.PLAIN
    description: str = ""
    is_enabled: bool = True
    case_sensitive: bool = False
    watchlist_id: str | None = None
    tags: list[str] = Field(default_factory=list)
    match_count: int = 0
    last_match: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("value")
    @classmethod
    def value_must_not_be_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Keyword value must not be empty")
        return v.strip()

    def record_match(self) -> None:
        """Increment match counter and update last_match timestamp."""
        self.match_count += 1
        self.last_match = datetime.now(timezone.utc)
        self.updated_at = datetime.now(timezone.utc)

    @property
    def normalized_value(self) -> str:
        """Return the value normalized for comparison."""
        return self.value if self.case_sensitive else self.value.lower()

    def __repr__(self) -> str:
        return f"Keyword(value={self.value!r}, type={self.type.value!r})"
