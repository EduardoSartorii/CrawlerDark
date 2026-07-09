"""
Indicator Entity (Indicator of Compromise — IOC).

Represents a single, atomic piece of threat intelligence evidence.
In CTI, IOCs are used to detect, track, and attribute malicious activity.

Business Rules:
    - Each IOC has a type (IP, domain, hash, email, URL, etc.)
    - IOCs can be related to multiple Findings
    - IOC expiry prevents stale indicators from causing false positives
    - Whitelisted IOCs are never flagged regardless of other scores
    - Confidence degrades over time (configurable TTL)

Design:
    - Entity (identity-based)
    - Rich domain model with business behavior
    - No infrastructure dependencies
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import Field, field_validator

from .base import BaseEntity, DomainEvent, _utcnow


class IndicatorType(StrEnum):
    """STIX 2.1-aligned indicator type vocabulary."""

    IP_V4 = "ipv4-addr"
    IP_V6 = "ipv6-addr"
    DOMAIN = "domain-name"
    URL = "url"
    EMAIL = "email-addr"
    FILE_HASH_MD5 = "file:hashes.MD5"
    FILE_HASH_SHA1 = "file:hashes.SHA-1"
    FILE_HASH_SHA256 = "file:hashes.SHA-256"
    FILE_NAME = "file:name"
    REGISTRY_KEY = "windows-registry-key"
    MUTEX = "mutex"
    WALLET_BTC = "wallet:btc"
    WALLET_ETH = "wallet:eth"
    CVE = "vulnerability"
    ASN = "autonomous-system"
    CERTIFICATE = "x509-certificate"
    USER_AGENT = "user-agent"
    PHONE = "phone-number"
    CPF = "cpf"
    CNPJ = "cnpj"
    CREDIT_CARD = "credit-card"
    USERNAME = "username"
    TELEGRAM_HANDLE = "telegram"
    GITHUB_HANDLE = "github"
    UNKNOWN = "unknown"


class IndicatorStatus(StrEnum):
    ACTIVE = "active"
    EXPIRED = "expired"
    WHITELISTED = "whitelisted"
    UNDER_REVIEW = "under_review"
    REVOKED = "revoked"


class IndicatorAddedEvent(DomainEvent):
    event_type: str = "indicator.added"


class IndicatorWhitelistedEvent(DomainEvent):
    event_type: str = "indicator.whitelisted"


class Indicator(BaseEntity):
    """
    An atomic Indicator of Compromise.

    Acts as a shared correlation anchor: multiple Findings can reference the same IOC,
    and the correlation engine uses shared IOCs to link otherwise unrelated findings.
    """

    value: str = Field(..., description="The raw IOC value (IP, hash, domain, etc.)")
    ioc_type: IndicatorType = Field(..., description="STIX-aligned type")
    status: IndicatorStatus = Field(default=IndicatorStatus.ACTIVE)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    source: str = Field(default="unknown")
    tags: list[str] = Field(default_factory=list)
    tlp: str = Field(default="WHITE", description="Traffic Light Protocol label")
    first_seen: datetime = Field(default_factory=_utcnow)
    last_seen: datetime = Field(default_factory=_utcnow)
    expires_at: datetime | None = Field(default=None)
    description: str = Field(default="")
    metadata: dict[str, Any] = Field(default_factory=dict)
    related_finding_ids: list[str] = Field(default_factory=list)

    @field_validator("value")
    @classmethod
    def value_must_not_be_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Indicator value cannot be empty")
        return v.strip().lower()

    def whitelist(self, reason: str = "") -> None:
        """
        Mark this indicator as whitelisted.
        Whitelisted IOCs are excluded from all detection outputs.
        """
        self.status = IndicatorStatus.WHITELISTED
        self.metadata["whitelist_reason"] = reason
        self.touch()
        self.raise_event(
            IndicatorWhitelistedEvent(
                aggregate_id=self.id,
                payload={"value": self.value, "reason": reason},
            )
        )

    def revoke(self) -> None:
        """Revoke an IOC (e.g., false positive confirmed)."""
        self.status = IndicatorStatus.REVOKED
        self.touch()

    def refresh_seen(self) -> None:
        """Update last_seen to now — called when re-observed in a new finding."""
        self.last_seen = _utcnow()
        self.touch()

    def is_active(self) -> bool:
        """Check if the indicator is active and not expired."""
        if self.status != IndicatorStatus.ACTIVE:
            return False
        if self.expires_at and datetime.now(tz=timezone.utc) > self.expires_at:
            self.status = IndicatorStatus.EXPIRED
            return False
        return True

    def is_whitelisted(self) -> bool:
        return self.status == IndicatorStatus.WHITELISTED

    def link_finding(self, finding_id: str) -> None:
        """Associate this IOC with a new finding."""
        if finding_id not in self.related_finding_ids:
            self.related_finding_ids.append(finding_id)
            self.touch()

    @property
    def sighting_count(self) -> int:
        """Number of findings that reference this indicator."""
        return len(self.related_finding_ids)

    def __str__(self) -> str:
        return f"[{self.ioc_type.value}] {self.value}"
