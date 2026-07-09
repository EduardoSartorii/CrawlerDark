"""Domain events emitted by the hunting pipeline.

Events make the platform event driven without forcing the domain layer to know
whether observers are logs, metrics, audit records, exporters or future Django
notifications.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class DomainEvent(BaseModel):
    """Base immutable event envelope."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    name: str
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    payload: dict[str, Any] = Field(default_factory=dict)


class FindingCollected(DomainEvent):
    """Raised when a connector emits a normalized finding."""

    name: str = "finding.collected"


class FindingPersisted(DomainEvent):
    """Raised after a finding is committed to storage."""

    name: str = "finding.persisted"


class FindingExported(DomainEvent):
    """Raised after a finding is exported to an integration."""

    name: str = "finding.exported"


class ConnectorHealthChanged(DomainEvent):
    """Raised when a connector health check changes status."""

    name: str = "connector.health_changed"
