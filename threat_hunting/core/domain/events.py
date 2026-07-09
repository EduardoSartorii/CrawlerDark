"""Domain events used by the observer/event-driven architecture."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from threat_hunting.core.domain.entities import Finding, utc_now


class DomainEvent(BaseModel):
    """Base event emitted by use cases without knowing event bus details."""

    id: UUID = Field(default_factory=uuid4)
    occurred_at: datetime = Field(default_factory=utc_now)
    name: str
    payload: dict[str, Any] = Field(default_factory=dict)


class FindingCollected(DomainEvent):
    """Event emitted after a finding is persisted."""

    name: str = "finding.collected"

    @classmethod
    def from_finding(cls, finding: Finding) -> "FindingCollected":
        """Create a lightweight event payload safe for logs and queues."""

        return cls(
            payload={
                "finding_id": str(finding.id),
                "source": finding.source,
                "connector": finding.connector,
                "category": finding.category,
                "severity": finding.severity,
                "score": finding.score,
            }
        )
