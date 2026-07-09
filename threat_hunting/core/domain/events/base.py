"""
DomainEvent Base
================

All domain events inherit from this class.
Domain events represent facts — something that has already happened.
They are published on the IEventBus and consumed by domain event handlers.

Architecture:
    - Events are immutable after creation.
    - Events carry enough data for handlers to act without additional queries.
    - Events are versioned to support schema evolution.
    - The event_id uniquely identifies each event occurrence (idempotency).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


class DomainEvent(BaseModel):
    """Immutable base class for all domain events."""

    model_config = {"frozen": True}

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str
    aggregate_id: str
    aggregate_type: str
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    version: int = 1
    metadata: dict[str, Any] = Field(default_factory=dict)

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"event_id={self.event_id!r}, "
            f"aggregate_id={self.aggregate_id!r}, "
            f"occurred_at={self.occurred_at.isoformat()!r})"
        )
