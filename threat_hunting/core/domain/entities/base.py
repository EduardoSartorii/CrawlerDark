"""
Base Domain Entity.

Architectural basis for all domain entities in the CTI platform.
Entities are distinguished by identity (UUID), not by attribute values.

Design Patterns:
    - Entity pattern (DDD): identity-based equality
    - Rich domain model: behavior lives in the entity
    - Domain events: entities collect events; application layer dispatches them

All entities must:
    - Have a stable UUID identity
    - Track creation/modification timestamps
    - Support domain event collection
    - Never depend on infrastructure
"""

from __future__ import annotations

import uuid
from abc import ABC
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


def _utcnow() -> datetime:
    """Return current UTC datetime without tzinfo for DB compatibility."""
    return datetime.now(tz=timezone.utc)


def _new_uuid() -> str:
    """Generate a new UUID4 string."""
    return str(uuid.uuid4())


class DomainEvent(BaseModel):
    """
    Base class for all domain events.

    Domain events represent something that happened in the domain.
    They are immutable records of facts.
    """

    model_config = ConfigDict(frozen=True)

    event_id: str = Field(default_factory=_new_uuid)
    event_type: str
    aggregate_id: str
    occurred_at: datetime = Field(default_factory=_utcnow)
    payload: dict[str, Any] = Field(default_factory=dict)


class BaseEntity(BaseModel, ABC):
    """
    Abstract base for all domain entities.

    Subclasses define their own fields and domain behavior.
    Infrastructure concerns (persistence, serialization) must NOT appear here.
    """

    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        validate_assignment=True,
    )

    id: str = Field(default_factory=_new_uuid, description="Stable UUID identity")
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)

    def model_post_init(self, __context: Any) -> None:
        """Initialize instance-level private state after Pydantic construction."""
        object.__setattr__(self, "_domain_events_store", [])

    def raise_event(self, event: DomainEvent) -> None:
        """Accumulate a domain event for later dispatch."""
        # Access via object.__getattribute__ to bypass Pydantic field handling
        try:
            store = object.__getattribute__(self, "_domain_events_store")
        except AttributeError:
            store = []
            object.__setattr__(self, "_domain_events_store", store)
        store.append(event)

    def pull_events(self) -> list[DomainEvent]:
        """Pull and clear accumulated domain events."""
        try:
            store = object.__getattribute__(self, "_domain_events_store")
        except AttributeError:
            return []
        events = list(store)
        store.clear()
        return events

    def touch(self) -> None:
        """Update the modification timestamp."""
        self.updated_at = _utcnow()

    def __eq__(self, other: object) -> bool:
        """Entity equality is based solely on identity."""
        if not isinstance(other, BaseEntity):
            return NotImplemented
        return self.id == other.id

    def __hash__(self) -> int:
        return hash(self.id)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(id={self.id!r})"
