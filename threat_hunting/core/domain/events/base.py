"""Base domain event.

Responsibility
--------------
Provide the common shape of every domain event: a stable name (from the
:class:`EventName` enum), an occurrence timestamp and a correlation ``run_id``
so all events of a single pipeline run can be traced together.
"""

from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field

from threat_hunting.core.domain.enums import EventName


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class DomainEvent(BaseModel):
    """Immutable fact describing something that happened in the domain."""

    model_config = ConfigDict(frozen=True)

    name: EventName
    occurred_at: datetime = Field(default_factory=_utcnow)
    run_id: str | None = None
