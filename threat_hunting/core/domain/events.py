"""Domain events (Event-Driven Architecture).

Responsibility
--------------
Represent facts that have happened in the domain. Each pipeline milestone emits
one of these on the ``EventBus``. Subscribers (audit logging, metrics, automatic
MISP export) react without the pipeline knowing they exist — this is the Observer
pattern and the backbone of the platform's extensibility.

Business rules
--------------
* Events are immutable facts, named in the past tense.
* Events never carry infrastructure objects, only domain data, so any adapter
  can consume them.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from threat_hunting.core.domain.entities import Finding


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True, slots=True)
class DomainEvent:
    """Base class for all domain events."""

    finding: Finding
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    occurred_at: datetime = field(default_factory=_utcnow)

    @property
    def name(self) -> str:
        """Return the event type name (used as the bus topic)."""
        return type(self).__name__


@dataclass(frozen=True, slots=True)
class FindingCollected(DomainEvent):
    """A connector produced a candidate finding."""


@dataclass(frozen=True, slots=True)
class FindingDetected(DomainEvent):
    """The detection engine matched at least one rule."""


@dataclass(frozen=True, slots=True)
class FindingScored(DomainEvent):
    """The scoring engine assigned a score/severity."""


@dataclass(frozen=True, slots=True)
class FindingCorrelated(DomainEvent):
    """The correlation engine linked the finding to other intelligence."""


@dataclass(frozen=True, slots=True)
class FindingDeduplicated(DomainEvent):
    """The deduplication engine flagged the finding as a duplicate."""


@dataclass(frozen=True, slots=True)
class FindingEnriched(DomainEvent):
    """The enrichment engine added context to the finding."""


@dataclass(frozen=True, slots=True)
class FindingPersisted(DomainEvent):
    """The finding was stored through the Unit of Work."""


@dataclass(frozen=True, slots=True)
class FindingExported(DomainEvent):
    """The finding was exported by one or more exporters."""
