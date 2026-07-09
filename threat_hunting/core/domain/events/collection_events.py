"""Collection lifecycle domain events."""

from __future__ import annotations

from pydantic import Field

from threat_hunting.core.domain.events.base import DomainEvent


class CollectionStarted(DomainEvent):
    """Emitted when a connector begins a collection run."""

    event_type: str = "collection.started"
    aggregate_type: str = "ConnectorConfig"
    connector: str
    source: str


class CollectionCompleted(DomainEvent):
    """Emitted when a connector successfully finishes a collection run."""

    event_type: str = "collection.completed"
    aggregate_type: str = "ConnectorConfig"
    connector: str
    source: str
    findings_count: int = 0
    duration_seconds: float = 0.0


class CollectionFailed(DomainEvent):
    """Emitted when a connector run encounters a fatal error."""

    event_type: str = "collection.failed"
    aggregate_type: str = "ConnectorConfig"
    connector: str
    source: str
    error: str
    is_retryable: bool = True
