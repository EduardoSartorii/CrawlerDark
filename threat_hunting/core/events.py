"""Domain events and in-memory event bus implementation."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from threat_hunting.core.contracts import EventBusPort, EventHandler


@dataclass(slots=True)
class DomainEvent:
    """Base event used across pipeline and commands."""

    event_type: str
    payload: dict[str, Any] = field(default_factory=dict)
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))


class InMemoryEventBus(EventBusPort):
    """Simple observer implementation for decoupled event publishing."""

    def __init__(self) -> None:
        self._handlers: dict[type[DomainEvent], list[EventHandler]] = defaultdict(list)

    def publish(self, event: DomainEvent) -> None:
        """Publish an event to all compatible handlers."""
        for event_type, handlers in self._handlers.items():
            if isinstance(event, event_type):
                for handler in handlers:
                    handler(event)

    def subscribe(self, event_type: type[DomainEvent], handler: EventHandler) -> None:
        """Subscribe a handler to an event type."""
        self._handlers[event_type].append(handler)


@dataclass(slots=True)
class PipelineStageCompleted(DomainEvent):
    """Emitted whenever a pipeline stage completes successfully."""


@dataclass(slots=True)
class PipelineStageFailed(DomainEvent):
    """Emitted whenever a pipeline stage fails."""


@dataclass(slots=True)
class FindingsPersisted(DomainEvent):
    """Emitted after findings are persisted."""


@dataclass(slots=True)
class FindingsExported(DomainEvent):
    """Emitted after findings are exported."""
