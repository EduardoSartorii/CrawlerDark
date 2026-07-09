"""In-process event bus implementing the observer pattern."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable

from threat_hunting.core.domain.events import DomainEvent


class InMemoryEventBus:
    """Simple synchronous event bus for CLI and tests.

    Production deployments can replace this adapter with Redis streams, Kafka,
    Celery, or another eventing backend without changing the application layer.
    """

    def __init__(self) -> None:
        self._handlers: dict[str, list[Callable[[DomainEvent], None]]] = defaultdict(list)

    def subscribe(self, event_name: str, handler: Callable[[DomainEvent], None]) -> None:
        """Register a handler for a named event."""

        self._handlers[event_name].append(handler)

    def publish(self, event: DomainEvent) -> None:
        """Publish an event to specific and wildcard subscribers."""

        for handler in [*self._handlers[event.name], *self._handlers["*"]]:
            handler(event)
