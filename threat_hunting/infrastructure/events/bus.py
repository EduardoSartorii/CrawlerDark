"""In-memory observer event bus."""

from __future__ import annotations

from collections.abc import Callable

from threat_hunting.core.domain.events import DomainEvent


class InMemoryEventBus:
    """Publish events to registered observers in-process."""

    def __init__(self) -> None:
        self._subscribers: dict[str, list[Callable[[DomainEvent], None]]] = {}
        self.published: list[DomainEvent] = []

    def subscribe(self, event_name: str, handler: Callable[[DomainEvent], None]) -> None:
        """Register an observer for an event name."""

        self._subscribers.setdefault(event_name, []).append(handler)

    def publish(self, event: DomainEvent) -> None:
        """Publish an event to matching observers."""

        self.published.append(event)
        for handler in self._subscribers.get(event.name, []):
            handler(event)
