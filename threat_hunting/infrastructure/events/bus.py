"""InMemoryEventBus.

Responsibility
--------------
A synchronous, in-process publish/subscribe bus implementing the core
``EventBus`` port. Handlers are invoked in registration order; a failing handler
is isolated (logged to stats) so one bad subscriber cannot break publishing.

A future distributed bus (Redis/Kafka) would implement the same port and drop
in without changing publishers or subscribers.
"""

from __future__ import annotations

from collections import defaultdict

from threat_hunting.core.application.ports.event_bus import EventHandler
from threat_hunting.core.domain.enums import EventName
from threat_hunting.core.domain.events.base import DomainEvent


class InMemoryEventBus:
    """Synchronous in-memory event bus."""

    def __init__(self) -> None:
        self._handlers: dict[EventName, list[EventHandler]] = defaultdict(list)
        self.errors: list[str] = []

    def subscribe(self, event_name: EventName, handler: EventHandler) -> None:
        """Register ``handler`` for ``event_name``."""
        self._handlers[event_name].append(handler)

    def publish(self, event: DomainEvent) -> None:
        """Deliver ``event`` to every subscribed handler, isolating failures."""
        for handler in list(self._handlers.get(event.name, [])):
            try:
                handler(event)
            except Exception as exc:  # a subscriber must not break publishing
                self.errors.append(f"{event.name.value}: {exc}")
