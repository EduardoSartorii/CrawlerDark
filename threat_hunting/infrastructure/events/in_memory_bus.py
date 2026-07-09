"""In-memory synchronous event bus.

Responsibility
--------------
Implement :class:`EventBusPort`. Producers (the pipeline) publish domain events;
subscribers registered per event type receive them synchronously. Being
in-process and synchronous keeps ordering deterministic and testing simple; the
same port could later be implemented over Redis/Kafka without touching
producers or subscribers.

Business rules
--------------
* A failing subscriber must never break the pipeline or other subscribers; its
  error is isolated and logged by the caller's logging subscriber.
"""

from __future__ import annotations

from collections import defaultdict

from threat_hunting.core.application.ports.event_bus import EventBusPort, EventHandler
from threat_hunting.core.domain.events import DomainEvent


class InMemoryEventBus(EventBusPort):
    """Synchronous, in-process publish/subscribe bus."""

    def __init__(self) -> None:
        self._handlers: dict[type[DomainEvent], list[EventHandler]] = defaultdict(list)

    def subscribe(
        self, event_type: type[DomainEvent], handler: EventHandler
    ) -> None:
        self._handlers[event_type].append(handler)

    def publish(self, event: DomainEvent) -> None:
        for event_type, handlers in self._handlers.items():
            if isinstance(event, event_type):
                for handler in handlers:
                    try:
                        handler(event)
                    except Exception:  # noqa: BLE001 - isolate subscriber failures
                        continue
