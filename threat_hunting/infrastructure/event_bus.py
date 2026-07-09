"""In-process event bus implementing observer pattern."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable

from threat_hunting.core.contracts import AuditPort, EventBusPort, EventHandler
from threat_hunting.core.events import DomainEvent


class InMemoryEventBus(EventBusPort):
    """Synchronous in-memory event dispatcher."""

    def __init__(self, audit: AuditPort) -> None:
        self._audit = audit
        self._listeners: dict[str, list[EventHandler]] = defaultdict(list)

    def publish(self, event: DomainEvent) -> None:
        self._audit.log("event_published", {"name": event.name, "event_id": str(event.event_id)})
        for callback in self._listeners[event.name]:
            callback(event)

    def subscribe(self, event_name: str, callback: EventHandler) -> None:
        self._listeners[event_name].append(callback)


class InMemoryAuditLog(AuditPort):
    """Simple audit sink suitable for tests and local operation."""

    def __init__(self) -> None:
        self.events: list[dict[str, object]] = []

    def log(self, action: str, metadata: dict[str, object]) -> None:
        self.events.append({"action": action, **metadata})
