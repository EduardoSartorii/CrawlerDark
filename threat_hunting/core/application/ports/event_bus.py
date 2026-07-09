"""Event bus port (Observer / Event-Driven).

Responsibility
--------------
Define the publish/subscribe contract used to decouple producers of domain
events from their consumers. Subscribers (metrics, audit, auto-export) register
handlers by event name; publishers simply publish. The concrete in-memory bus
lives in infrastructure.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol, runtime_checkable

from threat_hunting.core.domain.enums import EventName
from threat_hunting.core.domain.events.base import DomainEvent

# A handler reacts to a domain event. Kept as a simple callable for flexibility.
EventHandler = Callable[[DomainEvent], None]


@runtime_checkable
class EventBus(Protocol):
    """Publish/subscribe contract for domain events."""

    def subscribe(self, event_name: EventName, handler: EventHandler) -> None:
        """Register ``handler`` to be called when ``event_name`` is published."""
        ...

    def publish(self, event: DomainEvent) -> None:
        """Deliver ``event`` to every subscribed handler."""
        ...
