"""Event bus port (Observer pattern / Event-Driven Architecture).

Responsibility
--------------
Decouple *producers* of domain events (the pipeline) from *consumers* (audit
logging, metrics, automatic export). Producers publish; the bus dispatches to
subscribers registered for the event type.
"""

from __future__ import annotations

import abc
from collections.abc import Callable
from typing import TypeAlias

from threat_hunting.core.domain.events import DomainEvent

#: A subscriber is any callable that consumes a domain event.
EventHandler: TypeAlias = Callable[[DomainEvent], None]


class EventBusPort(abc.ABC):
    """Publish/subscribe contract for domain events."""

    @abc.abstractmethod
    def subscribe(self, event_type: type[DomainEvent], handler: EventHandler) -> None:
        """Register ``handler`` to receive events of ``event_type``."""

    @abc.abstractmethod
    def publish(self, event: DomainEvent) -> None:
        """Dispatch ``event`` to all matching subscribers."""
