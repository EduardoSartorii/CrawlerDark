"""
IEventBus Port
==============

Contract for the domain event bus.
The event bus decouples event producers (domain aggregates, pipeline stages)
from event consumers (handlers, notification services, metrics collectors).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Callable, Coroutine

if TYPE_CHECKING:
    from threat_hunting.core.domain.events.base import DomainEvent

# Type alias for async event handler callables
EventHandler = Callable[["DomainEvent"], Coroutine[Any, Any, None]]


class IEventBus(ABC):
    """Abstract event bus port."""

    @abstractmethod
    async def publish(self, event: "DomainEvent") -> None:
        """Publish an event to all registered handlers.

        Args:
            event: The domain event to publish.
        """

    @abstractmethod
    def subscribe(self, event_type: str, handler: EventHandler) -> None:
        """Register a handler for a specific event type.

        Args:
            event_type: The event_type string (e.g. 'finding.scored').
            handler: Async callable that receives the event.
        """

    @abstractmethod
    def unsubscribe(self, event_type: str, handler: EventHandler) -> None:
        """Remove a previously registered handler."""
