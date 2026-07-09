"""In-process event bus implementing Observer pattern."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Awaitable, Callable
from typing import Any

import structlog

from threat_hunting.core.contracts.services import IEventBus
from threat_hunting.core.domain.events import DomainEvent

logger = structlog.get_logger(__name__)

EventHandler = Callable[[DomainEvent], Awaitable[None]]


class InProcessEventBus(IEventBus):
    """Simple async event bus for domain events."""

    def __init__(self) -> None:
        self._handlers: dict[str, list[EventHandler]] = defaultdict(list)

    def subscribe(self, event_type: str, handler: EventHandler) -> None:
        """Register handler for event type."""
        self._handlers[event_type].append(handler)
        logger.debug("eventbus.subscribed", event_type=event_type)

    async def publish(self, event: DomainEvent) -> None:
        """Publish event to all registered handlers."""
        handlers = self._handlers.get(event.event_type, [])
        handlers.extend(self._handlers.get("*", []))
        for handler in handlers:
            try:
                await handler(event)
            except Exception as exc:
                logger.error("eventbus.handler.error", event=event.event_type, error=str(exc))
