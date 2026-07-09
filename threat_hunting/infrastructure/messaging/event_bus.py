"""Event Bus — Observer Pattern.

Responsibility
--------------
Publish domain events to subscribed handlers. Decouples export, audit and
metrics from the pipeline.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Sequence

import structlog

from threat_hunting.core.application.ports import EventBusPort, EventHandler
from threat_hunting.core.domain.events import DomainEvent

logger = structlog.get_logger(__name__)


class InMemoryEventBus(EventBusPort):
    """Synchronous-async in-process event bus."""

    def __init__(self) -> None:
        self._handlers: dict[str, list[EventHandler]] = defaultdict(list)
        self._wildcard: list[EventHandler] = []
        self.history: list[DomainEvent] = []

    def subscribe(self, event_type: str, handler: EventHandler) -> None:
        if event_type == "*":
            self._wildcard.append(handler)
        else:
            self._handlers[event_type].append(handler)
        logger.debug("event_bus.subscribed", event_type=event_type)

    async def publish(self, event: DomainEvent) -> None:
        self.history.append(event)
        handlers = list(self._handlers.get(event.event_type, [])) + list(self._wildcard)
        for handler in handlers:
            try:
                await handler.handle(event)
            except Exception as exc:
                logger.exception(
                    "event_bus.handler_error",
                    event_type=event.event_type,
                    error=str(exc),
                )

    async def publish_many(self, events: Sequence[DomainEvent]) -> None:
        for event in events:
            await self.publish(event)


__all__ = ["InMemoryEventBus"]
