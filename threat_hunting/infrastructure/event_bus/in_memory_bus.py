"""
InMemoryEventBus
================

In-process, async event bus implementation.
Suitable for single-process deployments (CLI, scheduler).

For distributed deployments, replace with a Redis Pub/Sub or Kafka-backed
implementation. Both use the same IEventBus interface — no Core changes needed.

Design:
    - Handlers are registered per event_type string.
    - All handlers for an event are called concurrently (asyncio.gather).
    - Handler exceptions are caught and logged — they do not block other handlers.
    - The bus is thread-safe via asyncio event loop (single-threaded assumption).
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from typing import TYPE_CHECKING

import structlog

from threat_hunting.core.domain.ports.event_bus import IEventBus, EventHandler

if TYPE_CHECKING:
    from threat_hunting.core.domain.events.base import DomainEvent

logger = structlog.get_logger(__name__)


class InMemoryEventBus(IEventBus):
    """
    In-memory async event bus.

    All event handlers are called asynchronously and concurrently.
    """

    def __init__(self) -> None:
        self._handlers: dict[str, list[EventHandler]] = defaultdict(list)

    async def publish(self, event: "DomainEvent") -> None:
        """
        Publish an event to all registered handlers.

        Args:
            event: The domain event to publish.
        """
        handlers = self._handlers.get(event.event_type, [])
        wildcard_handlers = self._handlers.get("*", [])
        all_handlers = handlers + wildcard_handlers

        if not all_handlers:
            return

        logger.debug(
            "event_published",
            event_type=event.event_type,
            aggregate_id=event.aggregate_id,
            handler_count=len(all_handlers),
        )

        results = await asyncio.gather(
            *[self._safe_call(h, event) for h in all_handlers],
            return_exceptions=True,
        )
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(
                    "event_handler_error",
                    event_type=event.event_type,
                    handler_index=i,
                    error=str(result),
                )

    async def _safe_call(self, handler: EventHandler, event: "DomainEvent") -> None:
        """Call a handler, catching and logging any exception."""
        try:
            await handler(event)
        except Exception as exc:
            raise exc

    def subscribe(self, event_type: str, handler: EventHandler) -> None:
        """Register a handler for the given event type."""
        if handler not in self._handlers[event_type]:
            self._handlers[event_type].append(handler)
            logger.debug("handler_registered", event_type=event_type, handler=handler.__name__)

    def unsubscribe(self, event_type: str, handler: EventHandler) -> None:
        """Remove a registered handler."""
        try:
            self._handlers[event_type].remove(handler)
        except ValueError:
            pass

    def handler_count(self, event_type: str) -> int:
        """Return the number of handlers registered for an event type."""
        return len(self._handlers.get(event_type, []))
