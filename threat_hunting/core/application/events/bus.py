"""In-memory event bus.

Implementação canônica do ``EventBusPort``. Handlers são coroutines; falhas
individuais não interrompem os demais handlers do mesmo evento (isolamento).
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from collections.abc import Awaitable, Callable

from ...domain.events import DomainEvent

Handler = Callable[[DomainEvent], Awaitable[None]]


class InMemoryEventBus:
    """Barramento de eventos in-memory, seguro para uso assíncrono."""

    def __init__(self) -> None:
        self._handlers: dict[type[DomainEvent], list[Handler]] = defaultdict(list)
        self._lock = asyncio.Lock()

    def subscribe(self, event_type: type[DomainEvent], handler: Handler) -> None:
        self._handlers[event_type].append(handler)

    async def publish(self, event: DomainEvent) -> None:
        async with self._lock:
            handlers = list(self._handlers.get(type(event), []))
            handlers.extend(self._handlers.get(DomainEvent, []))
        if not handlers:
            return
        results = await asyncio.gather(
            *(self._safe_call(h, event) for h in handlers), return_exceptions=True
        )
        # Errors are swallowed by design; a wiring layer plugs an observer that
        # logs them via structlog. Not raising keeps the bus fire-and-forget.
        for _ in results:
            pass

    @staticmethod
    async def _safe_call(handler: Handler, event: DomainEvent) -> None:
        try:
            await handler(event)
        except Exception:  # noqa: BLE001 — isolamento intencional
            pass
