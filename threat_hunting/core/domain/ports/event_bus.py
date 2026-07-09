"""EventBusPort — pub/sub in-memory de eventos de domínio."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Protocol, runtime_checkable

from ..events import DomainEvent

Handler = Callable[[DomainEvent], Awaitable[None]]


@runtime_checkable
class EventBusPort(Protocol):
    def subscribe(self, event_type: type[DomainEvent], handler: Handler) -> None: ...

    async def publish(self, event: DomainEvent) -> None: ...
