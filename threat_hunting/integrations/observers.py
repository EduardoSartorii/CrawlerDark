"""Observer adapters subscribed to domain events."""

from __future__ import annotations

from threat_hunting.core.events import DomainEvent


class HighScoreObserver:
    """Simple observer for high-score finding notifications."""

    def __init__(self) -> None:
        self.events: list[DomainEvent] = []

    def __call__(self, event: DomainEvent) -> None:
        self.events.append(event)
