"""Event subscribers (Observer Pattern).

Responsibility
--------------
React to domain events without the producers knowing about them:

* :class:`AutoExportSubscriber` -- on ``HighSeverityFindingDetected`` it pushes
  the finding to a configured exporter (e.g. MISP), implementing the
  "score > threshold ⇒ auto-export" requirement.
* :class:`AuditLogSubscriber` -- writes a structured audit line for every event
  it is subscribed to, satisfying the auditing requirement.
"""

from __future__ import annotations

from threat_hunting.core.application.ports.exporter import Exporter
from threat_hunting.core.domain.events.base import DomainEvent
from threat_hunting.core.domain.events.finding_events import HighSeverityFindingDetected


class AutoExportSubscriber:
    """Auto-exports high-severity findings via a target exporter."""

    def __init__(self, exporter: Exporter) -> None:
        self._exporter = exporter
        self.exported: int = 0

    def __call__(self, event: DomainEvent) -> None:
        """Export the finding carried by a high-severity event."""
        if isinstance(event, HighSeverityFindingDetected):
            self._exporter.export([event.finding])
            self.exported += 1


class AuditLogSubscriber:
    """Writes a structured audit record for each received event."""

    def __init__(self, logger: object | None = None) -> None:
        # Lazy default so structlog stays optional at import time.
        if logger is None:
            from threat_hunting.infrastructure.observability.logging import get_logger

            logger = get_logger("audit")
        self._logger = logger
        self.records: list[str] = []

    def __call__(self, event: DomainEvent) -> None:
        """Emit an audit log line for the event."""
        self.records.append(event.name.value)
        info = getattr(self._logger, "info", None)
        if callable(info):
            # Note: 'event' is structlog's positional message arg, so the event
            # name is passed under a distinct key to avoid a kwarg collision.
            info(
                "audit_event",
                event_type=event.name.value,
                run_id=getattr(event, "run_id", None),
                occurred_at=event.occurred_at.isoformat(),
            )
