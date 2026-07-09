"""Built-in event subscribers (Observer consumers).

Responsibility
--------------
React to domain events without the pipeline knowing they exist:

* :class:`AuditLogSubscriber` — emits a structured audit log line per event
  (execution, findings, score, correlation, export, ...).
* :class:`MetricsSubscriber` — increments Prometheus counters/histograms.

New reactions (alerting, webhooks, SIEM forwarding) are added simply by
subscribing another handler — the Open/Closed principle in action.
"""

from __future__ import annotations

from threat_hunting.core.application.ports.event_bus import EventBusPort
from threat_hunting.core.domain.events import (
    DomainEvent,
    FindingExported,
    FindingPersisted,
)
from threat_hunting.infrastructure.observability.logging import get_logger
from threat_hunting.infrastructure.observability.metrics import Metrics


class AuditLogSubscriber:
    """Writes a structured audit line for every domain event."""

    def __init__(self) -> None:
        self._log = get_logger("threat_hunting.audit")

    def register(self, bus: EventBusPort) -> None:
        """Subscribe to all domain events."""
        bus.subscribe(DomainEvent, self._on_event)

    def _on_event(self, event: DomainEvent) -> None:
        self._log.info(
            "domain_event",
            event=event.name,
            finding_id=event.finding.id,
            connector=event.finding.connector,
            score=event.finding.score,
            severity=event.finding.severity.value,
        )


class MetricsSubscriber:
    """Updates Prometheus metrics from domain events."""

    def __init__(self, metrics: Metrics) -> None:
        self._metrics = metrics

    def register(self, bus: EventBusPort) -> None:
        """Subscribe to the events that carry metric signal."""
        bus.subscribe(FindingPersisted, self._on_persisted)
        bus.subscribe(FindingExported, self._on_exported)

    def _on_persisted(self, event: DomainEvent) -> None:
        self._metrics.findings_total.labels(
            event.finding.connector, event.finding.severity.value
        ).inc()

    def _on_exported(self, event: DomainEvent) -> None:
        self._metrics.exports_total.labels("auto").inc()
