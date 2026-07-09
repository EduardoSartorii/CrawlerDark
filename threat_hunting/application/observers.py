"""Observer handlers for structured logs and metrics."""

from __future__ import annotations

from typing import Any

import structlog

from threat_hunting.core.events import DomainEvent
from threat_hunting.infrastructure.observability.metrics import HuntingMetrics

logger = structlog.get_logger(__name__)


class LoggingObserver:
    """Observer that logs every emitted event in structured format."""

    def __call__(self, event: DomainEvent) -> None:
        logger.info(
            "event_emitted",
            event_type=event.event_type,
            payload=event.payload,
            occurred_at=event.occurred_at.isoformat(),
        )


class MetricsObserver:
    """Observer that updates metrics based on event type."""

    def __init__(self, metrics: HuntingMetrics) -> None:
        self._metrics = metrics

    def __call__(self, event: DomainEvent) -> None:
        event_type = event.event_type
        self._metrics.events_total.labels(event_type=event_type).inc()
        findings_count = int(event.payload.get("findings_count", 0))
        if findings_count:
            self._metrics.findings_total.inc(findings_count)
        duration_ms = event.payload.get("duration_ms")
        if isinstance(duration_ms, (int, float)):
            self._metrics.stage_duration_ms.labels(stage=event.payload.get("stage", "unknown")).observe(duration_ms)
