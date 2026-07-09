"""Observability — structlog, Prometheus metrics, OpenTelemetry tracing, health, audit.

Responsibility
--------------
Cross-cutting observability adapters implementing MetricsPort, TracerPort,
AuditPort and HealthCheckPort. Core depends only on ports.
"""

from __future__ import annotations

from typing import Any

import structlog
from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import ConsoleSpanExporter, SimpleSpanProcessor
from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest

from threat_hunting.core.application.ports import (
    AuditPort,
    HealthCheckPort,
    MetricsPort,
    StorageBackendPort,
    TracerPort,
)
from threat_hunting.core.domain.enums import HealthState
from threat_hunting.core.domain.events import AuditRecorded, DomainEvent
from threat_hunting.core.domain.value_objects import HealthStatus, utc_now

logger = structlog.get_logger(__name__)


def configure_logging(*, json_logs: bool = False, level: str = "INFO") -> None:
    """Configure structlog for the platform."""
    import logging

    logging.basicConfig(level=getattr(logging, level.upper(), logging.INFO), format="%(message)s")
    shared: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]
    if json_logs:
        renderer: Any = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer()

    structlog.configure(
        processors=[*shared, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level.upper(), logging.INFO)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=False,
    )


class PrometheusMetrics(MetricsPort):
    """Prometheus client metrics adapter."""

    def __init__(self, registry: CollectorRegistry | None = None) -> None:
        self.registry = registry or CollectorRegistry()
        self._counters: dict[str, Counter] = {}
        self._histograms: dict[str, Histogram] = {}
        self._gauges: dict[str, Gauge] = {}

    def _counter(self, name: str, labels: list[str]) -> Counter:
        if name not in self._counters:
            self._counters[name] = Counter(
                name, f"threat_hunting {name}", labelnames=labels, registry=self.registry
            )
        return self._counters[name]

    def _histogram(self, name: str, labels: list[str]) -> Histogram:
        if name not in self._histograms:
            self._histograms[name] = Histogram(
                name, f"threat_hunting {name}", labelnames=labels, registry=self.registry
            )
        return self._histograms[name]

    def _gauge(self, name: str, labels: list[str]) -> Gauge:
        if name not in self._gauges:
            self._gauges[name] = Gauge(
                name, f"threat_hunting {name}", labelnames=labels, registry=self.registry
            )
        return self._gauges[name]

    def incr(self, name: str, *, value: float = 1.0, labels: dict[str, str] | None = None) -> None:
        labels = labels or {}
        c = self._counter(name, sorted(labels.keys()))
        if labels:
            c.labels(**labels).inc(value)
        else:
            c.inc(value)

    def observe(self, name: str, value: float, *, labels: dict[str, str] | None = None) -> None:
        labels = labels or {}
        h = self._histogram(name, sorted(labels.keys()))
        if labels:
            h.labels(**labels).observe(value)
        else:
            h.observe(value)

    def gauge(self, name: str, value: float, *, labels: dict[str, str] | None = None) -> None:
        labels = labels or {}
        g = self._gauge(name, sorted(labels.keys()))
        if labels:
            g.labels(**labels).set(value)
        else:
            g.set(value)

    def export(self) -> bytes:
        return generate_latest(self.registry)


class OpenTelemetryTracer(TracerPort):
    """OpenTelemetry tracer adapter."""

    def __init__(self, *, service_name: str = "threat-hunting", console: bool = False) -> None:
        resource = Resource.create({"service.name": service_name})
        provider = TracerProvider(resource=resource)
        if console:
            provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))
        trace.set_tracer_provider(provider)
        self._tracer = trace.get_tracer("threat_hunting")

    def start_span(self, name: str, **attrs: Any) -> Any:
        span = self._tracer.start_as_current_span(name)
        # Return context manager; caller uses `with`
        return _SpanContext(span, attrs)


class _SpanContext:
    def __init__(self, span_cm: Any, attrs: dict[str, Any]) -> None:
        self._cm = span_cm
        self._attrs = attrs
        self._span: Any = None

    def __enter__(self) -> Any:
        self._span = self._cm.__enter__()
        for k, v in self._attrs.items():
            if v is not None:
                self._span.set_attribute(k, str(v))
        return self._span

    def __exit__(self, *exc: Any) -> Any:
        return self._cm.__exit__(*exc)


class StructlogAudit(AuditPort):
    """Audit trail via structured logs + optional event bus echo."""

    def __init__(self, event_bus: Any | None = None) -> None:
        self._event_bus = event_bus
        self.records: list[dict[str, Any]] = []

    async def record(
        self, action: str, *, actor: str = "system", details: dict[str, Any] | None = None
    ) -> None:
        entry = {
            "action": action,
            "actor": actor,
            "details": details or {},
            "at": utc_now().isoformat(),
        }
        self.records.append(entry)
        logger.info("audit.recorded", **entry)
        if self._event_bus is not None:
            await self._event_bus.publish(
                AuditRecorded(aggregate_id=action, payload=entry)
            )


class PlatformHealthCheck(HealthCheckPort):
    """Aggregate health checks across storage and registered callables."""

    def __init__(self) -> None:
        self._checks: list[Any] = []

    def register(self, check: Any) -> None:
        """Register an async callable returning HealthStatus."""
        self._checks.append(check)

    def register_storage(self, storage: StorageBackendPort) -> None:
        self._checks.append(storage.health)

    async def check_all(self) -> list[HealthStatus]:
        results: list[HealthStatus] = []
        for check in self._checks:
            try:
                status = await check()
                results.append(status)
            except Exception as exc:
                results.append(
                    HealthStatus(
                        component="unknown",
                        state=HealthState.UNHEALTHY.value,
                        message=str(exc),
                        checked_at=utc_now(),
                    )
                )
        if not results:
            results.append(
                HealthStatus(
                    component="platform",
                    state=HealthState.HEALTHY.value,
                    message="no checks registered",
                    checked_at=utc_now(),
                )
            )
        return results

    async def overall(self) -> HealthState:
        statuses = await self.check_all()
        states = {s.state for s in statuses}
        if HealthState.UNHEALTHY.value in states:
            return HealthState.UNHEALTHY
        if HealthState.DEGRADED.value in states:
            return HealthState.DEGRADED
        return HealthState.HEALTHY


class LoggingEventHandler:
    """Wildcard event handler that logs all domain events."""

    async def handle(self, event: DomainEvent) -> None:
        logger.info(
            "domain.event",
            event_type=event.event_type,
            aggregate_id=event.aggregate_id,
            payload_keys=list(event.payload.keys()),
        )


__all__ = [
    "configure_logging",
    "PrometheusMetrics",
    "OpenTelemetryTracer",
    "StructlogAudit",
    "PlatformHealthCheck",
    "LoggingEventHandler",
]
