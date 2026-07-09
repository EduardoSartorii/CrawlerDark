"""Observability — logging, metrics, tracing, and health checks."""

from __future__ import annotations

import logging
import time
from typing import Any

import structlog
from prometheus_client import Counter, Gauge, Histogram, start_http_server

FINDINGS_TOTAL = Counter("th_findings_total", "Total findings processed", ["connector", "severity"])
CONNECTOR_DURATION = Histogram("th_connector_duration_seconds", "Connector execution duration", ["connector"])
PIPELINE_STAGE_DURATION = Histogram("th_pipeline_stage_seconds", "Pipeline stage duration", ["stage"])
ACTIVE_CONNECTORS = Gauge("th_active_connectors", "Currently running connectors")
EXPORTS_TOTAL = Counter("th_exports_total", "Total exports", ["format"])


def setup_logging(debug: bool = False) -> None:
    """Configure structlog for structured logging."""
    log_level = logging.DEBUG if debug else logging.INFO
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
    )


def setup_metrics(port: int = 9090) -> None:
    """Start Prometheus metrics HTTP server."""
    try:
        start_http_server(port)
    except OSError:
        pass


def setup_tracing(service_name: str = "threat-hunting") -> Any:
    """Configure OpenTelemetry tracing."""
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.resources import Resource

        provider = TracerProvider(resource=Resource.create({"service.name": service_name}))
        trace.set_tracer_provider(provider)
        return trace.get_tracer(service_name)
    except ImportError:
        return None


class HealthChecker:
    """Aggregated health check for platform components."""

    def __init__(self) -> None:
        self._checks: dict[str, Any] = {}

    def register(self, name: str, check_fn: Any) -> None:
        self._checks[name] = check_fn

    async def check_all(self) -> dict[str, str]:
        results = {}
        for name, fn in self._checks.items():
            try:
                status = await fn()
                results[name] = status.value if hasattr(status, "value") else str(status)
            except Exception as exc:
                results[name] = f"unhealthy: {exc}"
        return results


class MetricsObserver:
    """Observer that records metrics from domain events."""

    async def on_connector_executed(self, event: Any) -> None:
        CONNECTOR_DURATION.labels(connector=event.connector).observe(event.duration_seconds)
        FINDINGS_TOTAL.labels(connector=event.connector, severity="all").inc(event.findings_count)

    async def on_export_triggered(self, event: Any) -> None:
        EXPORTS_TOTAL.labels(format=event.export_format).inc()

    async def on_pipeline_stage(self, event: Any) -> None:
        PIPELINE_STAGE_DURATION.labels(stage=event.stage).observe(event.duration_seconds)
