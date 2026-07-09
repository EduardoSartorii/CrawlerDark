"""Observability: structured logging, metrics, tracing and health checks.

All four degrade gracefully when their optional backend is absent (structlog,
prometheus_client, opentelemetry), so the platform is always observable to some
degree and never fails to import in a minimal environment.
"""

from threat_hunting.infrastructure.observability.logging import configure_logging, get_logger
from threat_hunting.infrastructure.observability.metrics import Metrics
from threat_hunting.infrastructure.observability.tracing import Tracer
from threat_hunting.infrastructure.observability.health import HealthCheck, HealthReport

__all__ = [
    "configure_logging",
    "get_logger",
    "Metrics",
    "Tracer",
    "HealthCheck",
    "HealthReport",
]
