"""Health checks, Prometheus metrics, and OpenTelemetry tracing."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from prometheus_client import Counter, Histogram


FINDINGS_TOTAL = Counter("threat_hunting_findings_total", "Total findings collected", ["connector", "severity"])
PIPELINE_SECONDS = Histogram("threat_hunting_pipeline_seconds", "Pipeline execution duration", ["connector"])


def configure_tracing(service_name: str = "threat-hunting-collection") -> None:
    """Configure an OpenTelemetry tracer provider."""

    provider = TracerProvider()
    trace.set_tracer_provider(provider)


@contextmanager
def pipeline_span(connector_name: str) -> Iterator[None]:
    """Trace and measure a connector pipeline execution."""

    tracer = trace.get_tracer("threat_hunting.pipeline")
    with tracer.start_as_current_span("pipeline.run", attributes={"connector": connector_name}):
        with PIPELINE_SECONDS.labels(connector=connector_name).time():
            yield


def record_finding(connector_name: str, severity: str) -> None:
    """Increment finding metric."""

    FINDINGS_TOTAL.labels(connector=connector_name, severity=severity).inc()
