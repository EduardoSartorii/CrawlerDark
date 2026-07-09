"""OpenTelemetry setup for distributed tracing."""

from __future__ import annotations

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

_TRACING_CONFIGURED = False


def configure_tracing(service_name: str = "threat-hunting-platform", endpoint: str | None = None) -> None:
    """Configure OpenTelemetry tracer provider."""
    global _TRACING_CONFIGURED
    if _TRACING_CONFIGURED:
        return
    provider = TracerProvider(resource=Resource.create({"service.name": service_name}))
    if endpoint:
        exporter = OTLPSpanExporter(endpoint=endpoint)
        provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)
    _TRACING_CONFIGURED = True
