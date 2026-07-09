"""OpenTelemetry tracing setup."""

from __future__ import annotations

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider


def configure_tracing(service_name: str = "threat-hunting-collection") -> None:
    """Configure an OpenTelemetry tracer provider."""

    provider = TracerProvider(resource=Resource.create({"service.name": service_name}))
    trace.set_tracer_provider(provider)
