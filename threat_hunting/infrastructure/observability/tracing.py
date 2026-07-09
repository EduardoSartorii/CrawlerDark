"""Setup opcional de OpenTelemetry (OTLP gRPC exporter)."""

from __future__ import annotations


def configure_tracing(*, enabled: bool, endpoint: str, service_name: str) -> None:
    """Configura tracing global. Silencioso quando desabilitado."""
    if not enabled:
        return
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        try:
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
        except ImportError:  # pragma: no cover — dependência opcional
            return

        resource = Resource.create({"service.name": service_name})
        provider = TracerProvider(resource=resource)
        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
        trace.set_tracer_provider(provider)
    except Exception:  # noqa: BLE001
        return
