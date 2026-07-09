"""Prometheus metrics and OpenTelemetry tracing (both optional).

Responsibility
--------------
Expose platform telemetry. Prometheus counters/histograms track findings,
scores, durations and exports. OpenTelemetry tracing wraps pipeline stages when
the SDK is installed. Both dependencies are optional: when missing, the module
degrades to no-op shims so the platform runs anywhere.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

try:
    from prometheus_client import Counter, Histogram, start_http_server

    _PROM = True
except Exception:  # noqa: BLE001 - optional
    _PROM = False

try:
    from opentelemetry import trace

    _OTEL = True
except Exception:  # noqa: BLE001 - optional
    _OTEL = False


class _NoopMetric:
    """A metric that accepts any call and does nothing (fallback)."""

    def labels(self, *args: object, **kwargs: object) -> "_NoopMetric":
        return self

    def inc(self, amount: float = 1) -> None:
        return None

    def observe(self, amount: float) -> None:
        return None


class Metrics:
    """Facade over Prometheus metrics with a no-op fallback."""

    def __init__(self, *, enabled: bool = True) -> None:
        self.enabled = enabled and _PROM
        if self.enabled:
            self.findings_total = Counter(
                "th_findings_total", "Findings produced", ["connector", "severity"]
            )
            self.exports_total = Counter(
                "th_exports_total", "Findings exported", ["exporter"]
            )
            self.pipeline_duration = Histogram(
                "th_pipeline_duration_seconds", "Pipeline duration", ["connector"]
            )
            self.stage_errors = Counter(
                "th_stage_errors_total", "Pipeline stage errors", ["stage"]
            )
        else:
            noop = _NoopMetric()
            self.findings_total = noop
            self.exports_total = noop
            self.pipeline_duration = noop
            self.stage_errors = noop

    def serve(self, port: int) -> None:
        """Start the Prometheus metrics HTTP server (if available)."""
        if self.enabled:
            start_http_server(port)


@contextmanager
def span(name: str) -> Iterator[None]:
    """Start an OpenTelemetry span if tracing is available, else a no-op."""
    if _OTEL:
        tracer = trace.get_tracer("threat_hunting")
        with tracer.start_as_current_span(name):
            yield
    else:
        yield
