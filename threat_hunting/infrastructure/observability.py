"""Prometheus and OpenTelemetry adapters for core ports."""

from __future__ import annotations

from typing import Any

from opentelemetry import trace
from prometheus_client import Counter, Histogram

from threat_hunting.core.contracts import MetricsPort, SpanPort, TracerPort


class PrometheusMetrics(MetricsPort):
    """Metrics adapter with dynamic counter/histogram registry."""

    def __init__(self) -> None:
        self._counters: dict[str, Counter] = {}
        self._histograms: dict[str, Histogram] = {}

    def increment(self, metric: str, value: int = 1) -> None:
        if metric not in self._counters:
            self._counters[metric] = Counter(metric, f"Counter for {metric}")
        self._counters[metric].inc(value)

    def observe(self, metric: str, value: float) -> None:
        if metric not in self._histograms:
            self._histograms[metric] = Histogram(metric, f"Histogram for {metric}")
        self._histograms[metric].observe(value)


class _SpanWrapper(SpanPort):
    """Span wrapper implementing core span contract."""

    def __init__(self, span: Any) -> None:
        self._span = span

    def set_attribute(self, key: str, value: Any) -> None:
        self._span.set_attribute(key, value)

    def __enter__(self) -> "_SpanWrapper":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self._span.end()


class OpenTelemetryTracer(TracerPort):
    """Tracer adapter backed by opentelemetry-sdk."""

    def __init__(self, namespace: str = "threat_hunting") -> None:
        self._tracer = trace.get_tracer(namespace)

    def start_span(self, name: str) -> SpanPort:
        span = self._tracer.start_span(name)
        return _SpanWrapper(span)
