"""Prometheus metrics service."""

from __future__ import annotations

from prometheus_client import Counter, Histogram, CollectorRegistry, generate_latest


class MetricsService:
    """Expose counters and histograms for collection pipeline telemetry."""

    def __init__(self) -> None:
        self.registry = CollectorRegistry()
        self.findings_total = Counter("findings_total", "Findings processed", ["connector"], registry=self.registry)
        self.exports_total = Counter("exports_total", "Findings exported", ["exporter"], registry=self.registry)
        self.pipeline_seconds = Histogram("pipeline_seconds", "Pipeline execution time", registry=self.registry)

    def render(self) -> bytes:
        """Return Prometheus exposition format."""

        return generate_latest(self.registry)
