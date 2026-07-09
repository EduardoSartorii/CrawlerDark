"""Prometheus metrics registry for platform telemetry."""

from __future__ import annotations

from prometheus_client import CollectorRegistry, Counter, Histogram


class HuntingMetrics:
    """Prometheus metric definitions used by observers and handlers."""

    def __init__(self, registry: CollectorRegistry | None = None) -> None:
        self.registry = registry or CollectorRegistry(auto_describe=True)
        self.events_total = Counter(
            "threat_hunting_events_total",
            "Total number of emitted events",
            labelnames=["event_type"],
            registry=self.registry,
        )
        self.findings_total = Counter(
            "threat_hunting_findings_total",
            "Total number of findings processed",
            registry=self.registry,
        )
        self.stage_duration_ms = Histogram(
            "threat_hunting_stage_duration_ms",
            "Pipeline stage processing duration in milliseconds",
            labelnames=["stage"],
            registry=self.registry,
        )
