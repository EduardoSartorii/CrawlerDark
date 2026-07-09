"""Prometheus metrics.

Responsibility
--------------
Expose the platform's counters/histograms. When ``prometheus_client`` is
installed the metrics are real Prometheus objects (scrapable); otherwise they
fall back to in-process counters so code that records metrics never breaks and
values remain inspectable in tests.
"""

from __future__ import annotations

from collections import defaultdict


class _NoopMetric:
    """In-process fallback metric supporting the Prometheus call surface."""

    def __init__(self) -> None:
        self.value: float = 0.0
        self._labelled: dict[tuple, "_NoopMetric"] = defaultdict(_NoopMetric)

    def labels(self, *args: str, **kwargs: str) -> "_NoopMetric":
        key = args + tuple(sorted(kwargs.items()))
        return self._labelled[key]

    def inc(self, amount: float = 1.0) -> None:
        self.value += amount

    def observe(self, amount: float) -> None:
        self.value += amount

    def set(self, amount: float) -> None:
        self.value = amount


class Metrics:
    """Registry of the platform's metrics (Prometheus-backed when available)."""

    def __init__(self) -> None:
        self._prometheus = self._try_prometheus()
        if self._prometheus is not None:
            counter, histogram, gauge = self._prometheus
            self.findings_total = counter(
                "threat_hunting_findings_total", "Findings produced", ["connector", "severity"]
            )
            self.connector_errors_total = counter(
                "threat_hunting_connector_errors_total", "Connector errors", ["connector"]
            )
            self.pipeline_stage_seconds = histogram(
                "threat_hunting_pipeline_stage_seconds", "Stage duration", ["stage"]
            )
            self.exports_total = counter(
                "threat_hunting_exports_total", "Exports performed", ["exporter"]
            )
            self.findings_score = gauge(
                "threat_hunting_last_score", "Score of the last finding", ["connector"]
            )
        else:
            self.findings_total = _NoopMetric()
            self.connector_errors_total = _NoopMetric()
            self.pipeline_stage_seconds = _NoopMetric()
            self.exports_total = _NoopMetric()
            self.findings_score = _NoopMetric()

    @staticmethod
    def _try_prometheus():
        try:
            from prometheus_client import Counter, Gauge, Histogram
        except ImportError:
            return None
        return Counter, Histogram, Gauge

    @property
    def enabled(self) -> bool:
        """Whether real Prometheus metrics are active."""
        return self._prometheus is not None
