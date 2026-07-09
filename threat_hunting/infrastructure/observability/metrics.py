"""
MetricsCollector — Prometheus Metrics
=====================================

Exposes platform metrics via prometheus-client.
A separate HTTP server serves /metrics on the configured port.

Metrics exposed:
    - threat_hunting_findings_total (counter, labels: connector, severity, category)
    - threat_hunting_collection_duration_seconds (histogram, labels: connector)
    - threat_hunting_pipeline_stage_duration_seconds (histogram, labels: stage)
    - threat_hunting_exports_total (counter, labels: exporter, success)
    - threat_hunting_rules_matched_total (counter, labels: rule_type, rule_name)
    - threat_hunting_connectors_active (gauge)
    - threat_hunting_score_distribution (histogram)
"""

from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram, start_http_server


class MetricsCollector:
    """
    Central Prometheus metrics registry.

    Registered as a singleton in the DI container.
    Metrics are exposed on /metrics via a dedicated HTTP server.
    """

    def __init__(self) -> None:
        self.findings_total = Counter(
            "threat_hunting_findings_total",
            "Total Findings produced",
            ["connector", "severity", "category"],
        )
        self.collection_duration = Histogram(
            "threat_hunting_collection_duration_seconds",
            "Time to complete a connector collection run",
            ["connector"],
            buckets=[1, 5, 15, 30, 60, 120, 300, 600],
        )
        self.pipeline_stage_duration = Histogram(
            "threat_hunting_pipeline_stage_duration_seconds",
            "Time spent in each pipeline stage",
            ["stage"],
            buckets=[0.001, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0],
        )
        self.exports_total = Counter(
            "threat_hunting_exports_total",
            "Total export attempts",
            ["exporter", "success"],
        )
        self.rules_matched_total = Counter(
            "threat_hunting_rules_matched_total",
            "Total detection rule matches",
            ["rule_type", "rule_name"],
        )
        self.connectors_active = Gauge(
            "threat_hunting_connectors_active",
            "Number of currently active connectors",
        )
        self.score_distribution = Histogram(
            "threat_hunting_score_distribution",
            "Distribution of Finding scores",
            buckets=[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
        )
        self.errors_total = Counter(
            "threat_hunting_errors_total",
            "Total processing errors",
            ["component", "error_type"],
        )

    def record_finding(self, connector: str, severity: str, category: str) -> None:
        self.findings_total.labels(connector=connector, severity=severity, category=category).inc()

    def record_export(self, exporter: str, success: bool) -> None:
        self.exports_total.labels(exporter=exporter, success=str(success).lower()).inc()

    def record_score(self, score: float) -> None:
        self.score_distribution.observe(score)

    def record_rule_match(self, rule_type: str, rule_name: str) -> None:
        self.rules_matched_total.labels(rule_type=rule_type, rule_name=rule_name[:64]).inc()

    def record_error(self, component: str, error_type: str) -> None:
        self.errors_total.labels(component=component, error_type=error_type).inc()

    def start_server(self, port: int = 9090) -> None:
        """Start the Prometheus metrics HTTP server."""
        start_http_server(port)


# Module-level singleton (import-time initialization is safe).
metrics = MetricsCollector()
