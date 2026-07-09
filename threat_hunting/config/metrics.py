"""
Prometheus Metrics Configuration.

Defines all platform metrics exposed via /metrics endpoint.
Metrics follow Prometheus naming conventions and best practices.

Metric Categories:
    - Collection: connector runs, findings collected
    - Detection: rules evaluated, matches found
    - Scoring: score distributions
    - Export: exports per destination, latency
    - Errors: per-component error counters
    - Latency: pipeline stage histograms
"""

from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram, Info, start_http_server

# ── Collection Metrics ────────────────────────────────────────────────────────

connector_runs_total = Counter(
    "threat_hunting_connector_runs_total",
    "Total connector execution runs",
    ["connector_id", "status"],
)

findings_collected_total = Counter(
    "threat_hunting_findings_collected_total",
    "Total findings collected by connector",
    ["connector_id", "category"],
)

findings_duplicates_total = Counter(
    "threat_hunting_findings_duplicates_total",
    "Total duplicate findings skipped",
    ["connector_id"],
)

findings_active_gauge = Gauge(
    "threat_hunting_findings_active",
    "Current number of active (non-FP, non-archived) findings",
)

# ── Detection Metrics ─────────────────────────────────────────────────────────

detection_rules_evaluated_total = Counter(
    "threat_hunting_detection_rules_evaluated_total",
    "Total rule evaluations",
    ["rule_type"],
)

detection_matches_total = Counter(
    "threat_hunting_detection_matches_total",
    "Total rule match events",
    ["rule_type", "connector_id"],
)

detection_suppressions_total = Counter(
    "threat_hunting_detection_suppressions_total",
    "Total findings suppressed by whitelist rules",
)

# ── Scoring Metrics ───────────────────────────────────────────────────────────

finding_score_histogram = Histogram(
    "threat_hunting_finding_score",
    "Distribution of finding scores",
    buckets=[1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
)

# ── Export Metrics ────────────────────────────────────────────────────────────

exports_total = Counter(
    "threat_hunting_exports_total",
    "Total export operations",
    ["destination", "status"],
)

export_duration_seconds = Histogram(
    "threat_hunting_export_duration_seconds",
    "Export operation duration",
    ["destination"],
)

# ── Pipeline Metrics ──────────────────────────────────────────────────────────

pipeline_stage_duration_seconds = Histogram(
    "threat_hunting_pipeline_stage_duration_seconds",
    "Duration of each pipeline stage",
    ["stage"],
    buckets=[0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0],
)

# ── System Info ───────────────────────────────────────────────────────────────

platform_info = Info(
    "threat_hunting_platform",
    "Platform version and configuration info",
)


def start_metrics_server(port: int = 9090) -> None:
    """Start the Prometheus metrics HTTP server."""
    start_http_server(port)
    platform_info.info({
        "version": "1.0.0",
        "name": "Threat Hunting Platform",
    })


def record_connector_run(connector_id: str, status: str) -> None:
    connector_runs_total.labels(connector_id=connector_id, status=status).inc()


def record_finding_collected(connector_id: str, category: str) -> None:
    findings_collected_total.labels(connector_id=connector_id, category=category).inc()


def record_export(destination: str, success: bool) -> None:
    status = "success" if success else "failure"
    exports_total.labels(destination=destination, status=status).inc()
