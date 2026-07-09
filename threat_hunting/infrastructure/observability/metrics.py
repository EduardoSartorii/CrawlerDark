"""Métricas Prometheus centralizadas."""

from __future__ import annotations

from prometheus_client import Counter, Histogram, start_http_server


class Metrics:
    """Registro global. Instanciado uma vez pelo composition root."""

    def __init__(self) -> None:
        self.findings_total = Counter(
            "threat_hunting_findings_total",
            "Total findings observed",
            ["connector", "category", "severity"],
        )
        self.findings_persisted = Counter(
            "threat_hunting_findings_persisted_total",
            "Findings persisted after dedup",
            ["connector"],
        )
        self.pipeline_errors = Counter(
            "threat_hunting_pipeline_errors_total",
            "Errors emitted by pipeline stages",
            ["stage"],
        )
        self.connector_duration = Histogram(
            "threat_hunting_connector_duration_seconds",
            "Total duration of a connector run",
            ["connector"],
        )
        self.export_total = Counter(
            "threat_hunting_export_total",
            "Findings exported",
            ["target"],
        )

    def start_http_exporter(self, port: int) -> None:
        start_http_server(port)
