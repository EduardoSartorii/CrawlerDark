"""Métricas Prometheus centralizadas.

Utiliza um ``CollectorRegistry`` dedicado por instância para permitir múltiplas
instanciações (útil em testes e em processos CLI de curta duração).
"""

from __future__ import annotations

from prometheus_client import CollectorRegistry, Counter, Histogram, start_http_server


class Metrics:
    """Registro isolado. Instanciado uma vez pelo composition root."""

    def __init__(self) -> None:
        self.registry = CollectorRegistry()
        self.findings_total = Counter(
            "threat_hunting_findings_total",
            "Total findings observed",
            ["connector", "category", "severity"],
            registry=self.registry,
        )
        self.findings_persisted = Counter(
            "threat_hunting_findings_persisted_total",
            "Findings persisted after dedup",
            ["connector"],
            registry=self.registry,
        )
        self.pipeline_errors = Counter(
            "threat_hunting_pipeline_errors_total",
            "Errors emitted by pipeline stages",
            ["stage"],
            registry=self.registry,
        )
        self.connector_duration = Histogram(
            "threat_hunting_connector_duration_seconds",
            "Total duration of a connector run",
            ["connector"],
            registry=self.registry,
        )
        self.export_total = Counter(
            "threat_hunting_export_total",
            "Findings exported",
            ["target"],
            registry=self.registry,
        )

    def start_http_exporter(self, port: int) -> None:
        start_http_server(port, registry=self.registry)
