"""Application pipeline orchestration for connector processing flow."""

from __future__ import annotations

from collections.abc import Sequence
from time import perf_counter

from threat_hunting.core.contracts import (
    CorrelationEnginePort,
    ConnectorPort,
    DeduplicationEnginePort,
    DetectionEnginePort,
    EnrichmentEnginePort,
    EventBusPort,
    ExporterPort,
    ExtractorPort,
    MetricsPort,
    ScoringEnginePort,
    TracerPort,
    UnitOfWorkPort,
)
from threat_hunting.core.events import DomainEvent
from threat_hunting.domain.entities import ExecutionContext, Finding


class HuntingPipeline:
    """Runs the canonical processing pipeline with full stage decoupling."""

    def __init__(
        self,
        extractor: ExtractorPort,
        detection_engine: DetectionEnginePort,
        scoring_engine: ScoringEnginePort,
        correlation_engine: CorrelationEnginePort,
        deduplication_engine: DeduplicationEnginePort,
        enrichment_engine: EnrichmentEnginePort,
        uow: UnitOfWorkPort,
        exporters: Sequence[ExporterPort],
        event_bus: EventBusPort,
        metrics: MetricsPort,
        tracer: TracerPort,
        auto_export_threshold: float = 70.0,
    ) -> None:
        self._extractor = extractor
        self._detection_engine = detection_engine
        self._scoring_engine = scoring_engine
        self._correlation_engine = correlation_engine
        self._deduplication_engine = deduplication_engine
        self._enrichment_engine = enrichment_engine
        self._uow = uow
        self._exporters = {exporter.name: exporter for exporter in exporters}
        self._event_bus = event_bus
        self._metrics = metrics
        self._tracer = tracer
        self._auto_export_threshold = auto_export_threshold

    def run(self, connector: ConnectorPort, context: ExecutionContext) -> Sequence[Finding]:
        """Execute all processing stages in the required order."""
        started = perf_counter()
        with self._tracer.start_span(f"pipeline:{connector.name}") as span:
            span.set_attribute("connector", connector.name)
            connector.connect()
            try:
                raw_items = connector.collect(context)
                parsed_items = connector.parse(raw_items)
                extracted_items = self._extractor.process(parsed_items)
                normalized_findings = connector.normalize(extracted_items)
                detected = self._detection_engine.process(normalized_findings, context)
                scored = self._scoring_engine.process(detected, context)
                correlated = self._correlation_engine.process(scored, context)
                deduplicated = self._deduplication_engine.process(correlated, context)
                enriched = self._enrichment_engine.process(deduplicated, context)
                self._persist(enriched)
                self._publish_events(enriched, context)
                self._metrics.increment("pipeline_runs_total")
                self._metrics.observe("pipeline_findings_count", float(len(enriched)))
                self._metrics.observe("pipeline_runtime_seconds", perf_counter() - started)
                return enriched
            finally:
                connector.close()

    def export(self, findings: Sequence[Finding], context: ExecutionContext, exporter_name: str) -> None:
        """Export findings through selected exporter."""
        exporter = self._exporters[exporter_name]
        exporter.export(findings, context)
        self._event_bus.publish(
            DomainEvent(
                name="FindingExported",
                payload={
                    "connector": context.connector_name,
                    "exporter": exporter_name,
                    "count": len(findings),
                },
            )
        )

    def _persist(self, findings: Sequence[Finding]) -> None:
        with self._uow as unit:
            unit.findings.save_many(findings)
            unit.commit()

    def _publish_events(self, findings: Sequence[Finding], context: ExecutionContext) -> None:
        for finding in findings:
            self._event_bus.publish(
                DomainEvent(
                    name="FindingDetected",
                    payload={
                        "finding_id": str(finding.id),
                        "connector": finding.connector,
                        "score": finding.score,
                        "severity": finding.severity.value,
                    },
                )
            )
            if finding.score >= self._auto_export_threshold and "misp" in self._exporters:
                self._exporters["misp"].export([finding], context)
                self._event_bus.publish(
                    DomainEvent(
                        name="HighScoreFinding",
                        payload={
                            "finding_id": str(finding.id),
                            "score": finding.score,
                        },
                    )
                )
