"""Threat hunting collection pipeline.

The pipeline is intentionally explicit: each stage is a replaceable strategy
or adapter. This keeps connector SDK code small and lets detections, scoring,
correlation, deduplication, enrichment, persistence, and export evolve
independently.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from threat_hunting.connectors.base import BaseConnector, RawCollectionItem
from threat_hunting.core.application.ports import (
    CorrelationEngine,
    DeduplicationEngine,
    DetectionEngine,
    EnrichmentEngine,
    EventBus,
    Exporter,
    ScoringEngine,
    UnitOfWork,
)
from threat_hunting.core.domain.entities import Finding
from threat_hunting.core.domain.events import FindingCollected


class CollectionPipeline:
    """Orchestrates the complete connector-to-export flow."""

    def __init__(
        self,
        detection_engine: DetectionEngine,
        scoring_engine: ScoringEngine,
        correlation_engine: CorrelationEngine,
        deduplication_engine: DeduplicationEngine,
        enrichment_engine: EnrichmentEngine,
        unit_of_work: UnitOfWork,
        event_bus: EventBus,
        exporters: Sequence[Exporter] | None = None,
        auto_export_threshold: float = 80.0,
    ) -> None:
        self.detection_engine = detection_engine
        self.scoring_engine = scoring_engine
        self.correlation_engine = correlation_engine
        self.deduplication_engine = deduplication_engine
        self.enrichment_engine = enrichment_engine
        self.unit_of_work = unit_of_work
        self.event_bus = event_bus
        self.exporters = list(exporters or [])
        self.auto_export_threshold = auto_export_threshold

    def run(self, connector: BaseConnector, limit: int | None = None, export: bool = True) -> list[Finding]:
        """Execute all pipeline stages for a connector."""

        persisted: list[Finding] = []
        connector.connect()
        try:
            for raw_item in self._limited(connector.collect(), limit):
                parsed = connector.parse(raw_item)
                extracted = connector.extract(parsed)
                normalized = connector.normalize(extracted)
                matches = self.detection_engine.evaluate(normalized)
                scored = self.scoring_engine.score(normalized, matches)
                with self.unit_of_work as uow:
                    existing = uow.findings.list()
                    correlated = self.correlation_engine.correlate(scored, existing)
                    if self.deduplication_engine.is_duplicate(correlated, existing):
                        continue
                    enriched = self.enrichment_engine.enrich(correlated)
                    stored = uow.findings.save(enriched)
                    uow.commit()
                persisted.append(stored)
                self.event_bus.publish(FindingCollected.from_finding(stored))
            if export:
                self._export_high_score_findings(persisted)
            return persisted
        finally:
            connector.close()

    @staticmethod
    def _limited(items: Iterable[RawCollectionItem], limit: int | None) -> Iterable[RawCollectionItem]:
        """Yield at most ``limit`` raw collection items."""

        for index, item in enumerate(items):
            if limit is not None and index >= limit:
                break
            yield item

    def _export_high_score_findings(self, findings: Sequence[Finding]) -> None:
        """Export findings that cross the configured threshold."""

        exportable = [finding for finding in findings if finding.score >= self.auto_export_threshold]
        if not exportable:
            return
        for exporter in self.exporters:
            exporter.export(exportable)
