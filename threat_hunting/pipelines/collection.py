"""Mandatory collection pipeline orchestration.

The sequence is fixed by business architecture:
Connector -> Parser -> Extractor -> Normalizer -> Detection -> Scoring ->
Correlation -> Deduplication -> Enrichment -> Persistence -> Export.
"""

from __future__ import annotations

from collections.abc import Sequence

from threat_hunting.connectors.base import BaseConnector
from threat_hunting.core.application.ports import (
    CorrelationEnginePort,
    DeduplicationEnginePort,
    DetectionEnginePort,
    EnrichmentEnginePort,
    EventBus,
    ExporterPort,
    ExtractorPort,
    NormalizerPort,
    ParserPort,
    ScoringEnginePort,
    UnitOfWork,
)
from threat_hunting.core.domain.entities import Finding
from threat_hunting.core.domain.events import FindingCollected, FindingExported, FindingPersisted


class CollectionPipeline:
    """Run one connector through every independent pipeline stage."""

    def __init__(
        self,
        parser: ParserPort,
        extractor: ExtractorPort,
        normalizer: NormalizerPort,
        detection_engine: DetectionEnginePort,
        scoring_engine: ScoringEnginePort,
        correlation_engine: CorrelationEnginePort,
        deduplication_engine: DeduplicationEnginePort,
        enrichment_engine: EnrichmentEnginePort,
        unit_of_work: UnitOfWork,
        exporters: Sequence[ExporterPort],
        event_bus: EventBus,
        export_threshold: float,
    ) -> None:
        self._parser = parser
        self._extractor = extractor
        self._normalizer = normalizer
        self._detection_engine = detection_engine
        self._scoring_engine = scoring_engine
        self._correlation_engine = correlation_engine
        self._deduplication_engine = deduplication_engine
        self._enrichment_engine = enrichment_engine
        self._unit_of_work = unit_of_work
        self._exporters = list(exporters)
        self._event_bus = event_bus
        self._export_threshold = export_threshold

    def run(self, connector: BaseConnector, export: bool = True) -> list[Finding]:
        """Execute the full pipeline for a connector."""

        processed: list[Finding] = []
        connector.connect()
        try:
            for raw_item in connector.collect():
                parsed = connector.parse(self._parser.parse(raw_item))
                finding = connector.normalize(parsed)
                finding = self._extractor.extract(finding)
                finding = self._normalizer.normalize(finding)
                finding = self._detection_engine.detect(finding)
                finding = self._scoring_engine.score(finding)
                with self._unit_of_work as uow:
                    existing = uow.findings.list()
                    finding = self._correlation_engine.correlate(finding, existing)
                    duplicate = self._deduplication_engine.is_duplicate(finding, existing)
                    if duplicate:
                        continue
                    finding = self._enrichment_engine.enrich(finding)
                    uow.findings.add(finding)
                self._event_bus.publish(
                    FindingCollected(payload={"finding_id": finding.id, "connector": connector.name})
                )
                self._event_bus.publish(FindingPersisted(payload={"finding_id": finding.id}))
                if export and finding.score >= self._export_threshold:
                    for exporter in self._exporters:
                        exporter.export(finding)
                        self._event_bus.publish(
                            FindingExported(payload={"finding_id": finding.id, "exporter": exporter.name})
                        )
                processed.append(finding)
        finally:
            connector.close()
        return processed
