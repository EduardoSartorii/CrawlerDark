"""End-to-end integration test for the collection pipeline.

Runs the built-in offline ``SampleConnector`` through the full pipeline with real
engines and an in-memory store, asserting the whole chain (parse -> extract ->
normalize -> detect -> score -> correlate -> dedup -> enrich -> persist ->
auto-export) behaves as designed.
"""

from __future__ import annotations

from threat_hunting.core.application.pipeline import Pipeline
from threat_hunting.core.domain.events import DomainEvent
from threat_hunting.infrastructure.config.settings import ScoringWeights
from threat_hunting.infrastructure.connectors.builtins.sample import SampleConnector
from threat_hunting.infrastructure.correlation.engine import CorrelationEngine
from threat_hunting.infrastructure.deduplication.engine import DeduplicationEngine
from threat_hunting.infrastructure.detections.engine import DetectionEngine
from threat_hunting.infrastructure.detections.rules import KeywordRule, ThreatActorRule
from threat_hunting.infrastructure.enrichment.engine import EnrichmentEngine
from threat_hunting.infrastructure.events.in_memory_bus import InMemoryEventBus
from threat_hunting.infrastructure.exporters.json_exporter import JsonExporter
from threat_hunting.infrastructure.extractors.ioc_extractor import RegexIOCExtractor
from threat_hunting.infrastructure.normalizers.default_normalizer import (
    DefaultNormalizer,
)
from threat_hunting.infrastructure.parsers.html_parser import HtmlTextParser
from threat_hunting.infrastructure.scoring.engine import WeightedScoringEngine
from threat_hunting.infrastructure.storage.memory_repo import InMemoryUnitOfWork


class _AutoExporter(JsonExporter):
    """JSON exporter that opts into auto-export for the test."""

    name = "auto"

    def supports_auto_export(self) -> bool:
        return True


def _build_pipeline(uow, bus, tmp_path) -> Pipeline:
    detection = DetectionEngine(
        rules=[
            KeywordRule("leak", ["leak", "dump", "database"], 15.0),
            ThreatActorRule("actors", ["LockBit3"], 30.0),
        ]
    )
    return Pipeline(
        parser=HtmlTextParser(),
        extractor=RegexIOCExtractor(),
        normalizer=DefaultNormalizer(),
        detection=detection,
        scoring=WeightedScoringEngine(ScoringWeights()),
        correlation=CorrelationEngine(),
        deduplication=DeduplicationEngine(),
        enrichment=EnrichmentEngine(),
        uow=uow,
        event_bus=bus,
        exporters=[_AutoExporter(tmp_path)],
        auto_export_threshold=80.0,
    )


async def test_pipeline_end_to_end(tmp_path) -> None:
    uow = InMemoryUnitOfWork()
    bus = InMemoryEventBus()
    events: list[str] = []
    bus.subscribe(DomainEvent, lambda e: events.append(e.name))

    pipeline = _build_pipeline(uow, bus, tmp_path)
    result = await pipeline.run(SampleConnector())

    # 3 records collected; the benign one is dropped by detection.
    assert result.collected == 3
    assert result.persisted == 2
    assert result.duplicates == 0

    stored = uow.findings.list()
    assert len(stored) == 2
    assert all(f.score >= 80 for f in stored)
    assert all(f.severity.value == "critical" for f in stored)

    # High-score findings were auto-exported and events fired end-to-end.
    assert result.exported == 2
    assert (tmp_path / "findings.json").exists()
    assert "FindingCollected" in events
    assert "FindingScored" in events
    assert "FindingPersisted" in events
    assert "FindingExported" in events


async def test_pipeline_deduplicates_second_run(tmp_path) -> None:
    uow = InMemoryUnitOfWork()
    bus = InMemoryEventBus()
    pipeline = _build_pipeline(uow, bus, tmp_path)

    await pipeline.run(SampleConnector())
    # Re-seed dedup from persisted context by running a fresh pipeline sharing uow.
    pipeline2 = _build_pipeline(uow, bus, tmp_path)
    pipeline2._deduplication.seed(uow.findings.recent())
    result = await pipeline2.run(SampleConnector())

    assert result.duplicates >= 2
    assert result.persisted == 0
