"""End-to-end tests for the collection pipeline."""

from threat_hunting.connectors.generic import StaticConnector
from threat_hunting.core.domain.entities import DetectionRule, ScorePolicy, Severity
from threat_hunting.correlation.engine import IndicatorCorrelationEngine
from threat_hunting.deduplication.engine import HybridDeduplicationEngine
from threat_hunting.detections.engine import RuleBasedDetectionEngine
from threat_hunting.enrichment.engine import ContextEnrichmentEngine
from threat_hunting.extractors.ioc import RegexIndicatorExtractor
from threat_hunting.infrastructure.events.bus import InMemoryEventBus
from threat_hunting.normalizers.default import CanonicalFindingNormalizer
from threat_hunting.parsers.default import PassthroughParser
from threat_hunting.pipelines.collection import CollectionPipeline
from threat_hunting.scoring.engine import WeightedScoringEngine
from threat_hunting.storage.repositories import InMemoryUnitOfWork


class RecordingExporter:
    """Exporter test double that records finding ids."""

    name = "recording"

    def __init__(self) -> None:
        self.exported: list[str] = []

    def export(self, finding) -> None:
        self.exported.append(finding.id)


def test_pipeline_processes_finding_and_exports_above_threshold() -> None:
    """The full mandatory pipeline extracts, detects, scores, persists and exports."""

    connector = StaticConnector(
        name="github",
        source="github",
        config={
            "category": "credential_hunting",
            "items": [
                {
                    "title": "Credential leak",
                    "description": "admin@example.com leaked password for example.com",
                }
            ],
        },
    )
    exporter = RecordingExporter()
    event_bus = InMemoryEventBus()
    pipeline = CollectionPipeline(
        parser=PassthroughParser(),
        extractor=RegexIndicatorExtractor(),
        normalizer=CanonicalFindingNormalizer(),
        detection_engine=RuleBasedDetectionEngine(
            [DetectionRule(id="r1", name="Leak", kind="keyword", pattern="leaked", severity=Severity.HIGH, weight=3)]
        ),
        scoring_engine=WeightedScoringEngine(
            ScorePolicy(weights={"detection": 5, "email": 4, "domain": 3, "credential": 6}, export_threshold=10)
        ),
        correlation_engine=IndicatorCorrelationEngine(),
        deduplication_engine=HybridDeduplicationEngine(),
        enrichment_engine=ContextEnrichmentEngine(),
        unit_of_work=InMemoryUnitOfWork(),
        exporters=[exporter],
        event_bus=event_bus,
        export_threshold=10,
    )

    findings = pipeline.run(connector)

    assert len(findings) == 1
    assert findings[0].score >= 10
    assert "credential_hunting" in findings[0].tags
    assert exporter.exported == [findings[0].id]
    assert [event.name for event in event_bus.published] == [
        "finding.collected",
        "finding.persisted",
        "finding.exported",
    ]


def test_pipeline_deduplicates_repeated_key_indicators() -> None:
    """The deduplication stage suppresses repeated indicators across runs."""

    connector = StaticConnector(
        name="reddit",
        source="reddit",
        config={
            "items": [
                {"title": "Leak one", "description": "Repeated admin@example.com credential"},
                {"title": "Leak two", "description": "Repeated admin@example.com credential"},
            ]
        },
    )
    uow = InMemoryUnitOfWork()
    pipeline = CollectionPipeline(
        parser=PassthroughParser(),
        extractor=RegexIndicatorExtractor(),
        normalizer=CanonicalFindingNormalizer(),
        detection_engine=RuleBasedDetectionEngine([]),
        scoring_engine=WeightedScoringEngine(ScorePolicy(weights={"email": 1}, export_threshold=99)),
        correlation_engine=IndicatorCorrelationEngine(),
        deduplication_engine=HybridDeduplicationEngine(),
        enrichment_engine=ContextEnrichmentEngine(),
        unit_of_work=uow,
        exporters=[],
        event_bus=InMemoryEventBus(),
        export_threshold=99,
    )

    findings = pipeline.run(connector)

    assert len(findings) == 1
    assert len(uow.findings.list()) == 1
