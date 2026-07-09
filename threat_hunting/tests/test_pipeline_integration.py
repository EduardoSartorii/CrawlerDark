"""Integration tests for complete hunting pipeline."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from threat_hunting.connectors.reddit import RedditConnector
from threat_hunting.core.events import InMemoryEventBus
from threat_hunting.core.contracts import StageContext
from threat_hunting.correlation.engine import EntityCorrelationEngine
from threat_hunting.database.session import create_session_factory
from threat_hunting.deduplication.engine import FingerprintDeduplicationEngine
from threat_hunting.detections.engine import DynamicDetectionEngine
from threat_hunting.domain.entities import DetectionRule, RuleType, ScoringPolicy, WatchlistProfile
from threat_hunting.enrichment.engine import ContextEnrichmentEngine
from threat_hunting.exporters.implementations import CsvExporter, JsonExporter
from threat_hunting.extractors.indicator_extractor import IndicatorExtractor
from threat_hunting.normalizers.default_normalizer import DefaultNormalizer
from threat_hunting.parsers.default_parser import DefaultParser
from threat_hunting.pipelines.orchestrator import HuntingPipeline
from threat_hunting.scoring.engine import WeightedScoringEngine
from threat_hunting.scoring.strategies import SignalPresenceStrategy
from threat_hunting.storage.repository import SqlAlchemyUnitOfWork


def test_pipeline_runs_end_to_end(tmp_path: Path) -> None:
    db_url = f"sqlite:///{tmp_path / 'findings.db'}"
    session_factory = create_session_factory(db_url)
    uow = SqlAlchemyUnitOfWork(session_factory)
    policy = ScoringPolicy(weights={"keyword_match": 30}, threshold_misp_auto_export=80)
    rules = [DetectionRule(id="kw", name="keyword", type=RuleType.keyword, pattern="leak")]
    watchlist = WatchlistProfile()
    pipeline = HuntingPipeline(
        parser=DefaultParser(),
        extractor=IndicatorExtractor(),
        normalizer=DefaultNormalizer(),
        detection_engine=DynamicDetectionEngine(rules=rules, watchlist=watchlist),
        scoring_engine=WeightedScoringEngine(
            policy=policy,
            watchlist=watchlist,
            strategies=[SignalPresenceStrategy("keyword_match")],
        ),
        correlation_engine=EntityCorrelationEngine(),
        dedup_engine=FingerprintDeduplicationEngine(),
        enrichment_engine=ContextEnrichmentEngine(),
        uow=uow,
        exporters=[
            JsonExporter(output_file=str(tmp_path / "findings.json")),
            CsvExporter(output_file=str(tmp_path / "findings.csv")),
        ],
        misp_exporter=None,
        scoring_policy=policy,
        event_bus=InMemoryEventBus(),
    )
    connector = RedditConnector(config={})
    context = StageContext(
        connector_name="reddit",
        run_id="integration-run",
        started_at=datetime.now(UTC),
        metadata={},
    )
    findings = pipeline.run(connector=connector, context=context)
    assert len(findings) >= 1
    assert (tmp_path / "findings.json").exists()
    assert (tmp_path / "findings.csv").exists()
    with uow:
        persisted = uow.findings.list_recent(limit=10)
    assert len(persisted) >= 1
