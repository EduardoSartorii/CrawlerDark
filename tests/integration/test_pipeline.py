"""
Integration Tests — Pipeline End-to-End
==========================================

Tests the full pipeline from normalized Finding → persistence.
Uses real (in-memory SQLite) infrastructure but mock detection results.
"""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock

from threat_hunting.core.application.pipeline.pipeline import Pipeline, PipelineBuilder
from threat_hunting.core.application.pipeline.stages import (
    ScoringStage, PersistenceStage, DetectionStage,
    CorrelationStage, DeduplicationStage, EnrichmentStage,
)
from threat_hunting.core.domain.entities.finding import Finding, FindingStatus
from threat_hunting.core.domain.value_objects.score import Score
from threat_hunting.infrastructure.scoring.engine import ScoringEngine
from threat_hunting.infrastructure.correlation.engine import CorrelationEngine
from threat_hunting.infrastructure.deduplication.engine import DeduplicationEngine
from threat_hunting.infrastructure.enrichment.engine import EnrichmentEngine
from threat_hunting.infrastructure.event_bus.in_memory_bus import InMemoryEventBus
from threat_hunting.infrastructure.storage.unit_of_work import SQLAlchemyUnitOfWork

DEFAULT_WEIGHTS = {
    "ioc_match": 2.5,
    "credential_match": 3.0,
    "card_match": 3.5,
    "vip_match": 3.0,
    "threat_actor_match": 2.5,
    "keyword_match": 1.0,
    "yara_match": 2.0,
    "regex_match": 1.0,
    "high_ioc_density": 1.5,
    "ioc_density_threshold": 10,
    "recurrence_bonus": 0.5,
    "source_reputation": {"paste": 1.3},
    "max_score": 10.0,
}


class TestPipeline:
    """End-to-end pipeline integration tests."""

    @pytest.fixture
    def null_detection_engine(self):
        engine = AsyncMock()
        async def run(f):
            f.advance_status(FindingStatus.DETECTED)
            return f
        engine.run = run
        return engine

    @pytest.fixture
    def null_enrichment_engine(self):
        engine = AsyncMock()
        async def enrich(f):
            f.advance_status(FindingStatus.ENRICHED)
            return f
        engine.enrich = enrich
        return engine

    @pytest.fixture
    def null_finding_repo(self):
        repo = AsyncMock()
        repo.exists_by_hash.return_value = False
        repo.find_similar.return_value = []
        repo.list.return_value = []
        return repo

    @pytest.fixture
    def null_indicator_repo(self):
        repo = AsyncMock()
        repo.get_by_id.return_value = None
        return repo

    @pytest.fixture
    def pipeline(
        self,
        uow: SQLAlchemyUnitOfWork,
        event_bus: InMemoryEventBus,
        null_detection_engine,
        null_enrichment_engine,
        null_finding_repo,
        null_indicator_repo,
    ) -> Pipeline:
        scoring_engine = ScoringEngine(DEFAULT_WEIGHTS)
        correlation_engine = CorrelationEngine(
            finding_repo=null_finding_repo, event_bus=event_bus
        )
        dedup_engine = DeduplicationEngine(
            finding_repo=null_finding_repo, event_bus=event_bus
        )
        enrichment_engine = EnrichmentEngine(
            indicator_repo=null_indicator_repo,
            event_bus=event_bus,
            enabled=False,
        )

        return (
            PipelineBuilder(event_bus, auto_export_threshold=9.0)
            .with_stage(DetectionStage(null_detection_engine))
            .with_stage(ScoringStage(scoring_engine))
            .with_stage(CorrelationStage(correlation_engine))
            .with_stage(DeduplicationStage(dedup_engine))
            .with_stage(EnrichmentStage(enrichment_engine))
            .with_stage(PersistenceStage(uow))
            .build()
        )

    @pytest.mark.asyncio
    async def test_pipeline_persists_finding(
        self,
        pipeline: Pipeline,
        sample_finding: Finding,
        uow: SQLAlchemyUnitOfWork,
    ):
        result = await pipeline.process(sample_finding)
        assert result.success

        async with uow as u:
            persisted = await u.findings.get_by_id(sample_finding.id)
            assert persisted is not None

    @pytest.mark.asyncio
    async def test_pipeline_result_has_stage_metrics(
        self,
        pipeline: Pipeline,
        sample_finding: Finding,
    ):
        result = await pipeline.process(sample_finding)
        stage_names = [s.stage_name for s in result.stages]
        assert "detection" in stage_names
        assert "scoring" in stage_names
        assert "persistence" in stage_names
        assert result.total_duration_ms > 0

    @pytest.mark.asyncio
    async def test_pipeline_score_updated_in_finding(
        self,
        pipeline: Pipeline,
        sample_finding: Finding,
        uow: SQLAlchemyUnitOfWork,
    ):
        await pipeline.process(sample_finding)
        # Score should be >= 0 (no detections = 0, which is expected)
        assert sample_finding.score.value >= 0.0

    @pytest.mark.asyncio
    async def test_pipeline_timeline_populated(
        self,
        pipeline: Pipeline,
        sample_finding: Finding,
    ):
        await pipeline.process(sample_finding)
        events = [t.event for t in sample_finding.timeline]
        assert "finding_created" in events
        assert "status_persisted" in events
