"""Unit tests for pipeline orchestrator."""

import pytest

from threat_hunting.core.domain.entities import Finding
from threat_hunting.core.domain.enums import SourceType
from threat_hunting.infrastructure.connectors.reddit import RedditConnector
from threat_hunting.infrastructure.correlation.engine import CorrelationEngine
from threat_hunting.infrastructure.deduplication.engine import DeduplicationEngine
from threat_hunting.infrastructure.detections.engine import DetectionEngine
from threat_hunting.infrastructure.enrichment.engine import EnrichmentEngine
from threat_hunting.infrastructure.extractors.ioc import IocExtractor
from threat_hunting.infrastructure.normalizers.finding import FindingNormalizer
from threat_hunting.infrastructure.parsers.generic import GenericParser
from threat_hunting.infrastructure.pipelines.event_bus import InProcessEventBus
from threat_hunting.infrastructure.pipelines.orchestrator import PipelineOrchestrator
from threat_hunting.infrastructure.scoring.engine import ScoringEngine
from threat_hunting.infrastructure.storage.backends import JsonStorageBackend
from threat_hunting.tests.conftest import InMemoryRuleRepo, InMemoryScoreRepo, InMemoryWatchlistRepo


class MockFindingRepo:
    async def save(self, f):
        return f

    async def get_by_id(self, fid):
        return None

    async def list_all(self, limit=500, offset=0):
        return []

    async def find_by_connector(self, c, limit=100):
        return []

    async def find_by_hash(self, h):
        return None

    async def delete(self, fid):
        return False


class MockCorrelationRepo:
    async def save(self, link):
        return link

    async def find_by_source(self, sid):
        return []

    async def find_by_target(self, tid):
        return []


@pytest.mark.asyncio
async def test_pipeline_execute(tmp_path):
    pipeline = PipelineOrchestrator(
        parser=GenericParser(),
        extractor=IocExtractor(),
        normalizer=FindingNormalizer(),
        detection_engine=DetectionEngine(InMemoryRuleRepo(), InMemoryWatchlistRepo()),
        scoring_engine=ScoringEngine(InMemoryScoreRepo()),
        correlation_engine=CorrelationEngine(MockCorrelationRepo(), MockFindingRepo()),
        dedup_engine=DeduplicationEngine(),
        enrichment_engine=EnrichmentEngine(),
        storage=JsonStorageBackend(str(tmp_path)),
        finding_repo=MockFindingRepo(),
        event_bus=InProcessEventBus(),
    )
    connector = RedditConnector()
    findings = await pipeline.execute(connector, keywords=["malware"])
    assert len(findings) >= 1
    assert findings[0].connector == "reddit"
