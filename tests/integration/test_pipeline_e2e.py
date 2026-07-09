"""Teste end-to-end do pipeline com um conector fake in-memory + SQLite."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import pytest

from threat_hunting.core.application.events import InMemoryEventBus
from threat_hunting.core.application.pipeline import (
    CanonicalizeStage,
    DeduplicateStage,
    DetectStage,
    EnrichStage,
    ExtractStage,
    NormalizeStage,
    ParseStage,
    PersistStage,
    PipelineContext,
    PipelineOrchestrator,
    ScoreStage,
)
from threat_hunting.core.application.use_cases import RunConnectorPipelineUseCase
from threat_hunting.core.domain.builders import FindingBuilder
from threat_hunting.core.domain.value_objects import Category, Severity, SourceRef
from threat_hunting.infrastructure.config.schemas import ScoringConfig
from threat_hunting.infrastructure.connectors.base import BaseConnector
from threat_hunting.infrastructure.correlation import GraphCorrelationEngine
from threat_hunting.infrastructure.deduplication import HashDeduplicationEngine
from threat_hunting.infrastructure.detections import (
    CompositeDetectionEngine,
    RegexDetector,
)
from threat_hunting.infrastructure.enrichment import NoopEnrichmentEngine
from threat_hunting.infrastructure.extractors import (
    CompositeExtractor,
    CredentialExtractor,
    IOCExtractor,
)
from threat_hunting.infrastructure.normalizers import CanonicalNormalizer
from threat_hunting.infrastructure.scoring import WeightedScoringEngine


class FakeConnector(BaseConnector):
    name = "fake"

    async def collect(self) -> AsyncIterator[dict[str, Any]]:  # type: ignore[override]
        yield {"title": "Leaked data", "body": "aws AKIAIOSFODNN7EXAMPLE user@example.com"}
        yield {"title": "Public post", "body": "not much here, just a mention of X"}

    async def parse(self, payload: Any) -> dict[str, Any]:
        return payload

    async def normalize(self, parsed: dict[str, Any]):
        src = SourceRef(source="fake", connector=self.name, url="https://ex/fake")
        return (
            FindingBuilder()
            .title(parsed["title"])
            .description(parsed["body"])
            .source(src)
            .category(Category.OTHER)
            .severity(Severity.INFO)
            .raw(parsed)
            .build()
        )


REGEX_RULES = [
    {
        "id": "regex.aws",
        "pattern": r"AKIA[0-9A-Z]{16}",
        "category": "CREDENTIAL",
        "severity": "CRITICAL",
        "confidence": 95,
        "tags": ["aws"],
    },
]


@pytest.mark.asyncio
async def test_pipeline_persists_and_scores_findings(uow_factory):
    bus = InMemoryEventBus()
    orch = PipelineOrchestrator(
        [
            ParseStage(),
            NormalizeStage(),
            ExtractStage(CompositeExtractor([IOCExtractor(), CredentialExtractor()])),
            CanonicalizeStage(CanonicalNormalizer()),
            DetectStage(CompositeDetectionEngine([RegexDetector(REGEX_RULES)])),
            ScoreStage(
                WeightedScoringEngine(
                    ScoringConfig(
                        base_score=10,
                        weights={"regex_match": 5, "credential": 25, "email": 8},
                        severity_multiplier={"CRITICAL": 1.5, "INFO": 0.5, "MEDIUM": 1, "HIGH": 1.2, "LOW": 0.8},
                        source_bonus={"api": 3},
                        cap={"min": 0, "max": 100},
                    )
                ),
                bus,
            ),
            DeduplicateStage(HashDeduplicationEngine(), uow_factory, bus),
            EnrichStage(NoopEnrichmentEngine(), bus),
            PersistStage(uow_factory, bus),
        ],
        bus,
    )
    connector = FakeConnector()
    use_case = RunConnectorPipelineUseCase(orch, uow_factory)
    job = await use_case.execute(connector)

    assert job.items_collected == 2
    assert job.items_persisted == 2
    async with uow_factory() as uow:
        recent = list(await uow.findings.find_recent())
    assert len(recent) == 2
    leaked = next(f for f in recent if "Leaked" in f.title)
    assert leaked.severity is Severity.CRITICAL
    assert float(leaked.score) > 30


@pytest.mark.asyncio
async def test_pipeline_deduplicates_repeated_finding(uow_factory):
    bus = InMemoryEventBus()
    orch = PipelineOrchestrator(
        [
            ParseStage(),
            NormalizeStage(),
            ExtractStage(CompositeExtractor([IOCExtractor()])),
            CanonicalizeStage(CanonicalNormalizer()),
            DeduplicateStage(HashDeduplicationEngine(), uow_factory, bus),
            PersistStage(uow_factory, bus),
        ],
        bus,
    )
    use_case = RunConnectorPipelineUseCase(orch, uow_factory)
    await use_case.execute(FakeConnector())
    await use_case.execute(FakeConnector())
    async with uow_factory() as uow:
        recent = list(await uow.findings.find_recent())
    assert len(recent) == 2  # 2 unique in each run, dedup drops second run
