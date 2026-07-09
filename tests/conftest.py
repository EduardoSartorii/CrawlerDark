"""Shared test fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from threat_hunting.connectors.registry import ConnectorRegistry
from threat_hunting.core.application.event_bus import InMemoryEventBus
from threat_hunting.core.application.pipeline import CollectionPipeline
from threat_hunting.core.domain.rules import DetectionRule, RuleType, ScoringProfile
from threat_hunting.correlation.engine import IndicatorCorrelationEngine
from threat_hunting.deduplication.engine import HashSimilarityDeduplicationEngine
from threat_hunting.detections.engine import ConfigurableDetectionEngine
from threat_hunting.enrichment.engine import MetadataEnrichmentEngine
from threat_hunting.exporters.implementations import JsonExporter
from threat_hunting.scoring.engine import WeightedScoringEngine
from threat_hunting.storage.json_repository import JsonUnitOfWork


@pytest.fixture()
def rules() -> list[DetectionRule]:
    """Detection rules used by integration tests."""

    return [
        DetectionRule(
            name="credential keyword",
            type=RuleType.KEYWORD,
            values=["api_key", "credential"],
            weight=20,
            confidence=0.8,
            tags=["credential"],
        ),
        DetectionRule(
            name="vip email",
            type=RuleType.REGEX,
            pattern=r"\b[A-Za-z0-9._%+-]+@acme\.test\b",
            weight=25,
            confidence=0.9,
            tags=["vip"],
        ),
    ]


@pytest.fixture()
def registry() -> ConnectorRegistry:
    """Connector registry with configured GitHub seed data."""

    return ConnectorRegistry(
        {
            "github": {
                "items": [
                    {
                        "title": "ACME credential exposure",
                        "description": "api_key leaked for admin@acme.test at https://acme.test/login",
                        "url": "https://github.com/acme/leak",
                    }
                ]
            }
        }
    ).discover()


@pytest.fixture()
def pipeline(tmp_path: Path, rules: list[DetectionRule]) -> CollectionPipeline:
    """Collection pipeline wired with real engines and JSON persistence."""

    profile = ScoringProfile(
        base_score=5,
        weights={"keyword": 1.0, "regex": 1.2, "indicator_count": 2.0, "sensitive_match": 10.0},
        auto_export_threshold=60,
    )
    return CollectionPipeline(
        detection_engine=ConfigurableDetectionEngine(rules),
        scoring_engine=WeightedScoringEngine(profile),
        correlation_engine=IndicatorCorrelationEngine(),
        deduplication_engine=HashSimilarityDeduplicationEngine(),
        enrichment_engine=MetadataEnrichmentEngine({"tenant": "test"}),
        unit_of_work=JsonUnitOfWork(tmp_path / "findings.json"),
        event_bus=InMemoryEventBus(),
        exporters=[JsonExporter(tmp_path / "export.json")],
        auto_export_threshold=60,
    )
