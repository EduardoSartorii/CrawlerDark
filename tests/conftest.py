"""Shared pytest fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from threat_hunting.connectors.registry import ConnectorFactory, ConnectorRegistry
from threat_hunting.core.application.pipeline import PipelineOrchestrator
from threat_hunting.core.domain.entities import Finding
from threat_hunting.core.domain.enums import FindingCategory, IndicatorType, Severity
from threat_hunting.core.domain.services import FindingBuilder
from threat_hunting.core.domain.value_objects import Indicator
from threat_hunting.correlation.engine import CorrelationEngine
from threat_hunting.deduplication.engine import DeduplicationEngine
from threat_hunting.detections.engine import DetectionEngine
from threat_hunting.enrichment.engine import EnrichmentEngine
from threat_hunting.extractors.ioc_extractor import IocExtractor
from threat_hunting.infrastructure.messaging.event_bus import InMemoryEventBus
from threat_hunting.infrastructure.observability import PrometheusMetrics, StructlogAudit
from threat_hunting.infrastructure.persistence.memory import InMemoryUnitOfWork
from threat_hunting.parsers.passthrough import DefaultNormalizer, PassthroughParser
from threat_hunting.scoring.engine import ScoringEngine


@pytest.fixture
def config_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "config"


@pytest.fixture
def sample_finding() -> Finding:
    finding = (
        FindingBuilder()
        .with_title("Credential leak dump for vip@acme.com")
        .with_description(
            "Password dump leaked on darkweb. Contact vip@acme.com "
            "IP 203.0.113.10 domain malware.example stealer redline"
        )
        .with_source("darkweb")
        .with_connector("darkweb")
        .with_category(FindingCategory.LEAK)
        .with_severity(Severity.HIGH)
        .add_tag("leak")
        .build()
    )
    finding.add_indicator(Indicator(type=IndicatorType.EMAIL, value="vip@acme.com"))
    finding.add_indicator(Indicator(type=IndicatorType.IP, value="203.0.113.10"))
    finding.add_indicator(Indicator(type=IndicatorType.DOMAIN, value="malware.example"))
    return finding


@pytest.fixture
def uow() -> InMemoryUnitOfWork:
    return InMemoryUnitOfWork()


@pytest.fixture
def event_bus() -> InMemoryEventBus:
    return InMemoryEventBus()


@pytest.fixture
def detection_engine(config_dir: Path) -> DetectionEngine:
    return DetectionEngine(config_dir / "detection")


@pytest.fixture
def scoring_engine(config_dir: Path) -> ScoringEngine:
    return ScoringEngine(config_dir / "scoring.yaml")


@pytest.fixture
def pipeline(
    uow: InMemoryUnitOfWork,
    event_bus: InMemoryEventBus,
    detection_engine: DetectionEngine,
    scoring_engine: ScoringEngine,
) -> PipelineOrchestrator:
    return PipelineOrchestrator(
        parser=PassthroughParser(),
        extractor=IocExtractor(),
        normalizer=DefaultNormalizer(),
        detection=detection_engine,
        scoring=scoring_engine,
        correlation=CorrelationEngine(uow=uow),
        deduplication=DeduplicationEngine(uow=uow),
        enrichment=EnrichmentEngine(),
        uow=uow,
        event_bus=event_bus,
        metrics=PrometheusMetrics(),
        score_export_threshold=50.0,
    )


@pytest.fixture
def connector_factory() -> ConnectorFactory:
    registry = ConnectorRegistry()
    registry.discover()
    return ConnectorFactory(registry=registry)
