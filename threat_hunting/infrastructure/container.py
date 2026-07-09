"""Dependency injection container.

The container is the composition root for CLI, scheduler and future API/Django
interfaces. It wires adapters into application ports without leaking
infrastructure dependencies into the core.
"""

from __future__ import annotations

from dependency_injector import containers, providers

from threat_hunting.connectors.registry import ConnectorRegistry
from threat_hunting.correlation.engine import IndicatorCorrelationEngine
from threat_hunting.deduplication.engine import HybridDeduplicationEngine
from threat_hunting.detections.engine import RuleBasedDetectionEngine
from threat_hunting.enrichment.engine import ContextEnrichmentEngine
from threat_hunting.exporters.factory import ExporterFactory
from threat_hunting.extractors.ioc import RegexIndicatorExtractor
from threat_hunting.infrastructure.config.settings import AppSettings
from threat_hunting.infrastructure.events.bus import InMemoryEventBus
from threat_hunting.normalizers.default import CanonicalFindingNormalizer
from threat_hunting.parsers.default import PassthroughParser
from threat_hunting.pipelines.collection import CollectionPipeline
from threat_hunting.scoring.engine import WeightedScoringEngine
from threat_hunting.storage.repositories import InMemoryUnitOfWork, JsonFindingRepository, InMemoryFindingRepository
from threat_hunting.storage.sqlalchemy import SqlAlchemyUnitOfWork


def _build_unit_of_work(settings: AppSettings) -> object:
    if settings.storage.backend in {"sqlite", "postgresql", "postgres"} and settings.storage.url:
        return SqlAlchemyUnitOfWork(settings.storage.url)
    if settings.storage.backend == "json":
        return InMemoryUnitOfWork(JsonFindingRepository(settings.storage.path))
    return InMemoryUnitOfWork(InMemoryFindingRepository())


def _build_exporters(settings: AppSettings) -> list[object]:
    factory = ExporterFactory()
    return [factory.build(exporter) for exporter in settings.exporters if exporter.enabled]


class ApplicationContainer(containers.DeclarativeContainer):
    """Dependency Injector container for the platform."""

    settings = providers.Dependency(instance_of=AppSettings)
    event_bus = providers.Singleton(InMemoryEventBus)
    registry = providers.Singleton(
        ConnectorRegistry,
        definitions=providers.Callable(lambda config: config.connectors, settings),
        opsec_profiles=providers.Callable(lambda config: config.opsec_profiles, settings),
    )
    parser = providers.Factory(PassthroughParser)
    extractor = providers.Factory(RegexIndicatorExtractor)
    normalizer = providers.Factory(CanonicalFindingNormalizer)
    detection_engine = providers.Factory(
        RuleBasedDetectionEngine,
        rules=providers.Callable(lambda config: config.detection_rules, settings),
    )
    scoring_engine = providers.Factory(
        WeightedScoringEngine,
        policy=providers.Callable(lambda config: config.score_policy, settings),
    )
    correlation_engine = providers.Factory(IndicatorCorrelationEngine)
    deduplication_engine = providers.Factory(HybridDeduplicationEngine)
    enrichment_engine = providers.Factory(ContextEnrichmentEngine)
    unit_of_work = providers.Singleton(_build_unit_of_work, settings=settings)
    exporters = providers.Singleton(_build_exporters, settings=settings)
    pipeline = providers.Factory(
        CollectionPipeline,
        parser=parser,
        extractor=extractor,
        normalizer=normalizer,
        detection_engine=detection_engine,
        scoring_engine=scoring_engine,
        correlation_engine=correlation_engine,
        deduplication_engine=deduplication_engine,
        enrichment_engine=enrichment_engine,
        unit_of_work=unit_of_work,
        exporters=exporters,
        event_bus=event_bus,
        export_threshold=providers.Callable(lambda config: config.score_policy.export_threshold, settings),
    )
