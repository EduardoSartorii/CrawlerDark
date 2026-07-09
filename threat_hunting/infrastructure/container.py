"""Dependency Injector container for application assembly."""

from __future__ import annotations

from pathlib import Path

from dependency_injector import containers, providers

from threat_hunting.connectors.registry import ConnectorRegistry
from threat_hunting.core.application.event_bus import InMemoryEventBus
from threat_hunting.core.application.pipeline import CollectionPipeline
from threat_hunting.core.application.use_cases import ExportFindingsUseCase, RunHuntUseCase, ToggleConnectorUseCase
from threat_hunting.correlation.engine import IndicatorCorrelationEngine
from threat_hunting.deduplication.engine import HashSimilarityDeduplicationEngine
from threat_hunting.detections.engine import ConfigurableDetectionEngine
from threat_hunting.enrichment.engine import MetadataEnrichmentEngine
from threat_hunting.exporters.implementations import build_exporters
from threat_hunting.infrastructure.config import PlatformSettings
from threat_hunting.infrastructure.opsec import OpsecTransportFactory
from threat_hunting.scoring.engine import WeightedScoringEngine
from threat_hunting.storage.json_repository import JsonUnitOfWork
from threat_hunting.storage.memory import InMemoryUnitOfWork


def build_unit_of_work(settings: PlatformSettings) -> InMemoryUnitOfWork | JsonUnitOfWork:
    """Factory that selects the persistence adapter from configuration."""

    backend = settings.storage.get("backend", "memory")
    if backend == "json":
        return JsonUnitOfWork(Path(settings.storage.get("path", "data/findings.json")))
    return InMemoryUnitOfWork()


class ApplicationContainer(containers.DeclarativeContainer):
    """Dependency graph for CLI, scheduler, and future API/Django adapters."""

    settings = providers.Dependency(instance_of=PlatformSettings)
    opsec_factory = providers.Factory(OpsecTransportFactory, settings=settings)
    registry = providers.Singleton(
        lambda cfg, transport_factory: ConnectorRegistry(cfg, transport_factory).discover(),
        cfg=providers.Callable(lambda s: s.connectors, settings),
        transport_factory=opsec_factory,
    )
    event_bus = providers.Singleton(InMemoryEventBus)
    unit_of_work = providers.Singleton(build_unit_of_work, settings=settings)
    detection_engine = providers.Factory(
        ConfigurableDetectionEngine,
        rules=providers.Callable(lambda s: s.detection_rules, settings),
    )
    scoring_engine = providers.Factory(
        WeightedScoringEngine,
        profile=providers.Callable(lambda s: s.scoring, settings),
    )
    correlation_engine = providers.Factory(IndicatorCorrelationEngine)
    deduplication_engine = providers.Factory(HashSimilarityDeduplicationEngine)
    enrichment_engine = providers.Factory(
        MetadataEnrichmentEngine,
        context=providers.Callable(lambda s: s.enrichment, settings),
    )
    exporters = providers.Singleton(build_exporters, settings=settings)
    pipeline = providers.Factory(
        CollectionPipeline,
        detection_engine=detection_engine,
        scoring_engine=scoring_engine,
        correlation_engine=correlation_engine,
        deduplication_engine=deduplication_engine,
        enrichment_engine=enrichment_engine,
        unit_of_work=unit_of_work,
        event_bus=event_bus,
        exporters=providers.Callable(lambda e: list(e.values()), exporters),
        auto_export_threshold=providers.Callable(lambda s: s.scoring.auto_export_threshold, settings),
    )
    run_hunt_use_case = providers.Factory(RunHuntUseCase, registry=registry, pipeline=pipeline)
    toggle_connector_use_case = providers.Factory(ToggleConnectorUseCase, registry=registry)
    export_findings_use_case = providers.Factory(ExportFindingsUseCase, unit_of_work=unit_of_work, exporters=exporters)
