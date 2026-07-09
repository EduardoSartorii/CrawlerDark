"""Dependency-injection composition root.

Responsibility
--------------
Wire the whole platform together in one place using ``dependency-injector``.
This is the *only* module that knows how every abstraction maps to a concrete
adapter. The CLI, scheduler and a future API/Django admin all obtain their
collaborators from here, so swapping an implementation (storage backend,
transport, exporter set) is a single edit confined to this file.

The container respects configuration: the storage backend, OPSEC profiles,
scoring weights, rules and watchlists are all read from :class:`PlatformSettings`.
"""

from __future__ import annotations

from pathlib import Path

from dependency_injector import containers, providers

from threat_hunting.core.application.pipeline import Pipeline
from threat_hunting.core.application.ports.repository import UnitOfWorkPort
from threat_hunting.core.application.use_cases import (
    ExportFindingsUseCase,
    RunHuntUseCase,
)
from threat_hunting.infrastructure.config.settings import (
    PlatformSettings,
    load_settings,
)
from threat_hunting.infrastructure.connectors.registry import ConnectorRegistry
from threat_hunting.infrastructure.correlation.engine import CorrelationEngine
from threat_hunting.infrastructure.deduplication.engine import DeduplicationEngine
from threat_hunting.infrastructure.detections.engine import DetectionEngine
from threat_hunting.infrastructure.detections.rule_repository import (
    YamlRuleRepository,
    YamlWatchlistRepository,
)
from threat_hunting.infrastructure.enrichment.engine import EnrichmentEngine
from threat_hunting.infrastructure.events.in_memory_bus import InMemoryEventBus
from threat_hunting.infrastructure.events.subscribers import (
    AuditLogSubscriber,
    MetricsSubscriber,
)
from threat_hunting.infrastructure.exporters.factory import ExporterFactory
from threat_hunting.infrastructure.normalizers.default_normalizer import (
    DefaultNormalizer,
)
from threat_hunting.infrastructure.observability.health import HealthChecker
from threat_hunting.infrastructure.observability.logging import configure_logging
from threat_hunting.infrastructure.observability.metrics import Metrics
from threat_hunting.infrastructure.opsec.transport import TransportFactory
from threat_hunting.infrastructure.parsers.html_parser import HtmlTextParser
from threat_hunting.infrastructure.scoring.engine import WeightedScoringEngine
from threat_hunting.infrastructure.storage.json_repo import JsonUnitOfWork
from threat_hunting.infrastructure.storage.memory_repo import InMemoryUnitOfWork
from threat_hunting.infrastructure.storage.sqlalchemy_repo import (
    SqlAlchemyUnitOfWork,
    build_engine,
)


def _make_uow(settings: PlatformSettings) -> UnitOfWorkPort:
    """Build the configured Unit of Work (Factory for storage backends)."""
    backend = settings.storage.backend.lower()
    if backend in ("sqlite", "postgresql", "postgres"):
        return SqlAlchemyUnitOfWork(build_engine(settings.storage.dsn))
    if backend == "json":
        return JsonUnitOfWork(settings.storage.json_path)
    return InMemoryUnitOfWork()


def _make_detection_engine(settings: PlatformSettings) -> DetectionEngine:
    """Load rules + watchlists from config and build the detection engine."""
    rules = YamlRuleRepository(settings.rules_dir).load()
    watchlists = YamlWatchlistRepository(settings.watchlists_path).load()
    return DetectionEngine(rules=rules, watchlists=watchlists)


class Container(containers.DeclarativeContainer):
    """The platform composition root (dependency-injector)."""

    settings = providers.Dependency(instance_of=PlatformSettings)

    metrics = providers.Singleton(
        Metrics,
        enabled=settings.provided.observability.metrics_enabled,
    )

    transport_factory = providers.Singleton(TransportFactory, settings=settings)

    registry = providers.Singleton(
        ConnectorRegistry,
        settings=settings,
        transport_factory=transport_factory,
    )

    parser = providers.Singleton(HtmlTextParser)
    normalizer = providers.Singleton(DefaultNormalizer)
    detection = providers.Singleton(_make_detection_engine, settings)
    scoring = providers.Singleton(
        WeightedScoringEngine, weights=settings.provided.scoring
    )
    correlation = providers.Singleton(CorrelationEngine)
    deduplication = providers.Singleton(
        DeduplicationEngine,
        similarity_threshold=settings.provided.dedup_similarity_threshold,
    )
    enrichment = providers.Singleton(EnrichmentEngine)

    uow = providers.Singleton(_make_uow, settings)
    event_bus = providers.Singleton(InMemoryEventBus)
    exporter_factory = providers.Singleton(
        ExporterFactory, settings=settings.provided.export
    )
    health_checker = providers.Singleton(HealthChecker, registry=registry)


def build_container(settings_path: str | Path | None = "config/settings.yml") -> Container:
    """Build and fully wire a :class:`Container` from configuration.

    This performs the side-effecting wiring (logging, event subscribers, IOC
    extractor injection) that declarative providers cannot express cleanly, and
    returns a ready-to-use container.
    """
    settings = load_settings(settings_path)
    configure_logging(
        level=settings.observability.log_level,
        json_logs=settings.observability.json_logs,
    )
    container = Container(settings=settings)

    # Discover connectors (Plugin pattern).
    container.registry().discover()

    # Wire Observer subscribers onto the bus.
    bus = container.event_bus()
    AuditLogSubscriber().register(bus)
    MetricsSubscriber(container.metrics()).register(bus)

    return container


def build_pipeline(container: Container) -> Pipeline:
    """Assemble the collection pipeline from wired components."""
    from threat_hunting.infrastructure.extractors.ioc_extractor import (
        RegexIOCExtractor,
    )

    settings: PlatformSettings = container.settings()
    exporters = container.exporter_factory().auto_export_targets()
    return Pipeline(
        parser=container.parser(),
        extractor=RegexIOCExtractor(),
        normalizer=container.normalizer(),
        detection=container.detection(),
        scoring=container.scoring(),
        correlation=container.correlation(),
        deduplication=container.deduplication(),
        enrichment=container.enrichment(),
        uow=container.uow(),
        event_bus=container.event_bus(),
        exporters=exporters,
        auto_export_threshold=settings.export.auto_export_threshold,
    )


def build_run_hunt_use_case(container: Container) -> RunHuntUseCase:
    """Assemble the RunHunt use case with the registry as resolver."""
    registry = container.registry()
    return RunHuntUseCase(
        pipeline=build_pipeline(container),
        resolve_connector=registry.create,
        list_connectors=registry.enabled_connectors,
    )


def build_export_use_case(container: Container) -> ExportFindingsUseCase:
    """Assemble the ExportFindings use case with all exporters."""
    return ExportFindingsUseCase(
        uow=container.uow(),
        exporters=container.exporter_factory().build_all(),
    )
