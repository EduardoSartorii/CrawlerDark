"""Dependency injection container wiring application and infrastructure."""

from __future__ import annotations

import os
from pathlib import Path

from dependency_injector import containers, providers

from threat_hunting.application.factories import ConnectorFactory, ExporterFactory
from threat_hunting.application.observers import LoggingObserver, MetricsObserver
from threat_hunting.application.commands import RunHuntCommand
from threat_hunting.application.use_cases import HuntApplicationService, build_command_bus
from threat_hunting.config.settings import (
    AppSettings,
    load_app_settings,
    load_detection_rules,
    load_opsec_profiles,
    load_scoring_policy,
    load_watchlist,
)
from threat_hunting.core.events import DomainEvent, InMemoryEventBus
from threat_hunting.correlation.engine import EntityCorrelationEngine
from threat_hunting.database.session import create_session_factory
from threat_hunting.deduplication.engine import FingerprintDeduplicationEngine
from threat_hunting.detections.engine import DynamicDetectionEngine
from threat_hunting.enrichment.engine import ContextEnrichmentEngine
from threat_hunting.exporters.implementations import (
    CsvExporter,
    JsonExporter,
    MISPExporter,
    OpenCTIExporter,
    OpenSearchExporter,
    RestAPIExporter,
    STIX21Exporter,
    SplunkExporter,
    TAXII21Exporter,
    WebhookExporter,
)
from threat_hunting.extractors.indicator_extractor import IndicatorExtractor
from threat_hunting.infrastructure.observability.health import HealthCheckRegistry
from threat_hunting.infrastructure.observability.logging import configure_logging
from threat_hunting.infrastructure.observability.metrics import HuntingMetrics
from threat_hunting.infrastructure.observability.tracing import configure_tracing
from threat_hunting.integrations.misp_adapter import MISPAdapter
from threat_hunting.integrations.opencti_adapter import OpenCTIAdapter
from threat_hunting.normalizers.default_normalizer import DefaultNormalizer
from threat_hunting.parsers.default_parser import DefaultParser
from threat_hunting.pipelines.orchestrator import HuntingPipeline
from threat_hunting.plugins.manager import ConnectorPluginManager
from threat_hunting.scheduler.service import SchedulerService
from threat_hunting.scoring.engine import WeightedScoringEngine
from threat_hunting.scoring.strategies import SignalPresenceStrategy, ThreatActorMatchStrategy, VipMatchStrategy
from threat_hunting.storage.repository import SqlAlchemyUnitOfWork


class RuntimeContainer(containers.DeclarativeContainer):
    """Main dependency graph for CLI/API/Scheduler runtime."""

    config_dir = providers.Object(Path("threat_hunting/config"))

    app_settings = providers.Singleton(load_app_settings, config_dir=config_dir)
    watchlist = providers.Singleton(load_watchlist, config_dir=config_dir)
    detection_rules = providers.Singleton(load_detection_rules, config_dir=config_dir)
    scoring_policy = providers.Singleton(load_scoring_policy, config_dir=config_dir)
    opsec_profiles = providers.Singleton(load_opsec_profiles, config_dir=config_dir)

    metrics = providers.Singleton(HuntingMetrics)
    event_bus = providers.Singleton(InMemoryEventBus)
    health_registry = providers.Singleton(HealthCheckRegistry)

    parser = providers.Singleton(DefaultParser)
    extractor = providers.Singleton(IndicatorExtractor)
    normalizer = providers.Singleton(DefaultNormalizer)
    detection_engine = providers.Singleton(
        DynamicDetectionEngine,
        rules=detection_rules,
        watchlist=watchlist,
    )
    scoring_engine = providers.Singleton(
        WeightedScoringEngine,
        policy=scoring_policy,
        watchlist=watchlist,
        strategies=providers.List(
            providers.Factory(SignalPresenceStrategy, signal_name="regex_match"),
            providers.Factory(SignalPresenceStrategy, signal_name="keyword_match"),
            providers.Factory(SignalPresenceStrategy, signal_name="ioc_match"),
            providers.Factory(SignalPresenceStrategy, signal_name="credential_match"),
            providers.Factory(VipMatchStrategy),
            providers.Factory(ThreatActorMatchStrategy),
        ),
    )
    correlation_engine = providers.Singleton(EntityCorrelationEngine)
    dedup_engine = providers.Singleton(FingerprintDeduplicationEngine)
    enrichment_engine = providers.Singleton(ContextEnrichmentEngine)

    session_factory = providers.Singleton(
        create_session_factory,
        database_url=app_settings.provided.database.url,
    )
    uow = providers.Singleton(SqlAlchemyUnitOfWork, session_factory=session_factory)

    plugin_manager = providers.Singleton(ConnectorPluginManager)
    connector_registry = providers.Callable(lambda manager: manager.discover(), manager=plugin_manager)
    connector_factory = providers.Singleton(
        ConnectorFactory,
        registry=connector_registry,
        config=providers.Callable(lambda settings: settings.model_dump(), app_settings),
    )

    misp_adapter = providers.Singleton(
        MISPAdapter,
        url=providers.Callable(lambda: os.getenv("MISP_URL", "")),
        api_key=providers.Callable(lambda: os.getenv("MISP_API_KEY", "")),
        verify_ssl=providers.Callable(lambda: os.getenv("MISP_VERIFY_SSL", "true").lower() == "true"),
    )
    opencti_adapter = providers.Singleton(OpenCTIAdapter)

    exporters_registry = providers.Singleton(
        lambda misp_adapter, opencti_adapter: {
            "json": JsonExporter(),
            "csv": CsvExporter(),
            "misp": MISPExporter(adapter=misp_adapter, event_id=os.getenv("MISP_EVENT_ID")),
            "opencti": OpenCTIExporter(adapter=opencti_adapter),
            "splunk": SplunkExporter(),
            "opensearch": OpenSearchExporter(),
            "webhook": WebhookExporter(),
            "rest_api": RestAPIExporter(),
            "stix21": STIX21Exporter(),
            "taxii21": TAXII21Exporter(),
        },
        misp_adapter=misp_adapter,
        opencti_adapter=opencti_adapter,
    )
    exporter_factory = providers.Singleton(ExporterFactory, registry=exporters_registry)

    scheduler = providers.Singleton(SchedulerService)
    pipeline = providers.Singleton(
        HuntingPipeline,
        parser=parser,
        extractor=extractor,
        normalizer=normalizer,
        detection_engine=detection_engine,
        scoring_engine=scoring_engine,
        correlation_engine=correlation_engine,
        dedup_engine=dedup_engine,
        enrichment_engine=enrichment_engine,
        uow=uow,
        exporters=providers.List(
            providers.Callable(lambda registry: registry["json"], exporters_registry),
            providers.Callable(lambda registry: registry["csv"], exporters_registry),
        ),
        misp_exporter=providers.Callable(lambda registry: registry["misp"], exporters_registry),
        scoring_policy=scoring_policy,
        event_bus=event_bus,
    )
    app_service = providers.Singleton(
        HuntApplicationService,
        connector_factory=connector_factory,
        pipeline=pipeline,
        exporter_factory=exporter_factory,
        uow=uow,
        scoring_engine=scoring_engine,
        scheduler=scheduler,
        event_bus=event_bus,
        runtime_config=providers.Callable(lambda settings: settings.model_dump(), app_settings),
    )
    command_bus = providers.Singleton(build_command_bus, service=app_service)


def bootstrap_container(config_dir: Path | None = None) -> RuntimeContainer:
    """Create and initialize runtime container."""
    container = RuntimeContainer()
    if config_dir is not None:
        container.config_dir.override(providers.Object(config_dir))

    settings: AppSettings = container.app_settings()
    configure_logging(settings.observability.log_level)
    configure_tracing(endpoint=settings.observability.otel_endpoint)

    event_bus = container.event_bus()
    metrics = container.metrics()
    event_bus.subscribe(DomainEvent, LoggingObserver())
    event_bus.subscribe(DomainEvent, MetricsObserver(metrics))

    scheduler = container.scheduler()
    service = container.app_service()
    scheduler.set_run_target(lambda target: service.run_hunt(RunHuntCommand(target=target)))
    return container
