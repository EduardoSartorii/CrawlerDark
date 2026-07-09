"""Dependency Injector container that wires the entire platform."""

from __future__ import annotations

import os
from pathlib import Path

from dependency_injector import containers, providers

from threat_hunting.application.pipeline import HuntingPipeline
from threat_hunting.core.plugin import ConnectorRegistry
from threat_hunting.deduplication.engine import FingerprintDeduplicationEngine
from threat_hunting.detections.engine import DynamicDetectionEngine
from threat_hunting.enrichment.engine import ContextEnrichmentEngine
from threat_hunting.exporters.catalog import (
    CsvExporter,
    ElasticExporter,
    OpenCtiExporter,
    OpenSearchExporter,
    RestApiExporter,
    SplunkExporter,
    StixExporter,
    TaxiiExporter,
    WebhookExporter,
)
from threat_hunting.exporters.json_exporter import JsonExporter
from threat_hunting.exporters.misp import MispExporter
from threat_hunting.extractors.default_extractor import DefaultExtractor
from threat_hunting.infrastructure.config import AppSettings
from threat_hunting.infrastructure.event_bus import InMemoryAuditLog, InMemoryEventBus
from threat_hunting.infrastructure.observability import OpenTelemetryTracer, PrometheusMetrics
from threat_hunting.infrastructure.opsec import InMemoryCredentialProvider, OpsecTransport
from threat_hunting.scoring.engine import WeightedScoringEngine
from threat_hunting.storage.in_memory import (
    InMemoryFindingRepository,
    InMemoryRuleRepository,
    InMemoryUnitOfWork,
)
from threat_hunting.correlation.engine import IndicatorCorrelationEngine


class AppContainer(containers.DeclarativeContainer):
    """Root IoC container for runtime assembly."""

    wiring_config = containers.WiringConfiguration()

    config_path = providers.Callable(
        lambda: Path(os.getenv("THREAT_HUNTING_CONFIG", "config/default.yml"))
    )
    settings = providers.Singleton(AppSettings.from_yaml, path=config_path)

    credential_provider = providers.Singleton(InMemoryCredentialProvider, secrets={})
    opsec_transport = providers.Singleton(
        OpsecTransport,
        profiles=providers.Callable(lambda app_settings: app_settings.opsec_profiles, settings),
        credential_provider=credential_provider,
    )

    finding_repository = providers.Singleton(InMemoryFindingRepository)
    rule_repository = providers.Singleton(
        InMemoryRuleRepository,
        rule_items=providers.Callable(lambda app_settings: app_settings.dynamic_rules, settings),
    )
    uow = providers.Singleton(InMemoryUnitOfWork, findings=finding_repository)

    metrics = providers.Singleton(PrometheusMetrics)
    tracer = providers.Singleton(OpenTelemetryTracer)
    audit = providers.Singleton(InMemoryAuditLog)
    event_bus = providers.Singleton(InMemoryEventBus, audit=audit)

    extractor = providers.Singleton(DefaultExtractor)
    detection_engine = providers.Singleton(DynamicDetectionEngine, rule_repository=rule_repository)
    scoring_engine = providers.Singleton(
        WeightedScoringEngine,
        weights=providers.Callable(lambda app_settings: app_settings.score_weights, settings),
        critical_threshold=providers.Callable(
            lambda app_settings: app_settings.auto_export_threshold,
            settings,
        ),
    )
    correlation_engine = providers.Singleton(IndicatorCorrelationEngine)
    deduplication_engine = providers.Singleton(FingerprintDeduplicationEngine)
    enrichment_engine = providers.Singleton(ContextEnrichmentEngine)

    exporters = providers.List(
        providers.Singleton(MispExporter),
        providers.Singleton(JsonExporter),
        providers.Singleton(OpenCtiExporter),
        providers.Singleton(SplunkExporter),
        providers.Singleton(OpenSearchExporter),
        providers.Singleton(ElasticExporter),
        providers.Singleton(StixExporter),
        providers.Singleton(TaxiiExporter),
        providers.Singleton(WebhookExporter),
        providers.Singleton(RestApiExporter),
        providers.Singleton(CsvExporter),
    )

    pipeline = providers.Singleton(
        HuntingPipeline,
        extractor=extractor,
        detection_engine=detection_engine,
        scoring_engine=scoring_engine,
        correlation_engine=correlation_engine,
        deduplication_engine=deduplication_engine,
        enrichment_engine=enrichment_engine,
        uow=uow,
        exporters=exporters,
        event_bus=event_bus,
        metrics=metrics,
        tracer=tracer,
        auto_export_threshold=providers.Callable(
            lambda app_settings: app_settings.auto_export_threshold,
            settings,
        ),
    )

    connector_registry = providers.Singleton(
        ConnectorRegistry,
        connector_kwargs=providers.Callable(lambda transport: {"transport": transport}, opsec_transport),
    )
