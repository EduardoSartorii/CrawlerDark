"""Dependency Injection container (dependency-injector).

Responsibility
--------------
Wire all adapters to ports. Composition root — the ONLY place that knows
about both Core and Infrastructure. Connectors discovered via Plugin registry.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from dependency_injector import containers, providers

from threat_hunting.connectors.registry import ConnectorFactory, get_registry
from threat_hunting.core.application.pipeline import PipelineOrchestrator
from threat_hunting.core.application.use_cases import (
    ConnectorLifecycleHandler,
    ExportFindingsHandler,
    HealthCheckHandler,
    RunHuntHandler,
    ScoreTestHandler,
)
from threat_hunting.correlation.engine import CorrelationEngine
from threat_hunting.deduplication.engine import DeduplicationEngine
from threat_hunting.detections.engine import DetectionEngine
from threat_hunting.enrichment.engine import EnrichmentEngine
from threat_hunting.exporters import AutoMispExportHandler, ExporterFactory
from threat_hunting.extractors.ioc_extractor import IocExtractor
from threat_hunting.infrastructure.config.loader import (
    load_opsec_profiles,
    load_settings,
)
from threat_hunting.infrastructure.messaging.event_bus import InMemoryEventBus
from threat_hunting.infrastructure.observability import (
    LoggingEventHandler,
    OpenTelemetryTracer,
    PlatformHealthCheck,
    PrometheusMetrics,
    StructlogAudit,
    configure_logging,
)
from threat_hunting.infrastructure.opsec.transport import (
    HttpxOpsecTransport,
    InMemoryCredentialVault,
    TokenBucketRateLimiter,
)
from threat_hunting.infrastructure.persistence.memory import InMemoryUnitOfWork
from threat_hunting.parsers.passthrough import DefaultNormalizer, PassthroughParser
from threat_hunting.scoring.engine import ScoringEngine


class Container(containers.DeclarativeContainer):
    """Composition root for the Threat Hunting platform."""

    config = providers.Configuration()

    settings = providers.Singleton(load_settings, config.config_dir)

    logging_setup = providers.Resource(
        lambda settings: configure_logging(
            json_logs=settings.observability.json_logs,
            level=settings.observability.log_level,
        )
        or True,
        settings=settings,
    )

    event_bus = providers.Singleton(InMemoryEventBus)

    metrics = providers.Singleton(PrometheusMetrics)

    tracer = providers.Singleton(
        OpenTelemetryTracer,
        service_name="threat-hunting",
        console=False,
    )

    audit = providers.Singleton(StructlogAudit, event_bus=event_bus)

    health = providers.Singleton(PlatformHealthCheck)

    vault = providers.Singleton(InMemoryCredentialVault)

    rate_limiter = providers.Singleton(TokenBucketRateLimiter)

    transport = providers.Singleton(
        HttpxOpsecTransport,
        rate_limiter=rate_limiter,
        vault=vault,
    )

    opsec_profiles = providers.Singleton(load_opsec_profiles, config.config_dir)

    uow = providers.Singleton(InMemoryUnitOfWork)

    parser = providers.Singleton(PassthroughParser)
    extractor = providers.Singleton(IocExtractor)
    normalizer = providers.Singleton(DefaultNormalizer)

    detection_engine = providers.Singleton(
        DetectionEngine,
        config_dir=providers.Callable(
            lambda d: str(Path(d) / "detection"), config.config_dir
        ),
    )

    scoring_engine = providers.Singleton(
        ScoringEngine,
        config_path=providers.Callable(
            lambda d: str(Path(d) / "scoring.yaml"), config.config_dir
        ),
    )

    correlation_engine = providers.Singleton(CorrelationEngine, uow=uow)
    deduplication_engine = providers.Singleton(DeduplicationEngine, uow=uow)
    enrichment_engine = providers.Singleton(EnrichmentEngine)

    connector_registry = providers.Singleton(get_registry)

    connector_factory = providers.Singleton(
        ConnectorFactory,
        registry=connector_registry,
        transport=transport,
        opsec_profiles=opsec_profiles,
    )

    exporter_factory = providers.Factory(
        ExporterFactory,
        misp_url=providers.Callable(lambda s: s.misp.url, settings),
        misp_key=providers.Callable(lambda s: s.misp.key, settings),
    )

    pipeline = providers.Singleton(
        PipelineOrchestrator,
        parser=parser,
        extractor=extractor,
        normalizer=normalizer,
        detection=detection_engine,
        scoring=scoring_engine,
        correlation=correlation_engine,
        deduplication=deduplication_engine,
        enrichment=enrichment_engine,
        uow=uow,
        event_bus=event_bus,
        metrics=metrics,
        score_export_threshold=providers.Callable(
            lambda s: s.score_export_threshold, settings
        ),
    )

    run_hunt_handler = providers.Factory(
        RunHuntHandler,
        connector_factory=connector_factory,
        pipeline=pipeline,
        audit=audit,
        event_bus=event_bus,
    )

    connector_lifecycle_handler = providers.Factory(
        ConnectorLifecycleHandler,
        uow=uow,
        audit=audit,
    )

    export_handler = providers.Factory(
        ExportFindingsHandler,
        exporter_factory=exporter_factory,
        uow=uow,
        event_bus=event_bus,
        audit=audit,
    )

    score_test_handler = providers.Factory(
        ScoreTestHandler,
        scoring=scoring_engine,
        detection=detection_engine,
    )

    health_handler = providers.Factory(HealthCheckHandler, health=health)


def bootstrap(config_dir: str = "config") -> Container:
    """Bootstrap DI container, discover connectors, wire event handlers."""
    container = Container()
    container.config.config_dir.from_value(config_dir)
    # Force logging setup
    _ = container.logging_setup()

    # Discover connectors (Plugin Pattern)
    registry = container.connector_registry()
    registry.discover()

    # Wire observers
    event_bus = container.event_bus()
    event_bus.subscribe("*", LoggingEventHandler())
    auto_misp = AutoMispExportHandler(
        container.exporter_factory(),
        event_bus=event_bus,
    )
    event_bus.subscribe("ScoreThresholdExceeded", auto_misp)

    # Health checks
    health = container.health()

    async def _event_bus_health() -> Any:
        from threat_hunting.core.domain.enums import HealthState
        from threat_hunting.core.domain.value_objects import HealthStatus, utc_now

        return HealthStatus(
            component="event_bus",
            state=HealthState.HEALTHY.value,
            message=f"{len(event_bus.history)} events",
            checked_at=utc_now(),
        )

    health.register(_event_bus_health)

    async def _connectors_health() -> Any:
        from threat_hunting.core.domain.enums import HealthState
        from threat_hunting.core.domain.value_objects import HealthStatus, utc_now

        names = list(container.connector_factory().list_available())
        return HealthStatus(
            component="connectors",
            state=HealthState.HEALTHY.value,
            message=f"{len(names)} registered",
            details={"connectors": names},
            checked_at=utc_now(),
        )

    health.register(_connectors_health)

    return container


__all__ = ["Container", "bootstrap"]
