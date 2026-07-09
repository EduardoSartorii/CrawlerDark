"""Dependency Injection container using dependency-injector."""

from __future__ import annotations

from pathlib import Path

from dependency_injector import containers, providers

from threat_hunting.config.settings import PlatformConfig
from threat_hunting.core.application.handlers import (
    ConnectorConfigHandler,
    ExportHandler,
    RunAllConnectorsHandler,
    RunConnectorGroupHandler,
    RunConnectorHandler,
    ScoreTestHandler,
)
from threat_hunting.core.domain.entities import DetectionRule, WatchlistEntry
from threat_hunting.infrastructure.correlation.engine import CorrelationEngine
from threat_hunting.infrastructure.database.repositories import (
    InMemoryScoreProfileRepository,
    SqlAlchemyAuditRepository,
    SqlAlchemyConnectorConfigRepository,
    SqlAlchemyCorrelationRepository,
    SqlAlchemyDetectionRuleRepository,
    SqlAlchemyFindingRepository,
    SqlAlchemyWatchlistRepository,
    init_database,
)
from threat_hunting.infrastructure.deduplication.engine import DeduplicationEngine
from threat_hunting.infrastructure.detections.engine import DetectionEngine
from threat_hunting.infrastructure.enrichment.engine import EnrichmentEngine
from threat_hunting.infrastructure.exporters.base import (
    CsvExporter,
    JsonExporter,
    MispExporter,
    OpenSearchExporter,
    SplunkExporter,
    StixExporter,
    WebhookExporter,
)
from threat_hunting.infrastructure.extractors.ioc import IocExtractor
from threat_hunting.infrastructure.normalizers.finding import FindingNormalizer
from threat_hunting.infrastructure.parsers.generic import GenericParser
from threat_hunting.infrastructure.pipelines.event_bus import InProcessEventBus
from threat_hunting.infrastructure.pipelines.orchestrator import PipelineOrchestrator
from threat_hunting.infrastructure.plugins.discovery import ConnectorRegistry
from threat_hunting.infrastructure.scheduler.jobs import HuntScheduler
from threat_hunting.infrastructure.scoring.engine import ScoringEngine
from threat_hunting.infrastructure.storage.backends import StorageFactory


class Container(containers.DeclarativeContainer):
    """DI container wiring all platform components."""

    config = providers.Singleton(
        PlatformConfig.from_yaml,
        path=str(Path(__file__).parent / "platform.yaml"),
    )

    wiring_config = containers.WiringConfiguration(
        modules=["threat_hunting.cli.main"],
    )


async def bootstrap(database_url: str | None = None) -> dict:
    """Bootstrap all platform dependencies and return wired components."""
    import yaml

    config = PlatformConfig.from_yaml(Path(__file__).parent / "platform.yaml")
    db_url = database_url or config.database.url
    if db_url.startswith("sqlite") and ":///" in db_url:
        db_path = db_url.split("///", 1)[1]
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    engine, session_factory = await init_database(db_url)

    session = session_factory()
    finding_repo = SqlAlchemyFindingRepository(session)
    watchlist_repo = SqlAlchemyWatchlistRepository(session)
    rule_repo = SqlAlchemyDetectionRuleRepository(session)
    score_repo = InMemoryScoreProfileRepository()
    correlation_repo = SqlAlchemyCorrelationRepository(session)
    connector_config_repo = SqlAlchemyConnectorConfigRepository(session)
    audit_repo = SqlAlchemyAuditRepository(session)

    # Load rules from YAML
    rules_path = Path(__file__).parent / "detection_rules.yaml"
    if rules_path.exists():
        with open(rules_path) as f:
            rules_data = yaml.safe_load(f) or {}
        for rule_data in rules_data.get("rules", []):
            rule = DetectionRule(**rule_data)
            await rule_repo.save(rule)

    # Load watchlists from YAML
    watchlists_path = Path(__file__).parent / "watchlists.yaml"
    if watchlists_path.exists():
        with open(watchlists_path) as f:
            wl_data = yaml.safe_load(f) or {}
        for entry_data in wl_data.get("watchlists", []):
            entry = WatchlistEntry(**entry_data)
            await watchlist_repo.save(entry)

    await session.commit()

    # Connectors
    registry = ConnectorRegistry()
    registry.discover()

    # Pipeline components
    parser = GenericParser()
    extractor = IocExtractor()
    normalizer = FindingNormalizer()
    detection = DetectionEngine(rule_repo, watchlist_repo)
    scoring = ScoringEngine(score_repo)
    correlation = CorrelationEngine(correlation_repo, finding_repo)
    dedup = DeduplicationEngine()
    enrichment = EnrichmentEngine()

    # Exporters
    exporters = {
        "json": JsonExporter(),
        "csv": CsvExporter(),
        "stix": StixExporter(),
        "misp": MispExporter(config.export.misp_url, config.export.misp_api_key, config.export.misp_event_id),
        "splunk": SplunkExporter(config.export.splunk_hec_url, config.export.splunk_token),
        "elastic": OpenSearchExporter(config.export.elastic_url),
        "webhook": WebhookExporter(config.export.webhook_url),
    }

    # Event bus
    event_bus = InProcessEventBus()

    # Storage
    storage = StorageFactory.create(config.storage.backend, finding_repo=finding_repo)

    # Pipeline
    pipeline = PipelineOrchestrator(
        parser=parser,
        extractor=extractor,
        normalizer=normalizer,
        detection_engine=detection,
        scoring_engine=scoring,
        correlation_engine=correlation,
        dedup_engine=dedup,
        enrichment_engine=enrichment,
        storage=storage,
        finding_repo=finding_repo,
        event_bus=event_bus,
        exporters=exporters,
        score_profile_repo=score_repo,
    )

    # Handlers
    run_handler = RunConnectorHandler(registry, pipeline, connector_config_repo, event_bus)
    run_group_handler = RunConnectorGroupHandler(run_handler)
    run_all_handler = RunAllConnectorsHandler(registry, run_handler)
    connector_config_handler = ConnectorConfigHandler(connector_config_repo, audit_repo)
    export_handler = ExportHandler(exporters, finding_repo, event_bus)
    score_test_handler = ScoreTestHandler(scoring)

    scheduler = HuntScheduler()

    return {
        "config": config,
        "registry": registry,
        "pipeline": pipeline,
        "event_bus": event_bus,
        "run_handler": run_handler,
        "run_group_handler": run_group_handler,
        "run_all_handler": run_all_handler,
        "connector_config_handler": connector_config_handler,
        "export_handler": export_handler,
        "score_test_handler": score_test_handler,
        "scheduler": scheduler,
        "session_factory": session_factory,
        "engine": engine,
    }
