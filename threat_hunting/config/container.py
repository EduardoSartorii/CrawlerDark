"""Dependency-injection composition root.

Responsibility
--------------
Build and wire the entire object graph from :class:`Settings`, connecting
concrete infrastructure adapters to the core ports in exactly one place
(Dependency Injection / Composition Root). Nothing else in the codebase
constructs cross-layer dependencies.

The container is a hand-rolled, lazy provider graph so the platform has zero
hard dependency on any DI framework; it can be transparently backed by
``dependency-injector`` where that library is desired (each ``_build_*`` method
maps 1:1 to a provider). Objects are memoised so callers share singletons.
"""

from __future__ import annotations

from functools import cached_property
from pathlib import Path

from threat_hunting.config.settings import Settings, load_settings
from threat_hunting.core.application.pipeline.orchestrator import PipelineOrchestrator
from threat_hunting.core.application.ports.keyword_provider import KeywordProvider
from threat_hunting.core.application.ports.repository import UnitOfWork
from threat_hunting.core.application.services.export_service import ExportService
from threat_hunting.core.application.services.run_collection import RunCollectionService
from threat_hunting.infrastructure.connectors.registry import ConnectorRegistry
from threat_hunting.infrastructure.deduplication.engine import DeduplicationEngine
from threat_hunting.infrastructure.detections.engine import DetectionEngine
from threat_hunting.infrastructure.detections.loader import RuleLoader
from threat_hunting.infrastructure.enrichment.engine import EnrichmentEngine
from threat_hunting.infrastructure.enrichment.providers import DefangProvider, GeoTagProvider
from threat_hunting.infrastructure.events.bus import InMemoryEventBus
from threat_hunting.infrastructure.events.subscribers import (
    AuditLogSubscriber,
    AutoExportSubscriber,
)
from threat_hunting.infrastructure.exporters.factory import ExporterFactory
from threat_hunting.infrastructure.keywords.provider import (
    InMemoryKeywordProvider,
    YamlKeywordProvider,
)
from threat_hunting.infrastructure.observability.health import HealthCheck
from threat_hunting.infrastructure.observability.logging import configure_logging, get_logger
from threat_hunting.infrastructure.observability.metrics import Metrics
from threat_hunting.infrastructure.observability.tracing import Tracer
from threat_hunting.infrastructure.opsec.manager import OpsecManager
from threat_hunting.infrastructure.pipeline.factory import build_default_pipeline
from threat_hunting.infrastructure.scoring.engine import ScoringEngine
from threat_hunting.infrastructure.storage.factory import StorageFactory
from threat_hunting.core.domain.enums import EventName


class Container:
    """Lazy, memoised composition root wiring adapters to core ports."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or load_settings()
        configure_logging(
            level=self.settings.observability.log_level,
            json_output=self.settings.observability.json_logs,
        )

    # -- observability ----------------------------------------------------
    @cached_property
    def logger(self):
        """Shared structured logger."""
        return get_logger(self.settings.observability.service_name)

    @cached_property
    def metrics(self) -> Metrics:
        """Shared metrics registry."""
        return Metrics()

    @cached_property
    def tracer(self) -> Tracer:
        """Shared tracer facade."""
        return Tracer(self.settings.observability.service_name)

    # -- opsec / connectors ----------------------------------------------
    @cached_property
    def opsec(self) -> OpsecManager:
        """OPSEC manager built from the configured profiles."""
        return OpsecManager(
            profiles=dict(self.settings.opsec.profiles),
            connector_profiles=dict(self.settings.opsec.connector_profiles),
            offline=self.settings.opsec.offline,
        )

    @cached_property
    def registry(self) -> ConnectorRegistry:
        """Discovered connector registry with enable/disable overrides."""
        registry = ConnectorRegistry(
            opsec=self.opsec, enabled_overrides=dict(self.settings.connectors_enabled)
        )
        registry.discover()
        return registry

    # -- keywords / engines ----------------------------------------------
    @cached_property
    def keyword_provider(self) -> KeywordProvider:
        """Keyword provider from YAML when present, else an empty in-memory one."""
        watchlists = Path(self.settings.watchlists_file)
        if watchlists.exists():
            return YamlKeywordProvider(watchlists)
        return InMemoryKeywordProvider()

    @cached_property
    def detection_engine(self) -> DetectionEngine:
        """Detection engine with rules loaded dynamically from config + keywords."""
        loader = RuleLoader(self.keyword_provider)
        rules = loader.load(
            regex_rules=self.settings.detection_regex_rules,
            yara_rules=self.settings.yara_rules,
        )
        return DetectionEngine(
            rules,
            whitelist=self.settings.detection_whitelist,
            blacklist=self.settings.detection_blacklist,
            min_matches=self.settings.detection_min_matches,
        )

    @cached_property
    def scoring_engine(self) -> ScoringEngine:
        """Scoring engine using the configured weights."""
        return ScoringEngine(self.settings.scoring)

    @cached_property
    def enrichment_engine(self) -> EnrichmentEngine:
        """Enrichment engine with the built-in offline providers."""
        return EnrichmentEngine([GeoTagProvider(), DefangProvider()])

    @cached_property
    def deduplication_engine(self) -> DeduplicationEngine:
        """Deduplication engine (default strategies)."""
        return DeduplicationEngine()

    # -- storage / events / exporters ------------------------------------
    @cached_property
    def unit_of_work(self) -> UnitOfWork:
        """Unit of work for the configured storage backend."""
        return StorageFactory.build(
            self.settings.storage.backend, path=self.settings.storage.path
        )

    @cached_property
    def event_bus(self) -> InMemoryEventBus:
        """Event bus with audit and (optional) auto-export subscribers wired."""
        bus = InMemoryEventBus()
        bus.subscribe(EventName.PIPELINE_COMPLETED, AuditLogSubscriber(self.logger))
        bus.subscribe(EventName.FINDING_PERSISTED, AuditLogSubscriber(self.logger))
        if self.settings.export.auto_export_enabled:
            exporter = self.build_exporter(self.settings.export.auto_export_target)
            bus.subscribe(
                EventName.HIGH_SEVERITY_FINDING_DETECTED, AutoExportSubscriber(exporter)
            )
        return bus

    def build_exporter(self, name: str):
        """Factory helper building an exporter with OPSEC transport when needed."""
        options: dict[str, object] = {"transport": self.opsec.transport_for("exporter")}
        out_dir = self.settings.export.output_dir
        if name == "json":
            options["path"] = f"{out_dir}/findings.json"
        elif name == "csv":
            options["path"] = f"{out_dir}/findings.csv"
        elif name == "stix":
            options["path"] = f"{out_dir}/findings.stix.json"
        return ExporterFactory.build(name, **options)

    # -- pipeline / services ---------------------------------------------
    def build_pipeline(self) -> PipelineOrchestrator:
        """Assemble the default ordered pipeline for a run."""
        return build_default_pipeline(
            detection_engine=self.detection_engine,
            scoring_engine=self.scoring_engine,
            enrichment_engine=self.enrichment_engine,
            unit_of_work=self.unit_of_work,
            event_bus=self.event_bus,
            export_threshold=self.settings.export.score_threshold,
        )

    @cached_property
    def run_collection_service(self) -> RunCollectionService:
        """The primary collection use-case service."""
        return RunCollectionService(
            registry=self.registry,
            orchestrator=self.build_pipeline(),
            event_bus=self.event_bus,
        )

    @cached_property
    def export_service(self) -> ExportService:
        """The export use-case service exposing all built-in exporters."""
        exporters = {name: self.build_exporter(name) for name in ExporterFactory.available()}
        return ExportService(self.unit_of_work, exporters)

    @cached_property
    def health_check(self) -> HealthCheck:
        """Health check aggregator wired with the connector registry."""
        check = HealthCheck(registry=self.registry)

        def storage_probe() -> tuple[bool, str]:
            try:
                with self.unit_of_work as uow:
                    return True, f"{uow.findings.count()} findings"
            except Exception as exc:  # pragma: no cover - defensive
                return False, str(exc)

        check.add_probe("storage", storage_probe)
        return check
