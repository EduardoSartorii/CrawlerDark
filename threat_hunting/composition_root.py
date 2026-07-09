"""Composition Root — wiring central de todos os componentes.

Este é o ÚNICO local que instancia adapters concretos e os injeta na
application layer. A composição segue estritamente a Regra de Dependência:
tudo depende de abstrações do ``core/domain/ports``.

Uso típico::

    root = CompositionRoot.from_config_dir("config")
    await root.startup()
    ...
    await root.shutdown()
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from .core.application.events import InMemoryEventBus
from .core.application.pipeline import (
    CanonicalizeStage,
    CorrelateStage,
    DeduplicateStage,
    DetectStage,
    EnrichStage,
    ExportStage,
    ExtractStage,
    NormalizeStage,
    ParseStage,
    PersistStage,
    PipelineOrchestrator,
    PipelineStage,
    ScoreStage,
)
from .core.application.use_cases import (
    ExportFindingsUseCase,
    HealthCheckUseCase,
    RunConnectorPipelineUseCase,
)
from .core.domain.entities import WatchlistItem, WatchlistKind
from .core.domain.ports import ExporterPort
from .infrastructure.config import ConfigLoader
from .infrastructure.config.schemas import Settings
from .infrastructure.connectors import (
    ConnectorFactory,
    ConnectorRegistry,
)
from .infrastructure.connectors.base import BaseConnector
from .infrastructure.correlation import GraphCorrelationEngine
from .infrastructure.deduplication import HashDeduplicationEngine
from .infrastructure.detections import (
    CompositeDetectionEngine,
    IOCListDetector,
    KeywordDetector,
    RegexDetector,
    SigmaKeywordDetector,
    YaraDetector,
)
from .infrastructure.enrichment import CompositeEnrichmentEngine, NoopEnrichmentEngine
from .infrastructure.exporters import ExporterFactory
from .infrastructure.extractors import (
    CardExtractor,
    CompositeExtractor,
    CredentialExtractor,
    DocumentExtractor,
    IOCExtractor,
    WalletExtractor,
)
from .infrastructure.normalizers import CanonicalNormalizer
from .infrastructure.observability import Metrics, configure_logging, configure_tracing
from .infrastructure.opsec import EnvCredentials
from .infrastructure.scheduler import APSchedulerAdapter
from .infrastructure.scoring import WeightedScoringEngine
from .infrastructure.storage import StorageFactory


class CompositionRoot:
    """Container central de dependências."""

    def __init__(self, config_dir: str | Path = "config") -> None:
        self.loader = ConfigLoader(config_dir)
        self.settings: Settings = self.loader.load_settings()
        self.credentials = EnvCredentials()

        # Observabilidade
        configure_logging(
            level=self.settings.logging.level,
            json_output=self.settings.logging.json_output,
            redact_keys=self.settings.logging.redact_keys,
        )
        configure_tracing(
            enabled=self.settings.observability.opentelemetry.enabled,
            endpoint=self.settings.observability.opentelemetry.endpoint,
            service_name=self.settings.observability.opentelemetry.service_name,
        )
        self.metrics = Metrics()

        # Storage
        self.storage = StorageFactory(self.settings.storage)
        self.uow_factory: Callable[[], Any] = self.storage.uow_factory()

        # Event bus
        self.event_bus = InMemoryEventBus()

        # Watchlists e regras
        self._watchlists = self.loader.load_watchlists()
        self._scoring_config = self.loader.load_scoring()

        # Engines
        watchlist_items = self._build_watchlist_items()
        detection_engine = CompositeDetectionEngine(
            [
                RegexDetector(
                    self.loader.load_regex_rules(self._watchlists.regex_rules_file)
                    if self._watchlists.regex_rules_file
                    else []
                ),
                KeywordDetector(watchlist_items),
                IOCListDetector(self._watchlists.ioc_lists),
                YaraDetector(self._watchlists.yara_rules_dir or ""),
                SigmaKeywordDetector(self._watchlists.sigma_rules_dir or ""),
            ]
        )
        scoring_engine = WeightedScoringEngine(self._scoring_config)
        correlation_engine = GraphCorrelationEngine()
        deduplication_engine = HashDeduplicationEngine()
        enrichment_engine = CompositeEnrichmentEngine([NoopEnrichmentEngine()])
        extractor = CompositeExtractor(
            [
                IOCExtractor(),
                CredentialExtractor(),
                CardExtractor(),
                WalletExtractor(),
                DocumentExtractor(),
            ]
        )
        normalizer = CanonicalNormalizer()

        # Exporters
        exporter_configs = self.loader.load_exporters()
        self.exporters: dict[str, ExporterPort] = ExporterFactory().build_all(exporter_configs)

        # Auto-export targets
        autoexport_targets = [
            self.exporters[name]
            for name in self.settings.exporters.autoexport_targets
            if name in self.exporters
        ]

        # Pipeline
        stages_by_name: dict[str, PipelineStage] = {
            "parse": ParseStage(),
            "normalize": NormalizeStage(),
            "extract": ExtractStage(extractor),
            "canonicalize": CanonicalizeStage(normalizer),
            "detect": DetectStage(detection_engine),
            "score": ScoreStage(scoring_engine, self.event_bus),
            "correlate": CorrelateStage(correlation_engine, self.uow_factory),
            "deduplicate": DeduplicateStage(deduplication_engine, self.uow_factory, self.event_bus),
            "enrich": EnrichStage(enrichment_engine, self.event_bus),
            "persist": PersistStage(self.uow_factory, self.event_bus),
            "export": ExportStage(
                autoexport_targets,
                self.event_bus,
                threshold=self.settings.exporters.autoexport_score_threshold,
            ),
        }
        ordered = [
            stages_by_name[name]
            for name in self.settings.pipeline.stages
            if name in stages_by_name and name not in self.settings.pipeline.disabled
        ]
        self.orchestrator = PipelineOrchestrator(ordered, self.event_bus)

        # Use cases
        self.run_connector_uc = RunConnectorPipelineUseCase(self.orchestrator, self.uow_factory)
        self.export_findings_uc = ExportFindingsUseCase(self.uow_factory)
        self.health_uc = HealthCheckUseCase()

        # Connectors
        self._connector_configs = self.loader.load_connectors()
        ConnectorRegistry.discover()
        self.connector_factory = ConnectorFactory(self.settings.opsec)

        # Scheduler
        self.scheduler = APSchedulerAdapter(timezone=self.settings.scheduler.timezone)

        # Métricas HTTP
        if self.settings.observability.prometheus.enabled:
            try:
                self.metrics.start_http_exporter(self.settings.observability.prometheus.port)
            except OSError:
                # Porta já em uso (uso paralelo em testes) — ignore
                pass

    # --- Helpers públicos ---------------------------------------------------

    def build_connector(self, name: str) -> BaseConnector:
        cfg = self._connector_configs.get(name)
        if cfg is None:
            raise KeyError(f"Connector not configured: {name}")
        return self.connector_factory.build(name, cfg)

    def enabled_connector_names(self) -> list[str]:
        return [name for name, cfg in self._connector_configs.items() if cfg.enabled]

    def all_connector_names(self) -> list[str]:
        return list(self._connector_configs.keys())

    def is_connector_enabled(self, name: str) -> bool:
        cfg = self._connector_configs.get(name)
        return bool(cfg and cfg.enabled)

    async def create_schema(self) -> None:
        await self.storage.create_schema()
        await self._seed_watchlist_if_empty()

    async def shutdown(self) -> None:
        await self.scheduler.shutdown()
        await self.storage.dispose()

    # --- Internals ----------------------------------------------------------

    def _build_watchlist_items(self) -> list[WatchlistItem]:
        items: list[WatchlistItem] = []
        for k in self._watchlists.keywords:
            items.append(WatchlistItem(kind=WatchlistKind.KEYWORD, value=k))
        for b in self._watchlists.brands:
            items.append(WatchlistItem(kind=WatchlistKind.BRAND, value=b))
        for vip in self._watchlists.vips:
            items.append(WatchlistItem(kind=WatchlistKind.VIP, value=vip.name, aliases=set(vip.aliases)))
        for e in self._watchlists.executives:
            items.append(WatchlistItem(kind=WatchlistKind.EXECUTIVE, value=e))
        for d in self._watchlists.domains:
            items.append(WatchlistItem(kind=WatchlistKind.DOMAIN, value=d))
        for e in self._watchlists.emails:
            items.append(WatchlistItem(kind=WatchlistKind.EMAIL, value=e))
        for a in self._watchlists.threat_actors:
            items.append(
                WatchlistItem(kind=WatchlistKind.THREAT_ACTOR, value=a, tags={f"actor:{a.lower()}"})
            )
        for w in self._watchlists.wallets_btc:
            items.append(WatchlistItem(kind=WatchlistKind.WALLET, value=w))
        for w in self._watchlists.wallets_eth:
            items.append(WatchlistItem(kind=WatchlistKind.WALLET, value=w))
        for h in self._watchlists.telegram_handles:
            items.append(WatchlistItem(kind=WatchlistKind.TELEGRAM, value=h))
        for h in self._watchlists.github_handles:
            items.append(WatchlistItem(kind=WatchlistKind.GITHUB, value=h))
        for c in self._watchlists.cpf:
            items.append(WatchlistItem(kind=WatchlistKind.CPF, value=c))
        for c in self._watchlists.cnpj:
            items.append(WatchlistItem(kind=WatchlistKind.CNPJ, value=c))
        return items

    async def _seed_watchlist_if_empty(self) -> None:
        items = self._build_watchlist_items()
        if not items:
            return
        async with self.uow_factory() as uow:
            existing = list(await uow.watchlists.list(limit=1))
            if existing:
                return
            await uow.watchlists.bulk_replace(items)
            await uow.commit()
