"""
Dependency Injection Container.

Wires together all platform components using dependency-injector.
The container is the single source of truth for how components are assembled.

Architectural Benefit:
    - Components declare their dependencies via constructors
    - The container resolves and injects them
    - Tests can override any provider with mocks
    - No global state or singletons scattered across modules

Container Hierarchy:
    PlatformContainer
    ├── Settings (singleton)
    ├── DatabaseManager (singleton)
    ├── Repositories (factory — new instance per request)
    ├── Engines (singleton)
    │   ├── DetectionEngine
    │   ├── ScoringEngine
    │   ├── CorrelationEngine
    │   └── EnrichmentEngine
    ├── ConnectorRegistry (singleton)
    ├── CollectionScheduler (singleton)
    └── Exporters (factory)

Design Pattern: Dependency Injection Container (IoC)
"""

from __future__ import annotations

from dependency_injector import containers, providers

from ..infrastructure.connectors.base import BaseConnector
from ..infrastructure.correlation.engine import CorrelationEngine
from ..infrastructure.detections.engine import DetectionEngine
from ..infrastructure.enrichment.engine import EnrichmentEngine
from ..infrastructure.exporters.csv_exporter import CSVExporter
from ..infrastructure.exporters.json_exporter import JSONExporter
from ..infrastructure.exporters.misp_exporter import MISPExporter
from ..infrastructure.exporters.stix_exporter import STIX21Exporter
from ..infrastructure.plugins.registry import ConnectorRegistry
from ..infrastructure.scheduler.scheduler import CollectionScheduler
from ..infrastructure.scoring.engine import ScoringEngine, ScoringWeights
from ..infrastructure.storage.database import DatabaseManager
from ..infrastructure.storage.unit_of_work import SQLAlchemyUnitOfWork
from .settings import PlatformSettings


class PlatformContainer(containers.DeclarativeContainer):
    """
    Main dependency injection container for the Threat Hunting Platform.

    Usage:
        container = PlatformContainer()
        container.config.from_pydantic(settings)
        container.wire(modules=[...])
    """

    # ── Configuration ─────────────────────────────────────────────────────────
    config = providers.Configuration()

    # ── Settings ──────────────────────────────────────────────────────────────
    settings = providers.Singleton(
        PlatformSettings,
    )

    # ── Database ──────────────────────────────────────────────────────────────
    database_manager = providers.Singleton(
        DatabaseManager.sqlite,
        path="./data/threat_hunting.db",
    )

    # ── Unit of Work (factory — new per use case invocation) ─────────────────
    unit_of_work = providers.Factory(
        SQLAlchemyUnitOfWork,
        session_factory=database_manager.provided.session_factory,
    )

    # ── Detection Engine ──────────────────────────────────────────────────────
    detection_engine = providers.Singleton(
        DetectionEngine,
    )

    # ── Scoring Engine ────────────────────────────────────────────────────────
    scoring_engine = providers.Singleton(
        ScoringEngine,
        weights=providers.Factory(ScoringWeights),
    )

    # ── Correlation Engine ────────────────────────────────────────────────────
    correlation_engine = providers.Singleton(
        CorrelationEngine,
        min_shared_count=1,
        min_confidence=0.3,
    )

    # ── Enrichment Engine ─────────────────────────────────────────────────────
    enrichment_engine = providers.Singleton(
        EnrichmentEngine,
    )

    # ── Connector Registry ────────────────────────────────────────────────────
    connector_registry = providers.Singleton(
        ConnectorRegistry.create,
    )

    # ── Scheduler ─────────────────────────────────────────────────────────────
    scheduler = providers.Singleton(
        CollectionScheduler,
    )

    # ── Exporters ─────────────────────────────────────────────────────────────
    json_exporter = providers.Factory(JSONExporter)
    csv_exporter = providers.Factory(CSVExporter)
    stix_exporter = providers.Factory(STIX21Exporter)
    misp_exporter = providers.Factory(MISPExporter)
