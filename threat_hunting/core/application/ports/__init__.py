"""Ports: the abstract contracts the application depends on.

These are the *interfaces* of Hexagonal Architecture. The application layer
programs against them; infrastructure supplies the implementations. Grouping
them in one package makes the platform's seams explicit and easy to mock in
tests.
"""

from threat_hunting.core.application.ports.connector import ConnectorPort
from threat_hunting.core.application.ports.event_bus import EventBusPort, EventHandler
from threat_hunting.core.application.ports.exporter import ExporterPort
from threat_hunting.core.application.ports.pipeline_stages import (
    CorrelationEnginePort,
    DeduplicationEnginePort,
    DetectionEnginePort,
    EnrichmentEnginePort,
    ExtractorPort,
    NormalizerPort,
    ParserPort,
    ScoringEnginePort,
)
from threat_hunting.core.application.ports.repository import (
    FindingRepositoryPort,
    UnitOfWorkPort,
)
from threat_hunting.core.application.ports.rules import (
    RuleRepositoryPort,
    WatchlistRepositoryPort,
)
from threat_hunting.core.application.ports.transport import (
    TransportFactoryPort,
    TransportPort,
    TransportResponse,
)

__all__ = [
    "ConnectorPort",
    "CorrelationEnginePort",
    "DeduplicationEnginePort",
    "DetectionEnginePort",
    "EnrichmentEnginePort",
    "EventBusPort",
    "EventHandler",
    "ExporterPort",
    "ExtractorPort",
    "FindingRepositoryPort",
    "NormalizerPort",
    "ParserPort",
    "RuleRepositoryPort",
    "ScoringEnginePort",
    "TransportFactoryPort",
    "TransportPort",
    "TransportResponse",
    "UnitOfWorkPort",
    "WatchlistRepositoryPort",
]
