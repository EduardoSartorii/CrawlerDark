"""Ports (interfaces) — contratos que a infra deve implementar.

Depender de abstrações, não de implementações (SOLID/DIP).
"""

from .clock import ClockPort
from .connector import ConnectorPort
from .credentials import CredentialsPort
from .engines import (
    CorrelationEnginePort,
    DeduplicationEnginePort,
    DetectionEnginePort,
    EnrichmentEnginePort,
    ScoringEnginePort,
)
from .event_bus import EventBusPort
from .exporter import ExporterPort
from .http_client import HTTPClientPort
from .parsers import ExtractorPort, NormalizerPort, ParserPort
from .repositories import (
    DetectionRuleRepositoryPort,
    FindingRepositoryPort,
    IndicatorRepositoryPort,
    JobRepositoryPort,
    RepositoryPort,
    ThreatActorRepositoryPort,
    WatchlistRepositoryPort,
)
from .scheduler import SchedulerPort
from .unit_of_work import UnitOfWorkPort

__all__ = [
    "ClockPort",
    "ConnectorPort",
    "CorrelationEnginePort",
    "CredentialsPort",
    "DeduplicationEnginePort",
    "DetectionEnginePort",
    "DetectionRuleRepositoryPort",
    "EnrichmentEnginePort",
    "EventBusPort",
    "ExporterPort",
    "ExtractorPort",
    "FindingRepositoryPort",
    "HTTPClientPort",
    "IndicatorRepositoryPort",
    "JobRepositoryPort",
    "NormalizerPort",
    "ParserPort",
    "RepositoryPort",
    "SchedulerPort",
    "ScoringEnginePort",
    "ThreatActorRepositoryPort",
    "UnitOfWorkPort",
    "WatchlistRepositoryPort",
]
