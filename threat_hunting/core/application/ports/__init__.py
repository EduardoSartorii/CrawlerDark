"""Ports: the abstract contracts the core exposes to the outside world.

Every port is a small, role-specific :class:`typing.Protocol` (Interface
Segregation). Infrastructure adapters implement them; the application composes
against them. Nothing here imports infrastructure.
"""

from threat_hunting.core.application.ports.connector import (
    ConnectorPort,
    ConnectorMeta,
    ConnectorRegistryPort,
)
from threat_hunting.core.application.ports.pipeline import PipelineStage, PipelineContext
from threat_hunting.core.application.ports.repository import (
    FindingRepository,
    UnitOfWork,
)
from threat_hunting.core.application.ports.exporter import Exporter
from threat_hunting.core.application.ports.enrichment import EnrichmentProvider
from threat_hunting.core.application.ports.detection import DetectionRule
from threat_hunting.core.application.ports.transport import Transport, TransportResponse
from threat_hunting.core.application.ports.event_bus import EventBus, EventHandler
from threat_hunting.core.application.ports.keyword_provider import KeywordProvider

__all__ = [
    "ConnectorPort",
    "ConnectorMeta",
    "ConnectorRegistryPort",
    "PipelineStage",
    "PipelineContext",
    "FindingRepository",
    "UnitOfWork",
    "Exporter",
    "EnrichmentProvider",
    "DetectionRule",
    "Transport",
    "TransportResponse",
    "EventBus",
    "EventHandler",
    "KeywordProvider",
]
