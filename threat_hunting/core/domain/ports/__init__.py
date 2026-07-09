"""
Ports Package — Hexagonal Architecture Boundary
================================================

Ports are interfaces (abstract base classes) that define contracts
between the Core and the Infrastructure layers.

Design principle:
    - Ports are owned by the Core.
    - Adapters (infrastructure implementations) are owned by Infrastructure.
    - The Core never imports from Infrastructure.
    - Infrastructure always imports from Core (implements ports).
"""

from threat_hunting.core.domain.ports.connectors import IConnector
from threat_hunting.core.domain.ports.engines import (
    IDetectionEngine,
    IScoringEngine,
    ICorrelationEngine,
    IDeduplicationEngine,
    IEnrichmentEngine,
)
from threat_hunting.core.domain.ports.repositories import (
    IFindingRepository,
    IIndicatorRepository,
    IKeywordRepository,
    IVIPRepository,
    IThreatActorRepository,
    IRuleRepository,
    IConnectorConfigRepository,
)
from threat_hunting.core.domain.ports.exporters import IExporter
from threat_hunting.core.domain.ports.event_bus import IEventBus
from threat_hunting.core.domain.ports.storage import IUnitOfWork

__all__ = [
    "IConnector",
    "IDetectionEngine",
    "IScoringEngine",
    "ICorrelationEngine",
    "IDeduplicationEngine",
    "IEnrichmentEngine",
    "IFindingRepository",
    "IIndicatorRepository",
    "IKeywordRepository",
    "IVIPRepository",
    "IThreatActorRepository",
    "IRuleRepository",
    "IConnectorConfigRepository",
    "IExporter",
    "IEventBus",
    "IUnitOfWork",
]
