"""Domain events published through the event bus (Event-Driven design).

Events are immutable facts describing something that already happened. They
decouple the code that *causes* a change from the code that *reacts* to it
(Observer Pattern), e.g. the auto-MISP exporter reacting to a high-severity
finding.
"""

from threat_hunting.core.domain.events.base import DomainEvent
from threat_hunting.core.domain.events.finding_events import (
    FindingCollected,
    FindingScored,
    FindingPersisted,
    FindingExported,
    HighSeverityFindingDetected,
    PipelineStarted,
    PipelineCompleted,
    PipelineStageFailed,
)

__all__ = [
    "DomainEvent",
    "FindingCollected",
    "FindingScored",
    "FindingPersisted",
    "FindingExported",
    "HighSeverityFindingDetected",
    "PipelineStarted",
    "PipelineCompleted",
    "PipelineStageFailed",
]
