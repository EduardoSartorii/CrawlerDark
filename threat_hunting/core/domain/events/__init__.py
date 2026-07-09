"""Domain events — facts about things that happened in the domain."""

from threat_hunting.core.domain.events.base import DomainEvent
from threat_hunting.core.domain.events.finding_events import (
    FindingCreated,
    FindingScored,
    FindingCorrelated,
    FindingDeduplicated,
    FindingEnriched,
    FindingPersisted,
    FindingExported,
    FindingFalsePositive,
)
from threat_hunting.core.domain.events.collection_events import (
    CollectionStarted,
    CollectionCompleted,
    CollectionFailed,
)
from threat_hunting.core.domain.events.detection_events import (
    RuleMatched,
    ThreatDetected,
)

__all__ = [
    "DomainEvent",
    "FindingCreated",
    "FindingScored",
    "FindingCorrelated",
    "FindingDeduplicated",
    "FindingEnriched",
    "FindingPersisted",
    "FindingExported",
    "FindingFalsePositive",
    "CollectionStarted",
    "CollectionCompleted",
    "CollectionFailed",
    "RuleMatched",
    "ThreatDetected",
]
