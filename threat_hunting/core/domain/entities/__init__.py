"""Entidades do domínio.

Todas seguem o mesmo padrão:
* dataclasses ``kw_only=True`` para clareza;
* IDs gerados via ``uuid.uuid4`` por default;
* datetimes sempre em UTC (timezone-aware).
"""

from .artifact import Artifact
from .campaign import Campaign
from .detection_rule import DetectionRule
from .finding import Finding
from .indicator import Indicator
from .job import Job, JobStatus
from .relationship import Relationship, RelationshipType
from .threat_actor import ThreatActor
from .timeline_event import TimelineEvent
from .watchlist_item import WatchlistItem, WatchlistKind

__all__ = [
    "Artifact",
    "Campaign",
    "DetectionRule",
    "Finding",
    "Indicator",
    "Job",
    "JobStatus",
    "Relationship",
    "RelationshipType",
    "ThreatActor",
    "TimelineEvent",
    "WatchlistItem",
    "WatchlistKind",
]
