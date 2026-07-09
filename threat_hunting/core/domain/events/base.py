"""Domain events base and concrete events.

Responsibility
--------------
Define immutable domain events that decouple side-effects (export, audit,
metrics) from the pipeline via Observer/Event Bus pattern.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from threat_hunting.core.domain.value_objects import utc_now


class DomainEvent(BaseModel):
    """Base domain event — all events inherit from this."""

    model_config = ConfigDict(frozen=True)

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str = ""
    occurred_at: datetime = Field(default_factory=utc_now)
    aggregate_id: str = ""
    payload: dict[str, Any] = Field(default_factory=dict)

    def __init__(self, **data: Any) -> None:
        if "event_type" not in data or not data["event_type"]:
            data["event_type"] = self.__class__.__name__
        super().__init__(**data)


class FindingCreated(DomainEvent):
    """Emitted when a Finding is first created by a normalizer."""


class FindingScored(DomainEvent):
    """Emitted after scoring engine assigns a score."""


class FindingCorrelated(DomainEvent):
    """Emitted when correlation links are established."""


class FindingDeduplicated(DomainEvent):
    """Emitted when a Finding is identified as duplicate."""


class FindingEnriched(DomainEvent):
    """Emitted after enrichment completes."""


class FindingPersisted(DomainEvent):
    """Emitted after successful persistence."""


class ScoreThresholdExceeded(DomainEvent):
    """Emitted when Finding score exceeds configured auto-export threshold.

    Business rule: triggers automatic MISP (or configured) export.
    """


class ExportRequested(DomainEvent):
    """Emitted when an export to an external system is requested."""


class ExportCompleted(DomainEvent):
    """Emitted when an export finishes successfully."""


class HuntJobStarted(DomainEvent):
    """Emitted when a HuntJob begins execution."""


class HuntJobCompleted(DomainEvent):
    """Emitted when a HuntJob finishes (success or partial)."""


class HuntJobFailed(DomainEvent):
    """Emitted when a HuntJob fails fatally."""


class ConnectorHealthFailed(DomainEvent):
    """Emitted when a connector health check fails."""


class AuditRecorded(DomainEvent):
    """Emitted for governance/audit trail entries."""


__all__ = [
    "DomainEvent",
    "FindingCreated",
    "FindingScored",
    "FindingCorrelated",
    "FindingDeduplicated",
    "FindingEnriched",
    "FindingPersisted",
    "ScoreThresholdExceeded",
    "ExportRequested",
    "ExportCompleted",
    "HuntJobStarted",
    "HuntJobCompleted",
    "HuntJobFailed",
    "ConnectorHealthFailed",
    "AuditRecorded",
]
