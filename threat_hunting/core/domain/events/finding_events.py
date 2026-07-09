"""Concrete finding & pipeline domain events.

Responsibility
--------------
Define the specific events emitted across the collection pipeline. Subscribers
(metrics, audit log, auto-exporters) react to these without the publisher
knowing they exist, satisfying the Observer Pattern and Event-Driven design.
"""

from __future__ import annotations

from pydantic import Field

from threat_hunting.core.domain.entities.finding import Finding
from threat_hunting.core.domain.enums import EventName
from threat_hunting.core.domain.events.base import DomainEvent


class FindingCollected(DomainEvent):
    """A finding was produced by a connector."""

    name: EventName = EventName.FINDING_COLLECTED
    finding: Finding


class FindingScored(DomainEvent):
    """A finding finished the scoring stage."""

    name: EventName = EventName.FINDING_SCORED
    finding: Finding


class FindingPersisted(DomainEvent):
    """A finding was written to storage."""

    name: EventName = EventName.FINDING_PERSISTED
    finding: Finding


class FindingExported(DomainEvent):
    """A finding was exported to an external system."""

    name: EventName = EventName.FINDING_EXPORTED
    finding: Finding
    exporter: str


class HighSeverityFindingDetected(DomainEvent):
    """A finding crossed the auto-export score threshold."""

    name: EventName = EventName.HIGH_SEVERITY_FINDING_DETECTED
    finding: Finding
    threshold: float


class PipelineStarted(DomainEvent):
    """A pipeline run has started for a connector."""

    name: EventName = EventName.PIPELINE_STARTED
    connector: str


class PipelineCompleted(DomainEvent):
    """A pipeline run finished."""

    name: EventName = EventName.PIPELINE_COMPLETED
    connector: str
    findings_count: int = 0
    stats: dict[str, float] = Field(default_factory=dict)


class PipelineStageFailed(DomainEvent):
    """A pipeline stage raised an error."""

    name: EventName = EventName.PIPELINE_STAGE_FAILED
    connector: str
    stage: str
    error: str
