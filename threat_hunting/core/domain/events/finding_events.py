"""
Finding Domain Events
=====================

Events emitted during the Finding lifecycle, consumed by handlers that
trigger side effects: notifications, metrics, export triggers, etc.
"""

from __future__ import annotations

from typing import Any

from pydantic import Field

from threat_hunting.core.domain.events.base import DomainEvent


class FindingCreated(DomainEvent):
    """Emitted when a new Finding is produced by a connector."""

    event_type: str = "finding.created"
    aggregate_type: str = "Finding"
    connector: str
    source: str
    category: str
    title: str


class FindingScored(DomainEvent):
    """Emitted after the ScoringEngine assigns a score to a Finding."""

    event_type: str = "finding.scored"
    aggregate_type: str = "Finding"
    score_value: float
    severity: str
    confidence: float
    matched_rules: list[str] = Field(default_factory=list)


class FindingCorrelated(DomainEvent):
    """Emitted when a Finding is correlated to other entities."""

    event_type: str = "finding.correlated"
    aggregate_type: str = "Finding"
    correlation_group: str
    related_finding_ids: list[str] = Field(default_factory=list)


class FindingDeduplicated(DomainEvent):
    """Emitted when a Finding is identified as a duplicate."""

    event_type: str = "finding.deduplicated"
    aggregate_type: str = "Finding"
    original_finding_id: str


class FindingEnriched(DomainEvent):
    """Emitted after the EnrichmentEngine processes a Finding."""

    event_type: str = "finding.enriched"
    aggregate_type: str = "Finding"
    enrichers_applied: list[str] = Field(default_factory=list)
    indicators_enriched: int = 0


class FindingPersisted(DomainEvent):
    """Emitted when a Finding is successfully saved to storage."""

    event_type: str = "finding.persisted"
    aggregate_type: str = "Finding"
    storage_backend: str


class FindingExported(DomainEvent):
    """Emitted when a Finding is exported to an external platform."""

    event_type: str = "finding.exported"
    aggregate_type: str = "Finding"
    exporter: str
    destination: str


class FindingFalsePositive(DomainEvent):
    """Emitted when a Finding is marked as a false positive."""

    event_type: str = "finding.false_positive"
    aggregate_type: str = "Finding"
    reason: str
    analyst: str = "system"
