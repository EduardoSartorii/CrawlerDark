"""Detection engine domain events."""

from __future__ import annotations

from pydantic import Field

from threat_hunting.core.domain.events.base import DomainEvent


class RuleMatched(DomainEvent):
    """Emitted when a detection rule matches a Finding."""

    event_type: str = "detection.rule_matched"
    aggregate_type: str = "Finding"
    rule_id: str
    rule_name: str
    rule_type: str
    finding_id: str
    confidence: float


class ThreatDetected(DomainEvent):
    """
    Emitted when a Finding receives a HIGH or CRITICAL score.
    This event triggers immediate notification and priority export.
    """

    event_type: str = "detection.threat_detected"
    aggregate_type: str = "Finding"
    finding_id: str
    score: float
    severity: str
    category: str
    connector: str
    matched_rules: list[str] = Field(default_factory=list)
