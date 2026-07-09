"""
Campaign and attribution domain models.

Defines structures for campaign correlation, attribution scoring,
and historical incident relationships.

Architectural Responsibility:
    Models the intelligence layer above individual incident analysis,
    enabling multi-incident correlation and operator attribution.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from phishing_intel.models.findings import ConfidenceLevel


class CorrelationSignal(BaseModel):
    """Individual correlation signal contributing to attribution score."""

    signal_type: str
    weight: float
    matched_value: str
    source_incident_id: str | None = None
    description: str = ""


class CampaignAttribution(BaseModel):
    """
    Campaign attribution result with confidence scoring.

    Attribution Score Calculation:
        Sum of weighted correlation signals, capped at 100.
        0-39: Low confidence
        40-69: Medium confidence
        70-100: High confidence
    """

    campaign_id: str
    score: float = Field(ge=0.0, le=100.0, default=0.0)
    confidence: ConfidenceLevel = ConfidenceLevel.LOW
    signals: list[CorrelationSignal] = Field(default_factory=list)
    related_incidents: list[str] = Field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None


class Campaign(BaseModel):
    """
    Phishing campaign entity aggregating related incidents.

    Represents a cluster of phishing sites linked by shared
    infrastructure, fingerprints, or targeting patterns.
    """

    campaign_id: str
    name: str = ""
    attribution: CampaignAttribution | None = None
    target_brand: str = ""
    phishing_type: str = ""
    kit_fingerprint: str = ""
    incident_count: int = 0
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime | None = None
    updated_at: datetime | None = None
