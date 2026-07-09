"""Campaign & attribution Pydantic domain models.

Responsibility
--------------
Represent the output of the correlation engine: how a new sample relates to a
known campaign, the weighted attribution score and the confidence band.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

from pydantic import BaseModel, Field

from phishing_intel.models.findings import ConfidenceLevel


class CampaignMatch(BaseModel):
    """A single correlation signal that fired between two samples."""

    # Signal key matching a weight in ``CorrelationSettings.weights``.
    signal: str
    weight: int
    # Human-readable explanation of what matched.
    detail: str = ""


class AttributionScore(BaseModel):
    """Weighted attribution score with its confidence classification."""

    score: int = 0
    confidence: ConfidenceLevel = ConfidenceLevel.LOW
    matches: List[CampaignMatch] = Field(default_factory=list)
    # The campaign this sample was attributed to (if any).
    matched_campaign_id: Optional[str] = None


class Campaign(BaseModel):
    """A tracked phishing campaign aggregating related samples."""

    campaign_id: str
    target_brand: Optional[str] = None
    phishing_type: Optional[str] = None
    kit_fingerprint: Optional[str] = None
    score: int = 0
    confidence: ConfidenceLevel = ConfidenceLevel.LOW
    # URLs / sample identifiers linked to this campaign.
    members: List[str] = Field(default_factory=list)
    first_seen: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    last_seen: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
