"""Campaign attribution models.

Campaign correlation compares new incidents with historical observations using
weighted CTI signals such as kit fingerprint, certificate reuse, ASN, provider,
DOM pattern, JavaScript pattern, and target brand.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class CampaignSignal(BaseModel):
    """One weighted signal that contributed to an attribution score."""

    name: str
    value: str
    weight: int


class CampaignAttribution(BaseModel):
    """Final campaign attribution decision produced by correlators."""

    campaign_id: str
    score: int = Field(ge=0, le=100)
    confidence: str
    signals: list[CampaignSignal] = Field(default_factory=list)


def confidence_from_score(score: int) -> str:
    """Map an attribution score to the Portuguese confidence labels."""

    if score >= 70:
        return "alta"
    if score >= 40:
        return "media"
    return "baixa"
