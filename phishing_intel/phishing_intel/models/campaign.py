"""Pydantic models related to campaign attribution and correlations."""

from __future__ import annotations

from pydantic import BaseModel, Field


class CorrelationMatch(BaseModel):
    """Represents one historical campaign potentially related to an incident."""

    campaign_id: str
    reasons: list[str] = Field(default_factory=list)
    score: int = Field(ge=0, le=100)


class CampaignAttribution(BaseModel):
    """Final campaign attribution decision."""

    campaign_id: str
    attribution_score: int = Field(ge=0, le=100)
    confidence_level: str
    matched_campaigns: list[CorrelationMatch] = Field(default_factory=list)
    operator_hint: str | None = None
