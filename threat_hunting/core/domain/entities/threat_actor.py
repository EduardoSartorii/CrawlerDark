"""
ThreatActor Entity.

Represents a known or suspected threat actor (APT, eCrime group, hacktivist, etc.).
Used by the Correlation Engine to attribute findings and track actor activity.

Business Rules:
    - Actors have multiple aliases (tracking groups use different names)
    - Motivation drives the scoring context (financial vs. espionage vs. disruption)
    - Actor confidence represents certainty of attribution
    - Actors link to Campaigns, Malware families, and TTPs
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import Field

from .base import BaseEntity


class ActorType(StrEnum):
    APT = "apt"
    ECRIME = "ecrime"
    HACKTIVIST = "hacktivist"
    INSIDER = "insider"
    NATION_STATE = "nation_state"
    RANSOMWARE_GROUP = "ransomware_group"
    UNKNOWN = "unknown"


class ActorMotivation(StrEnum):
    FINANCIAL = "financial"
    ESPIONAGE = "espionage"
    DISRUPTION = "disruption"
    HACKTIVISM = "hacktivism"
    INFORMATION_THEFT = "information_theft"
    UNKNOWN = "unknown"


class ThreatActor(BaseEntity):
    """
    A tracked threat actor in the intelligence platform.

    Findings attributed to known threat actors receive automatic score boosts
    and are eligible for immediate MISP/OpenCTI export.
    """

    name: str = Field(..., min_length=1)
    aliases: list[str] = Field(default_factory=list)
    actor_type: ActorType = Field(default=ActorType.UNKNOWN)
    motivation: ActorMotivation = Field(default=ActorMotivation.UNKNOWN)
    country_of_origin: str | None = Field(default=None)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    is_active: bool = Field(default=True)
    description: str = Field(default="")
    first_observed: str | None = Field(default=None)
    last_observed: str | None = Field(default=None)
    tags: list[str] = Field(default_factory=list)
    ttps: list[str] = Field(default_factory=list, description="MITRE ATT&CK IDs")
    target_sectors: list[str] = Field(default_factory=list)
    target_countries: list[str] = Field(default_factory=list)
    associated_malware: list[str] = Field(default_factory=list)
    misp_galaxy_id: str | None = Field(default=None)
    opencti_id: str | None = Field(default=None)
    references: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def add_alias(self, alias: str) -> None:
        alias = alias.strip()
        if alias and alias.lower() not in [a.lower() for a in self.aliases]:
            self.aliases.append(alias)
            self.touch()

    def matches_name(self, name: str) -> bool:
        """Check if a name matches actor name or any alias (case-insensitive)."""
        name_lower = name.lower()
        return (
            self.name.lower() == name_lower
            or any(a.lower() == name_lower for a in self.aliases)
        )

    @property
    def score_boost(self) -> float:
        """Score boost applied when a Finding is attributed to this actor."""
        boosts = {
            ActorType.APT: 3.0,
            ActorType.NATION_STATE: 3.5,
            ActorType.RANSOMWARE_GROUP: 3.0,
            ActorType.ECRIME: 2.0,
            ActorType.HACKTIVIST: 1.5,
            ActorType.INSIDER: 2.5,
            ActorType.UNKNOWN: 1.0,
        }
        return boosts.get(self.actor_type, 1.0) * self.confidence

    def __str__(self) -> str:
        aliases_str = f" (aka: {', '.join(self.aliases[:3])})" if self.aliases else ""
        return f"ThreatActor: {self.name}{aliases_str} [{self.actor_type}]"
