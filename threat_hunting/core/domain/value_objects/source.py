"""
SourceType Value Object
=======================

Identifies the broad category of the data source from which a Finding
was collected. Used by the scoring engine to apply source-reputation
multipliers and by the OPSEC layer to select the appropriate proxy profile.
"""

from __future__ import annotations

from enum import Enum


class SourceType(str, Enum):
    """Broad source-type taxonomy."""

    SOCIAL = "social"
    DARKWEB = "darkweb"
    DEEPWEB = "deepweb"
    PASTE = "paste"
    GITHUB = "github"
    TELEGRAM = "telegram"
    DISCORD = "discord"
    FEED = "feed"
    API = "api"
    FORUM = "forum"
    MARKETPLACE = "marketplace"
    NEWS = "news"
    BLOG = "blog"
    MISP = "misp"
    OPENCTI = "opencti"
    OTHER = "other"

    @property
    def opsec_profile(self) -> str:
        """Select the OPSEC profile recommended for this source type."""
        if self in {SourceType.DARKWEB, SourceType.DEEPWEB}:
            return "darkweb"
        if self in {SourceType.MARKETPLACE, SourceType.FORUM}:
            return "darkweb"
        return "standard"

    @property
    def reputation_multiplier(self) -> float:
        """Default reputation multiplier for the scoring engine."""
        multipliers = {
            "darkweb": 1.5,
            "deepweb": 1.4,
            "telegram": 1.2,
            "discord": 1.1,
            "paste": 1.3,
            "github": 1.0,
            "social": 0.8,
            "feed": 0.5,
            "api": 0.7,
            "misp": 0.9,
            "opencti": 0.9,
        }
        return multipliers.get(self.value, 1.0)
