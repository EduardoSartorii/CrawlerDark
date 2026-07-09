"""
SourceType Value Object.

Classifies the origin of threat intelligence data.
Used by the scoring engine to apply source-specific trust/reputation weights.

Business Rules:
    - Different source types carry different base trust scores
    - Dark web sources require additional verification
    - Commercial feeds are generally higher fidelity
"""

from __future__ import annotations

from enum import StrEnum


class SourceType(StrEnum):
    """Taxonomy of threat intelligence source types."""

    # Social media & messaging
    SOCIAL_MEDIA = "social_media"
    TELEGRAM = "telegram"
    DISCORD = "discord"

    # Code repositories
    CODE_REPOSITORY = "code_repository"
    GITHUB = "github"
    GITLAB = "gitlab"

    # Dark/Deep web
    DARK_WEB = "dark_web"
    DEEP_WEB = "deep_web"
    FORUM = "forum"
    MARKETPLACE = "marketplace"
    PASTE_SITE = "paste_site"

    # Open web
    NEWS = "news"
    BLOG = "blog"
    WEBSITE = "website"
    RSS = "rss"

    # Intelligence feeds & platforms
    THREAT_FEED = "threat_feed"
    MISP = "misp"
    OPENCTI = "opencti"
    ALIENVAULT_OTX = "alienvault_otx"
    THREATFOX = "threatfox"
    URLHAUS = "urlhaus"

    # Commercial / API
    VIRUSTOTAL = "virustotal"
    SHODAN = "shodan"
    CENSYS = "censys"
    GREYNOISE = "greynoise"
    ABUSEIPDB = "abuseipdb"

    # Internal
    INTERNAL = "internal"
    MANUAL = "manual"
    UNKNOWN = "unknown"

    @property
    def trust_weight(self) -> float:
        """
        Base trust/fidelity weight for scoring engine.
        Higher weight = more reliable source.
        Range: 0.1 to 1.0
        """
        weights: dict[str, float] = {
            "virustotal": 0.95,
            "shodan": 0.90,
            "censys": 0.90,
            "misp": 0.90,
            "opencti": 0.90,
            "threatfox": 0.85,
            "urlhaus": 0.85,
            "alienvault_otx": 0.80,
            "greynoise": 0.80,
            "abuseipdb": 0.75,
            "threat_feed": 0.75,
            "github": 0.70,
            "gitlab": 0.65,
            "code_repository": 0.65,
            "dark_web": 0.60,
            "marketplace": 0.55,
            "forum": 0.50,
            "deep_web": 0.50,
            "paste_site": 0.50,
            "telegram": 0.45,
            "discord": 0.40,
            "social_media": 0.35,
            "news": 0.55,
            "blog": 0.45,
            "website": 0.40,
            "rss": 0.40,
            "internal": 1.0,
            "manual": 0.95,
        }
        return weights.get(self.value, 0.3)

    @property
    def requires_opsec(self) -> bool:
        """Whether this source type requires OPSEC layer (proxy/Tor)."""
        return self in {
            SourceType.DARK_WEB,
            SourceType.DEEP_WEB,
            SourceType.MARKETPLACE,
            SourceType.FORUM,
        }
