"""
Category Value Object
=====================

Classifies the type of intelligence contained in a Finding.
Drives routing decisions — which exporters, correlation rules, and
enrichers are applied to a given Finding.
"""

from __future__ import annotations

from enum import Enum


class Category(str, Enum):
    """Primary intelligence categories produced by connectors."""

    # Credential / identity threats
    CREDENTIAL_LEAK = "credential_leak"
    CREDENTIAL_STUFFING = "credential_stuffing"

    # Financial threats
    CARD_LEAK = "card_leak"
    FRAUD = "fraud"

    # Document / PII threats
    DOCUMENT_LEAK = "document_leak"
    PII = "pii"

    # Malware / infrastructure
    MALWARE = "malware"
    IOC = "ioc"
    INFRASTRUCTURE = "infrastructure"
    PHISHING = "phishing"
    C2 = "c2"

    # Threat actor intelligence
    THREAT_ACTOR = "threat_actor"
    CAMPAIGN = "campaign"

    # Brand / VIP
    BRAND_ABUSE = "brand_abuse"
    VIP_MENTION = "vip_mention"
    EXECUTIVE_MENTION = "executive_mention"

    # Dark/deep web
    DARKWEB = "darkweb"
    DEEPWEB = "deepweb"
    PASTE = "paste"
    FORUM_POST = "forum_post"
    MARKETPLACE = "marketplace"

    # Social media
    SOCIAL_MEDIA = "social_media"

    # General
    VULNERABILITY = "vulnerability"
    DATA_BREACH = "data_breach"
    RANSOMWARE = "ransomware"
    OSINT = "osint"
    GENERAL = "general"

    @property
    def is_high_priority(self) -> bool:
        """Business rule: categories that always warrant immediate attention."""
        return self in {
            self.CREDENTIAL_LEAK,
            self.CARD_LEAK,
            self.RANSOMWARE,
            self.C2,
            self.THREAT_ACTOR,
            self.VIP_MENTION,
        }
