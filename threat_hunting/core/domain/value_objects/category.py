"""
Category Value Object.

Defines the taxonomy of threat intelligence findings.
Drives filtering, routing, and export decisions across the platform.

Business Rules:
    - Categories map to MITRE ATT&CK and threat intelligence taxonomies
    - A finding must have exactly one primary category
    - Categories are used by the scoring engine to apply context weights
"""

from __future__ import annotations

from enum import StrEnum


class ThreatCategory(StrEnum):
    """
    Primary threat category taxonomy.

    Derived from MITRE ATT&CK, STIX, and industry-standard CTI classifications.
    """

    # Credential & Identity Threats
    CREDENTIAL_LEAK = "credential_leak"
    CREDENTIAL_STUFFING = "credential_stuffing"
    ACCOUNT_TAKEOVER = "account_takeover"

    # Data Leakage
    DATA_LEAK = "data_leak"
    DATABASE_LEAK = "database_leak"
    CODE_LEAK = "code_leak"
    DOCUMENT_LEAK = "document_leak"

    # Financial Fraud
    CARD_DATA = "card_data"
    FINANCIAL_FRAUD = "financial_fraud"
    CRYPTO_THEFT = "crypto_theft"

    # Malware & Infrastructure
    MALWARE = "malware"
    RANSOMWARE = "ransomware"
    BOTNET = "botnet"
    C2_INFRASTRUCTURE = "c2_infrastructure"
    PHISHING = "phishing"
    TYPOSQUATTING = "typosquatting"

    # Brand & Reputation
    BRAND_ABUSE = "brand_abuse"
    IMPERSONATION = "impersonation"
    VIP_THREAT = "vip_threat"
    EXECUTIVE_EXPOSURE = "executive_exposure"

    # Threat Intelligence
    IOC = "ioc"
    THREAT_ACTOR = "threat_actor"
    CAMPAIGN = "campaign"
    VULNERABILITY = "vulnerability"
    EXPLOIT = "exploit"

    # Dark/Deep Web
    DARK_WEB = "dark_web"
    FORUM_POST = "forum_post"
    MARKETPLACE = "marketplace"

    # OSINT
    SOCIAL_MEDIA = "social_media"
    PASTE_SITE = "paste_site"
    NEWS = "news"

    # PII / Compliance
    PII_EXPOSURE = "pii_exposure"
    CPF_LEAK = "cpf_leak"
    CNPJ_LEAK = "cnpj_leak"

    # Generic
    GENERAL = "general"
    UNKNOWN = "unknown"

    @property
    def is_high_value(self) -> bool:
        """High-value categories trigger immediate alerting rules."""
        return self in {
            ThreatCategory.CREDENTIAL_LEAK,
            ThreatCategory.CARD_DATA,
            ThreatCategory.RANSOMWARE,
            ThreatCategory.C2_INFRASTRUCTURE,
            ThreatCategory.VIP_THREAT,
            ThreatCategory.EXECUTIVE_EXPOSURE,
            ThreatCategory.DARK_WEB,
        }

    @property
    def mitre_tactic(self) -> str | None:
        """Best-effort mapping to MITRE ATT&CK tactic name."""
        _mapping: dict[str, str] = {
            "credential_leak": "TA0006 - Credential Access",
            "phishing": "TA0001 - Initial Access",
            "malware": "TA0002 - Execution",
            "c2_infrastructure": "TA0011 - Command and Control",
            "data_leak": "TA0010 - Exfiltration",
            "ransomware": "TA0040 - Impact",
        }
        return _mapping.get(self.value)
