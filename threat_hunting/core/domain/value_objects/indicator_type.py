"""
IndicatorType Value Object
==========================

Classifies the type of an Indicator of Compromise (IOC).
Used by the extraction layer to correctly tag parsed artifacts and by
the enrichment layer to select the appropriate enricher.
"""

from __future__ import annotations

from enum import Enum


class IndicatorType(str, Enum):
    """IOC classification taxonomy aligned with STIX 2.1 SCO types."""

    # Network
    IP = "ip"
    IP_RANGE = "ip_range"
    DOMAIN = "domain"
    FQDN = "fqdn"
    URL = "url"
    EMAIL = "email"
    ASN = "asn"
    CERTIFICATE_SHA1 = "certificate_sha1"
    JA3 = "ja3"

    # File
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    SSDEEP = "ssdeep"
    IMPHASH = "imphash"
    FILENAME = "filename"

    # Identity / PII
    CPF = "cpf"
    CNPJ = "cnpj"
    CARD_NUMBER = "card_number"
    PHONE = "phone"
    USERNAME = "username"
    NICKNAME = "nickname"
    WALLET = "wallet"

    # Platform-specific
    TELEGRAM_CHANNEL = "telegram_channel"
    TELEGRAM_USER = "telegram_user"
    GITHUB_REPO = "github_repo"
    GITHUB_USER = "github_user"
    PASTEBIN_URL = "pastebin_url"
    ONION_URL = "onion_url"

    # Malware / Actor
    MALWARE_FAMILY = "malware_family"
    THREAT_ACTOR = "threat_actor"
    CAMPAIGN = "campaign"
    CVE = "cve"
    YARA_RULE = "yara_rule"

    # Generic
    OTHER = "other"

    @property
    def stix_type(self) -> str:
        """Map to the closest STIX 2.1 observable type."""
        mapping: dict[str, str] = {
            "ip": "ipv4-addr",
            "ip_range": "ipv4-addr",
            "domain": "domain-name",
            "fqdn": "domain-name",
            "url": "url",
            "email": "email-addr",
            "md5": "file",
            "sha1": "file",
            "sha256": "file",
            "wallet": "cryptocurrency-wallet",
            "cve": "vulnerability",
        }
        return mapping.get(self.value, "artifact")

    @property
    def is_network_indicator(self) -> bool:
        """True if the indicator relates to network infrastructure."""
        return self in {
            IndicatorType.IP,
            IndicatorType.IP_RANGE,
            IndicatorType.DOMAIN,
            IndicatorType.FQDN,
            IndicatorType.URL,
            IndicatorType.ASN,
        }

    @property
    def is_pii(self) -> bool:
        """True if the indicator contains Personally Identifiable Information."""
        return self in {
            IndicatorType.CPF,
            IndicatorType.CNPJ,
            IndicatorType.CARD_NUMBER,
            IndicatorType.PHONE,
            IndicatorType.EMAIL,
        }
