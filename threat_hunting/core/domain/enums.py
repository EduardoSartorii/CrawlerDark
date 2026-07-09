"""Domain enumerations.

Responsibility
--------------
Provide the closed vocabularies of the domain (severities, categories, source
types, indicator types, relationship types, event names). Keeping these as
enums (instead of free strings) makes the domain self-validating and gives the
whole platform a single, refactor-safe source of truth.

These enums are part of the ubiquitous language and are referenced across every
layer, therefore they live in the domain and carry no infrastructure concerns.
"""

from __future__ import annotations

from enum import Enum


class Severity(str, Enum):
    """Qualitative danger level of a finding.

    Ordered from least to most critical. The numeric mapping (:meth:`weight`)
    lets the scoring engine translate a qualitative severity into a numeric
    contribution without hardcoding magic numbers elsewhere.
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def weight(self) -> int:
        """Return the ordinal weight used by scoring/sorting (INFO=0..CRITICAL=4)."""
        return _SEVERITY_ORDER[self]

    @classmethod
    def from_score(cls, score: float) -> "Severity":
        """Derive a severity bucket from a normalised 0-100 score."""
        if score >= 85:
            return cls.CRITICAL
        if score >= 65:
            return cls.HIGH
        if score >= 40:
            return cls.MEDIUM
        if score >= 15:
            return cls.LOW
        return cls.INFO


_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Category(str, Enum):
    """Hunting category a finding belongs to (drives routing & dashboards)."""

    THREAT_HUNTING = "threat_hunting"
    OSINT = "osint"
    BRAND_MONITORING = "brand_monitoring"
    VIP_MONITORING = "vip_monitoring"
    DARK_WEB = "dark_web"
    DEEP_WEB = "deep_web"
    CREDENTIAL_LEAK = "credential_leak"
    IOC = "ioc"
    CARD_LEAK = "card_leak"
    DATA_LEAK = "data_leak"
    DOCUMENT_LEAK = "document_leak"
    CAMPAIGN = "campaign"
    THREAT_ACTOR = "threat_actor"
    MALWARE = "malware"
    PHISHING = "phishing"
    OTHER = "other"


class SourceType(str, Enum):
    """Nature of the external source a connector talks to."""

    SOCIAL_MEDIA = "social_media"
    MESSAGING = "messaging"
    CODE_REPOSITORY = "code_repository"
    PASTE_SITE = "paste_site"
    NEWS = "news"
    BLOG = "blog"
    RSS = "rss"
    WEBSITE = "website"
    FORUM = "forum"
    MARKETPLACE = "marketplace"
    DARK_WEB = "dark_web"
    DEEP_WEB = "deep_web"
    THREAT_FEED = "threat_feed"
    API = "api"


class IndicatorType(str, Enum):
    """Type of an observable / IOC extracted from content."""

    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    CVE = "cve"
    BTC_WALLET = "btc_wallet"
    ETH_WALLET = "eth_wallet"
    CREDIT_CARD = "credit_card"
    CPF = "cpf"
    CNPJ = "cnpj"
    ASN = "asn"
    CERTIFICATE = "certificate"
    NICKNAME = "nickname"
    TELEGRAM = "telegram"
    GITHUB = "github"
    CREDENTIAL = "credential"
    FILENAME = "filename"


class RelationshipType(str, Enum):
    """Typed edge between two entities/indicators used by correlation."""

    RESOLVES_TO = "resolves_to"
    COMMUNICATES_WITH = "communicates_with"
    ATTRIBUTED_TO = "attributed_to"
    PART_OF_CAMPAIGN = "part_of_campaign"
    MENTIONS = "mentions"
    SHARED_INDICATOR = "shared_indicator"
    SAME_ACTOR = "same_actor"
    HOSTED_ON = "hosted_on"


class EventName(str, Enum):
    """Names of domain events published through the event bus."""

    FINDING_COLLECTED = "finding.collected"
    FINDING_PARSED = "finding.parsed"
    FINDING_NORMALIZED = "finding.normalized"
    FINDING_DETECTED = "finding.detected"
    FINDING_SCORED = "finding.scored"
    FINDING_CORRELATED = "finding.correlated"
    FINDING_DEDUPLICATED = "finding.deduplicated"
    FINDING_ENRICHED = "finding.enriched"
    FINDING_PERSISTED = "finding.persisted"
    FINDING_EXPORTED = "finding.exported"
    HIGH_SEVERITY_FINDING_DETECTED = "finding.high_severity"
    PIPELINE_STARTED = "pipeline.started"
    PIPELINE_COMPLETED = "pipeline.completed"
    PIPELINE_STAGE_FAILED = "pipeline.stage_failed"
