"""Domain enumerations (value objects with a closed set of values).

Responsibility
--------------
Provide the closed vocabularies used across the domain so that every connector
and every engine speaks the same language. Keeping these as ``str`` enums makes
them trivially serialisable (JSON/DB) while remaining type-safe.

Business rules
--------------
* ``Severity`` and ``ConfidenceLevel`` are ordered; comparisons must reflect the
  analyst's intuition (``CRITICAL > HIGH > ... ``).
* ``IndicatorType`` enumerates every observable the platform can extract,
  including Brazilian fraud-intelligence artifacts (CPF, CNPJ) and financial
  observables (credit cards, crypto wallets).
"""

from __future__ import annotations

from enum import Enum
from functools import total_ordering


@total_ordering
class _OrderedStrEnum(str, Enum):
    """A string enum whose members are ordered by declaration order."""

    def _order(self) -> int:
        members = list(type(self).__members__.values())
        return members.index(self)

    def __lt__(self, other: object) -> bool:  # noqa: D401 - operator
        if not isinstance(other, type(self)):
            return NotImplemented
        return self._order() < other._order()


class Severity(_OrderedStrEnum):
    """Analyst-facing impact rating of a finding (ordered)."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_score(cls, score: float) -> "Severity":
        """Derive a severity band from a 0-100 numeric score."""
        if score >= 90:
            return cls.CRITICAL
        if score >= 70:
            return cls.HIGH
        if score >= 40:
            return cls.MEDIUM
        if score >= 15:
            return cls.LOW
        return cls.INFO


class ConfidenceLevel(_OrderedStrEnum):
    """Confidence that a finding is a true positive (ordered)."""

    UNKNOWN = "unknown"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CONFIRMED = "confirmed"


class Category(str, Enum):
    """The hunting discipline that produced/classifies a finding."""

    THREAT_HUNTING = "threat_hunting"
    OSINT = "osint"
    BRAND_MONITORING = "brand_monitoring"
    VIP_MONITORING = "vip_monitoring"
    DARK_WEB = "dark_web"
    DEEP_WEB = "deep_web"
    CREDENTIAL_HUNTING = "credential_hunting"
    IOC_HUNTING = "ioc_hunting"
    CARD_HUNTING = "card_hunting"
    LEAK_HUNTING = "leak_hunting"
    DOCUMENT_HUNTING = "document_hunting"
    CAMPAIGN_DISCOVERY = "campaign_discovery"
    THREAT_ACTOR_DISCOVERY = "threat_actor_discovery"
    UNCLASSIFIED = "unclassified"


class IndicatorType(str, Enum):
    """Types of observable (IOC) the platform can extract and correlate."""

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
    NICKNAME = "nickname"
    TELEGRAM = "telegram"
    GITHUB = "github"
    CREDENTIAL = "credential"
    OTHER = "other"


class RelationshipType(str, Enum):
    """Typed edges produced by the correlation engine."""

    SHARES_INDICATOR = "shares_indicator"
    SAME_DOMAIN = "same_domain"
    SAME_ACTOR = "same_actor"
    SAME_CAMPAIGN = "same_campaign"
    SAME_BRAND = "same_brand"
    SAME_INFRASTRUCTURE = "same_infrastructure"
    DUPLICATE_OF = "duplicate_of"
    RELATED_TO = "related_to"


class ConnectorStatus(str, Enum):
    """Lifecycle/health status reported by a connector."""

    UNKNOWN = "unknown"
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    DISABLED = "disabled"
