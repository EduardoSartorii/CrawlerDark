"""Domain layer — enums.

Responsibility
--------------
Define the ubiquitous language enumerations used across the platform.
No infrastructure dependencies. Pure domain vocabulary.
"""

from __future__ import annotations

from enum import Enum, StrEnum


class Severity(StrEnum):
    """Finding severity levels used by detection and scoring engines."""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingCategory(StrEnum):
    """Canonical finding categories produced by connectors/normalizers."""

    THREAT_HUNTING = "threat_hunting"
    OSINT = "osint"
    BRAND_MONITORING = "brand_monitoring"
    VIP_MONITORING = "vip_monitoring"
    DARK_WEB = "dark_web"
    DEEP_WEB = "deep_web"
    CREDENTIAL = "credential"
    IOC = "ioc"
    CARD = "card"
    LEAK = "leak"
    DOCUMENT = "document"
    CAMPAIGN = "campaign"
    THREAT_ACTOR = "threat_actor"
    MALWARE = "malware"
    INFRASTRUCTURE = "infrastructure"
    OTHER = "other"


class IndicatorType(StrEnum):
    """Typed Indicator of Compromise (IOC) kinds."""

    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    CVE = "cve"
    ASN = "asn"
    CERTIFICATE = "certificate"
    WALLET = "wallet"
    CPF = "cpf"
    CNPJ = "cnpj"
    CARD = "card"
    TELEGRAM = "telegram"
    GITHUB = "github"
    USERNAME = "username"
    FILENAME = "filename"
    YARA = "yara"
    OTHER = "other"


class HuntJobStatus(StrEnum):
    """Lifecycle status of a HuntJob aggregate."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PARTIAL = "partial"


class ConnectorStatus(StrEnum):
    """Operational status of a connector."""

    ENABLED = "enabled"
    DISABLED = "disabled"
    DEGRADED = "degraded"
    UNKNOWN = "unknown"


class WatchlistType(StrEnum):
    """Types of watchlist entries managed by governance context."""

    KEYWORD = "keyword"
    VIP = "vip"
    COMPANY = "company"
    EXECUTIVE = "executive"
    BRAND = "brand"
    DOMAIN = "domain"
    THREAT_ACTOR = "threat_actor"
    EMAIL = "email"
    CPF = "cpf"
    CNPJ = "cnpj"
    CARD = "card"
    WALLET = "wallet"
    TELEGRAM = "telegram"
    GITHUB = "github"
    IOC = "ioc"
    YARA = "yara"
    REGEX = "regex"
    SIGMA = "sigma"


class DetectionRuleType(StrEnum):
    """Detection rule strategies loaded dynamically from config."""

    REGEX = "regex"
    YARA = "yara"
    SIGMA = "sigma"
    KEYWORD = "keyword"
    IOC_MATCH = "ioc_match"
    THREAT_ACTOR_MATCH = "threat_actor_match"
    HEURISTIC = "heuristic"
    WHITELIST = "whitelist"
    BLACKLIST = "blacklist"
    THRESHOLD = "threshold"
    COMPOSITE = "composite"


class ExportFormat(StrEnum):
    """Supported export formats / destinations."""

    MISP = "misp"
    OPENCTI = "opencti"
    SPLUNK = "splunk"
    OPENSEARCH = "opensearch"
    WEBHOOK = "webhook"
    REST_API = "rest_api"
    JSON = "json"
    CSV = "csv"
    STIX21 = "stix21"
    TAXII21 = "taxii21"


class StorageBackendType(StrEnum):
    """Abstract storage backend identifiers."""

    SQLITE = "sqlite"
    POSTGRESQL = "postgresql"
    OPENSEARCH = "opensearch"
    ELASTICSEARCH = "elasticsearch"
    SPLUNK = "splunk"
    JSON = "json"
    PARQUET = "parquet"
    DATA_LAKE = "data_lake"
    S3 = "s3"


class RelationshipType(StrEnum):
    """Relationship kinds between findings / entities."""

    RELATED_TO = "related_to"
    DERIVED_FROM = "derived_from"
    ATTRIBUTED_TO = "attributed_to"
    INDICATES = "indicates"
    USES = "uses"
    TARGETS = "targets"
    COMMUNICATES_WITH = "communicates_with"
    BELONGS_TO_CAMPAIGN = "belongs_to_campaign"
    SAME_INFRASTRUCTURE = "same_infrastructure"
    DUPLICATE_OF = "duplicate_of"


class HealthState(StrEnum):
    """Health check result states."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class ArtifactType(StrEnum):
    """Types of evidence artifacts attached to a Finding."""

    HTML = "html"
    TEXT = "text"
    JSON = "json"
    SCREENSHOT = "screenshot"
    FILE = "file"
    BINARY = "binary"
    LOG = "log"


# Re-export Enum for typing convenience
__all__ = [
    "Severity",
    "FindingCategory",
    "IndicatorType",
    "HuntJobStatus",
    "ConnectorStatus",
    "WatchlistType",
    "DetectionRuleType",
    "ExportFormat",
    "StorageBackendType",
    "RelationshipType",
    "HealthState",
    "ArtifactType",
    "Enum",
]
