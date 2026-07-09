"""Domain enumerations and value objects.

Defines the ubiquitous language types used across all bounded contexts.
"""

from enum import StrEnum


class Severity(StrEnum):
    """Finding severity classification."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SourceType(StrEnum):
    """Origin classification for collected intelligence."""

    SOCIAL = "social"
    DARKWEB = "darkweb"
    DEEPWEB = "deepweb"
    FEED = "feed"
    API = "api"
    PASTE = "paste"
    FORUM = "forum"
    MARKETPLACE = "marketplace"
    NEWS = "news"
    BLOG = "blog"
    SITE = "site"
    CODE = "code"
    MESSAGING = "messaging"


class FindingCategory(StrEnum):
    """Taxonomy for finding classification."""

    CREDENTIAL_LEAK = "credential_leak"
    CARD_LEAK = "card_leak"
    DOCUMENT_LEAK = "document_leak"
    BRAND_ABUSE = "brand_abuse"
    VIP_EXPOSURE = "vip_exposure"
    IOC = "ioc"
    MALWARE = "malware"
    CAMPAIGN = "campaign"
    THREAT_ACTOR = "threat_actor"
    INFRASTRUCTURE = "infrastructure"
    PHISHING = "phishing"
    FRAUD = "fraud"
    GENERAL = "general"


class IndicatorType(StrEnum):
    """IOC indicator type taxonomy."""

    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    CPF = "cpf"
    CNPJ = "cnpj"
    CARD = "card"
    WALLET = "wallet"
    TELEGRAM = "telegram"
    GITHUB = "github"
    USERNAME = "username"
    CVE = "cve"
    YARA = "yara"
    SIGMA = "sigma"


class WatchlistType(StrEnum):
    """Watchlist entry classification."""

    KEYWORD = "keyword"
    VIP = "vip"
    BRAND = "brand"
    COMPANY = "company"
    EXECUTIVE = "executive"
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


class RuleType(StrEnum):
    """Detection rule engine type."""

    REGEX = "regex"
    YARA = "yara"
    SIGMA = "sigma"
    KEYWORD = "keyword"
    IOC_MATCH = "ioc_match"
    THREAT_ACTOR = "threat_actor"
    HEURISTIC = "heuristic"
    WHITELIST = "whitelist"
    BLACKLIST = "blacklist"
    THRESHOLD = "threshold"
    COMPOSITE = "composite"


class ConnectorStatus(StrEnum):
    """Operational status of a connector."""

    ENABLED = "enabled"
    DISABLED = "disabled"
    ERROR = "error"


class HealthStatus(StrEnum):
    """Health check result for connectors and services."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


class ExportFormat(StrEnum):
    """Supported export destination formats."""

    MISP = "misp"
    OPENCTI = "opencti"
    SPLUNK = "splunk"
    OPENSEARCH = "opensearch"
    ELASTICSEARCH = "elasticsearch"
    WEBHOOK = "webhook"
    REST = "rest"
    JSON = "json"
    CSV = "csv"
    STIX = "stix"
    TAXII = "taxii"


class StorageBackendType(StrEnum):
    """Pluggable storage backend identifiers."""

    SQLITE = "sqlite"
    POSTGRESQL = "postgresql"
    JSON = "json"
    OPENSEARCH = "opensearch"
    ELASTICSEARCH = "elasticsearch"
    SPLUNK = "splunk"
    PARQUET = "parquet"
    S3 = "s3"
    DATALAKE = "datalake"
