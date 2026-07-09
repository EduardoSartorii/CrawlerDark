"""
Settings — Centralized Configuration
=====================================

Uses Pydantic Settings v2 to merge settings from:
    1. config/settings.yaml (base defaults)
    2. .env file (local overrides)
    3. Environment variables (highest priority)

Every subsystem reads settings through this module.
No component reads os.environ directly.
"""

from __future__ import annotations

import functools
from pathlib import Path
from typing import Any

import yaml
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class DatabaseSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="DB_")

    url: str = "sqlite+aiosqlite:///./threat_hunting.db"
    pool_size: int = 10
    max_overflow: int = 20
    echo: bool = False


class RedisSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="REDIS_")

    url: str = "redis://localhost:6379/0"
    max_connections: int = 50


class OpsecProfileSettings(BaseSettings):
    model_config = SettingsConfigDict(extra="allow")

    proxy: str | None = None
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    timeout: int = 30
    max_retries: int = 3
    backoff_factor: float = 2.0
    verify_ssl: bool = True
    rate_limit_rps: float = 2.0


class MISPSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="MISP_")

    url: str = ""
    key: str = ""
    verify_cert: bool = False
    distribution: int = 1
    threat_level: int = 2
    analysis: int = 2
    enabled: bool = False


class ConnectorCredentials(BaseSettings):
    model_config = SettingsConfigDict(extra="allow")

    reddit_client_id: str = Field(default="", alias="REDDIT_CLIENT_ID")
    reddit_client_secret: str = Field(default="", alias="REDDIT_CLIENT_SECRET")
    reddit_user_agent: str = Field(default="ThreatHuntingBot/1.0", alias="REDDIT_USER_AGENT")
    github_token: str = Field(default="", alias="GITHUB_TOKEN")
    telegram_api_id: str = Field(default="", alias="TELEGRAM_API_ID")
    telegram_api_hash: str = Field(default="", alias="TELEGRAM_API_HASH")
    virustotal_api_key: str = Field(default="", alias="VIRUSTOTAL_API_KEY")
    abuseipdb_api_key: str = Field(default="", alias="ABUSEIPDB_API_KEY")
    greynoise_api_key: str = Field(default="", alias="GREYNOISE_API_KEY")
    alienvault_otx_api_key: str = Field(default="", alias="ALIENVAULT_OTX_API_KEY")
    shodan_api_key: str = Field(default="", alias="SHODAN_API_KEY")


class ExporterSettings(BaseSettings):
    model_config = SettingsConfigDict(extra="allow")

    auto_export_threshold: float = 7.5
    json_output_path: str = "exports/json"
    csv_output_path: str = "exports/csv"
    stix_output_path: str = "exports/stix"
    splunk_url: str = Field(default="", alias="SPLUNK_URL")
    splunk_token: str = Field(default="", alias="SPLUNK_TOKEN")
    opensearch_url: str = Field(default="http://localhost:9200", alias="OPENSEARCH_URL")
    webhook_url: str = Field(default="", alias="WEBHOOK_URL")
    webhook_secret: str = Field(default="", alias="WEBHOOK_SECRET")


class ObservabilitySettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="OBSERVABILITY_")

    prometheus_enabled: bool = True
    prometheus_port: int = 9090
    otlp_enabled: bool = False
    otlp_endpoint: str = "http://localhost:4317"
    log_level: str = "INFO"


class ScoringWeights(BaseSettings):
    model_config = SettingsConfigDict(extra="allow")

    ioc_match: float = 2.5
    credential_match: float = 3.0
    card_match: float = 3.5
    cpf_match: float = 2.0
    cnpj_match: float = 1.5
    email_match: float = 1.0
    domain_match: float = 1.5
    yara_match: float = 2.0
    regex_match: float = 1.0
    vip_match: float = 3.0
    threat_actor_match: float = 2.5
    keyword_match: float = 1.0
    high_ioc_density: float = 1.5
    recurrence_bonus: float = 0.5
    max_score: float = 10.0


class Settings(BaseSettings):
    """
    Master settings object.

    Reads from environment variables and .env file.
    YAML config is loaded separately and merged at startup.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="allow",
    )

    # Platform
    environment: str = "development"
    secret_key: str = "change-me-in-production"
    log_level: str = "INFO"

    # Sub-settings (can be overridden by env vars via prefix)
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    redis: RedisSettings = Field(default_factory=RedisSettings)
    misp: MISPSettings = Field(default_factory=MISPSettings)
    credentials: ConnectorCredentials = Field(default_factory=ConnectorCredentials)
    exporters: ExporterSettings = Field(default_factory=ExporterSettings)
    observability: ObservabilitySettings = Field(default_factory=ObservabilitySettings)
    scoring: ScoringWeights = Field(default_factory=ScoringWeights)

    # Paths
    config_dir: Path = Path("config")
    rules_dir: Path = Path("config/rules")
    whitelist_dir: Path = Path("config/whitelists")

    # Detection
    enable_yara: bool = True
    enable_regex: bool = True
    enable_sigma: bool = False
    enable_keyword: bool = True
    enable_ioc_matching: bool = True

    # Correlation / Dedup
    correlation_enabled: bool = True
    correlation_time_window_hours: int = 72
    deduplication_enabled: bool = True
    deduplication_similarity_threshold: float = 0.85
    deduplication_ttl_hours: int = 168

    # Enrichment
    enrichment_enabled: bool = True

    @field_validator("rules_dir", "whitelist_dir", "config_dir", mode="before")
    @classmethod
    def ensure_path(cls, v: Any) -> Path:
        return Path(v)

    @classmethod
    def from_yaml(cls, yaml_path: Path | str = "config/settings.yaml") -> "Settings":
        """Load settings from YAML file and merge with environment variables."""
        path = Path(yaml_path)
        if path.exists():
            with open(path) as f:
                data = yaml.safe_load(f) or {}
        else:
            data = {}
        return cls(**_flatten_yaml(data))


def _flatten_yaml(data: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    """Recursively flatten nested YAML into a flat dict for Pydantic."""
    result: dict[str, Any] = {}
    for key, value in data.items():
        full_key = f"{prefix}{key}" if prefix else key
        if isinstance(value, dict) and key not in (
            "database", "redis", "misp", "credentials", "exporters",
            "observability", "scoring", "opsec",
        ):
            result.update(_flatten_yaml(value, f"{full_key}_"))
        else:
            result[full_key] = value
    return result


@functools.lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a cached singleton Settings instance."""
    try:
        return Settings.from_yaml()
    except Exception:
        return Settings()
