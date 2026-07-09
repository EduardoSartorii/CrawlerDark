"""Typed platform settings (Pydantic v2) with YAML + environment loading.

Responsibility
--------------
Provide a single, validated, strongly-typed configuration object for the whole
platform. Configuration is the primary extension mechanism: OPSEC profiles,
scoring weights, connector toggles and thresholds are declared here (from YAML
and environment variables), never hardcoded in engines or connectors.

Business rules
--------------
* Environment variables (prefix ``TH_``) override YAML values, which override
  built-in defaults.
* Unknown connectors default to *enabled* only if listed; the registry respects
  the ``connectors`` map for enable/disable state.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class OpsecProfile(BaseModel):
    """OPSEC transport settings for a group of connectors."""

    http_proxy: str | None = None
    https_proxy: str | None = None
    socks5_proxy: str | None = None
    verify_tls: bool = True
    user_agent: str = "Mozilla/5.0 (compatible; ThreatHuntingCollector/1.0)"
    timeout_seconds: float = 30.0
    max_retries: int = 3
    backoff_factor: float = 0.5
    rate_limit_per_second: float = 2.0
    headers: dict[str, str] = Field(default_factory=dict)


class ConnectorSettings(BaseModel):
    """Per-connector runtime configuration."""

    enabled: bool = True
    opsec_profile: str = "default"
    category: str | None = None
    options: dict[str, Any] = Field(default_factory=dict)


class ScoringWeights(BaseModel):
    """Configurable scoring weights (fraud/threat scoring engine).

    Every contributor to the score has an explicit, tunable weight so scoring is
    fully explainable and adjustable without code changes.
    """

    regex_match: float = 10.0
    yara_match: float = 25.0
    keyword_match: float = 10.0
    vip_match: float = 25.0
    ioc_match: float = 15.0
    credential: float = 20.0
    credit_card: float = 30.0
    email: float = 5.0
    document: float = 20.0
    cpf: float = 20.0
    cnpj: float = 20.0
    domain: float = 5.0
    threat_actor: float = 30.0
    source_reputation: float = 5.0
    context: float = 5.0
    ioc_volume: float = 2.0
    recurrence: float = 5.0
    history: float = 5.0
    per_indicator_cap: float = 40.0


class StorageSettings(BaseModel):
    """Persistence backend selection and connection details."""

    backend: str = "sqlite"  # sqlite | postgresql | memory | json
    dsn: str = "sqlite:///threat_hunting.db"
    json_path: str = "findings.jsonl"


class ExportSettings(BaseModel):
    """Exporter configuration and the automatic-export threshold."""

    output_dir: str = "exports"
    auto_export_threshold: float = 80.0
    auto_export_targets: list[str] = Field(default_factory=lambda: ["misp"])
    misp_url: str | None = None
    misp_key: str | None = None
    misp_event_id: str | None = None


class ObservabilitySettings(BaseModel):
    """Logging / metrics / tracing configuration."""

    log_level: str = "INFO"
    json_logs: bool = True
    metrics_enabled: bool = True
    metrics_port: int = 9464
    tracing_enabled: bool = False


class PlatformSettings(BaseSettings):
    """Root settings object for the whole platform."""

    model_config = SettingsConfigDict(
        env_prefix="TH_",
        env_nested_delimiter="__",
        extra="ignore",
    )

    detection_threshold: float = 0.0
    dedup_similarity_threshold: float = 0.9
    opsec_profiles: dict[str, OpsecProfile] = Field(
        default_factory=lambda: {"default": OpsecProfile()}
    )
    connectors: dict[str, ConnectorSettings] = Field(default_factory=dict)
    scoring: ScoringWeights = Field(default_factory=ScoringWeights)
    storage: StorageSettings = Field(default_factory=StorageSettings)
    export: ExportSettings = Field(default_factory=ExportSettings)
    observability: ObservabilitySettings = Field(default_factory=ObservabilitySettings)
    rules_dir: str = "config/rules"
    watchlists_path: str = "config/watchlists.yml"

    def opsec_profile(self, name: str) -> OpsecProfile:
        """Return an OPSEC profile, falling back to ``default``."""
        return self.opsec_profiles.get(name) or self.opsec_profiles.get(
            "default", OpsecProfile()
        )

    def connector_settings(self, name: str) -> ConnectorSettings:
        """Return per-connector settings, defaulting to enabled."""
        return self.connectors.get(name, ConnectorSettings())


def load_settings(path: str | Path | None = None) -> PlatformSettings:
    """Load settings from an optional YAML file, then env overrides.

    Precedence (highest first): environment variables > YAML file > defaults.
    """
    data: dict[str, Any] = {}
    if path is not None:
        file_path = Path(path)
        if file_path.exists():
            data = yaml.safe_load(file_path.read_text(encoding="utf-8")) or {}
    return PlatformSettings(**data)
