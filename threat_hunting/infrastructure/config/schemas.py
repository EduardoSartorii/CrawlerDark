"""Schemas Pydantic V2 para os YAMLs de configuração.

Toda configuração da plataforma é validada aqui, evitando surpresas em runtime.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class OpsecProfile(BaseModel):
    """Perfil OPSEC — proxy, headers, rate limit, retries."""

    model_config = ConfigDict(extra="forbid")

    proxy: str | None = None
    timeout_seconds: float = 30.0
    retries: int = 3
    backoff_seconds: float = 1.5
    jitter_seconds: float = 0.5
    rate_limit_per_second: float = 2.0
    user_agents: list[str] = Field(default_factory=list)
    headers: dict[str, str] = Field(default_factory=dict)


class OpsecConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    default_profile: str = "default"
    profiles: dict[str, OpsecProfile] = Field(default_factory=dict)


class SQLAlchemyStorage(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str
    echo: bool = False
    pool_size: int = 5
    max_overflow: int = 10


class JSONStorage(BaseModel):
    model_config = ConfigDict(extra="forbid")
    root: str = "./data/findings"


class StorageConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    backend: str = "sqlalchemy"
    sqlalchemy: SQLAlchemyStorage
    json_storage: JSONStorage = Field(alias="json")


class LoggingConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    level: str = "INFO"
    json_output: bool = Field(default=True, alias="json")
    redact_keys: list[str] = Field(default_factory=list)


class PrometheusConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = True
    port: int = 9464


class OpenTelemetryConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = False
    endpoint: str = "http://localhost:4317"
    service_name: str = "threat-hunting"


class ObservabilityConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    prometheus: PrometheusConfig
    opentelemetry: OpenTelemetryConfig


class SchedulerConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    timezone: str = "UTC"
    jobs: list[dict[str, Any]] = Field(default_factory=list)


class ExporterAutoConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    autoexport_score_threshold: float = 80.0
    autoexport_targets: list[str] = Field(default_factory=list)


class PipelineConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    stages: list[str] = Field(default_factory=list)
    disabled: list[str] = Field(default_factory=list)


class AppSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    environment: str = "development"
    timezone: str = "UTC"


class Settings(BaseModel):
    """Root do arquivo ``settings.yaml``."""

    model_config = ConfigDict(extra="forbid")

    app: AppSettings
    logging: LoggingConfig
    storage: StorageConfig
    observability: ObservabilityConfig
    opsec: OpsecConfig
    scheduler: SchedulerConfig
    exporters: ExporterAutoConfig
    pipeline: PipelineConfig


class ConnectorConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: str
    enabled: bool = False
    opsec_profile: str = "default"
    options: dict[str, Any] = Field(default_factory=dict)


class ExporterConfig(BaseModel):
    """Configuração livre por exporter (validação delegada ao adapter)."""

    model_config = ConfigDict(extra="allow")
    enabled: bool = False


class ScoringWeights(BaseModel):
    model_config = ConfigDict(extra="allow")


class ScoringConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    base_score: float = 0.0
    weights: dict[str, float] = Field(default_factory=dict)
    severity_multiplier: dict[str, float] = Field(default_factory=dict)
    source_bonus: dict[str, float] = Field(default_factory=dict)
    cap: dict[str, float] = Field(default_factory=lambda: {"min": 0.0, "max": 100.0})


class VIPEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    aliases: list[str] = Field(default_factory=list)


class WatchlistConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    keywords: list[str] = Field(default_factory=list)
    brands: list[str] = Field(default_factory=list)
    vips: list[VIPEntry] = Field(default_factory=list)
    executives: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    emails: list[str] = Field(default_factory=list)
    threat_actors: list[str] = Field(default_factory=list)
    wallets_btc: list[str] = Field(default_factory=list)
    wallets_eth: list[str] = Field(default_factory=list)
    telegram_handles: list[str] = Field(default_factory=list)
    github_handles: list[str] = Field(default_factory=list)
    cpf: list[str] = Field(default_factory=list)
    cnpj: list[str] = Field(default_factory=list)
    ioc_lists: list[str] = Field(default_factory=list)
    yara_rules_dir: str = ""
    sigma_rules_dir: str = ""
    regex_rules_file: str = ""

    @field_validator("keywords", "brands", "domains", mode="before")
    @classmethod
    def _strip_list(cls, v: list[str]) -> list[str]:
        return [x.strip() for x in v if x and x.strip()]
